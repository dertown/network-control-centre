package certdeploy

import (
	"errors"
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

// Field is one setting of a server type, rendered as a form field by the UI.
type Field struct {
	Key     string   `json:"key"`
	Label   string   `json:"label"`
	Default string   `json:"default,omitempty"`
	Help    string   `json:"help,omitempty"`
	Type    string   `json:"type,omitempty"` // text (default) | select | bool
	Choices []string `json:"choices,omitempty"`
}

// Kind is a type of server NCC can install certificates on.
type Kind struct {
	ID          string  `json:"id"`
	Label       string  `json:"label"`
	Description string  `json:"description"`
	Transport   string  `json:"transport"` // ssh | winrm
	DefaultPort int     `json:"default_port"`
	Fields      []Field `json:"fields"`
	// Secrets lists the vault keys this kind uses, beyond the login.
	Secrets []Field `json:"secrets,omitempty"`
	// VerifyWait is how long to keep checking that the server serves the new certificate.
	VerifyWait int `json:"verify_wait_s"`

	build func(p *planner) error
}

// Step is one action of a deployment.
type Step struct {
	Op     string `json:"op"` // write | edit | run
	Title  string `json:"title"`
	Path   string `json:"path,omitempty"`
	Detail string `json:"detail,omitempty"`

	data  []byte
	mode  string
	owner string
	edit  func(old []byte) ([]byte, error)
	cmd   string
}

// planner collects the steps for one target and certificate.
type planner struct {
	t         *Target
	transport string
	m         *Material
	opts      map[string]string
	secrets   map[string]string
	steps     []Step
	notes     []string
	warnings  []string
	// saveSecrets are generated values (e.g. a keystore password) stored in the vault on deploy.
	saveSecrets map[string]string
}

var placeholderRe = regexp.MustCompile(`\{([a-z_]+)\}`)

// opt returns a setting with {placeholders} filled in from other settings and {cert}.
func (p *planner) opt(key string) string {
	v := p.opts[key]
	for range 3 {
		if !strings.Contains(v, "{") {
			break
		}
		v = placeholderRe.ReplaceAllStringFunc(v, func(m string) string {
			k := m[1 : len(m)-1]
			if k == "cert" {
				return safeName(p.m.Name)
			}
			if r, ok := p.opts[k]; ok && k != key {
				return r
			}
			return m
		})
	}
	return strings.TrimSpace(v)
}

func (p *planner) bool(key string) bool {
	v := strings.ToLower(p.opt(key))
	return v == "true" || v == "yes" || v == "1" || v == "on"
}

func (p *planner) path(key string) (string, error) {
	v := p.opt(key)
	if v == "" {
		return "", fmt.Errorf("set %s", key)
	}
	if strings.ContainsAny(v, "\n\r\x00") {
		return "", fmt.Errorf("%s contains a line break", key)
	}
	if p.transport == "ssh" && !strings.HasPrefix(v, "/") {
		return "", fmt.Errorf("%s must be an absolute path (got %q)", key, v)
	}
	return v, nil
}

func (p *planner) write(title, path string, data []byte, mode, owner, detail string) {
	if detail == "" {
		detail = fmt.Sprintf("%d bytes, mode %s", len(data), mode)
		if mode == "" {
			detail = fmt.Sprintf("%d bytes", len(data))
		}
		if owner != "" {
			detail += ", owner " + owner
		}
	}
	p.steps = append(p.steps, Step{Op: "write", Title: title, Path: path, Detail: detail, data: data, mode: mode, owner: owner})
}

func (p *planner) edit(title, path, detail string, fn func([]byte) ([]byte, error)) {
	p.steps = append(p.steps, Step{Op: "edit", Title: title, Path: path, Detail: detail, edit: fn})
}

func (p *planner) run(title, cmd string) {
	if strings.TrimSpace(cmd) == "" {
		return
	}
	p.steps = append(p.steps, Step{Op: "run", Title: title, Detail: cmd, cmd: cmd})
}

// runHiding adds a command whose shown detail has a secret masked.
func (p *planner) runHiding(title, cmd, secret string) {
	p.steps = append(p.steps, Step{Op: "run", Title: title, Detail: strings.ReplaceAll(cmd, secret, "••••••"), cmd: cmd})
}

// runAs wraps a command to run as another (service) user when run_as is set.
func (p *planner) runAs(cmd string) string {
	u := p.opt("run_as")
	if u == "" || strings.TrimSpace(cmd) == "" {
		return cmd
	}
	return "su -s /bin/sh " + shQuote(u) + " -c " + shQuote(cmd)
}

func safeName(s string) string {
	var b strings.Builder
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '-', r == '.', r == '_':
			b.WriteRune(r)
		case r == '*':
			b.WriteString("wildcard")
		default:
			b.WriteRune('_')
		}
	}
	return strings.Trim(b.String(), ".")
}

func kvDetail(section string, kvs []KV) string {
	var parts []string
	for _, kv := range kvs {
		parts = append(parts, kv.Key+" = "+kv.Value)
	}
	if section != "" {
		return "[" + section + "] " + strings.Join(parts, ", ")
	}
	return strings.Join(parts, ", ")
}

// ---- shared field sets ----

var sshFields = []Field{
	{Key: "use_sudo", Label: "Use sudo", Default: "true", Type: "bool", Help: "Run file writes and restarts through sudo (not needed when logging in as root). The login password is used for sudo unless a separate sudo password is saved."},
	{Key: "host_key", Label: "SSH host key", Help: "Pinned SHA256 host key fingerprint. Leave empty: NCC shows the key on the first preview for you to confirm, then pins it."},
}

func checkField(key, label, def, help string) Field {
	return Field{Key: key, Label: label, Default: def, Help: help}
}

var kinds = []*Kind{
	{
		ID: "nginx", Label: "nginx", Transport: "ssh", DefaultPort: 22, VerifyWait: 30,
		Description: "Copies the full chain and the key over SSH, tests the configuration and reloads nginx.",
		Fields: append([]Field{
			checkField("cert_path", "Certificate file (full chain)", "/etc/nginx/ssl/{cert}.crt", "ssl_certificate in your server block."),
			checkField("key_path", "Private key file", "/etc/nginx/ssl/{cert}.key", "ssl_certificate_key in your server block."),
			checkField("owner", "File owner", "root:root", ""),
			checkField("reload", "Reload command", "nginx -t && systemctl reload nginx", ""),
			checkField("https_port", "HTTPS port to check", "443", "NCC connects here after deploying to confirm the new certificate is served."),
			checkField("check_name", "Host name to check", "", "Server name (SNI) used for the check. Defaults to the address, or the certificate's first name when the address is an IP."),
		}, sshFields...),
		build: func(p *planner) error {
			cert, err := p.path("cert_path")
			if err != nil {
				return err
			}
			key, err := p.path("key_path")
			if err != nil {
				return err
			}
			p.write("Upload certificate and chain", cert, []byte(p.m.FullChainPEM), "0644", p.opt("owner"), "")
			p.write("Upload private key", key, []byte(p.m.KeyPEM), "0600", p.opt("owner"), "")
			p.run("Test configuration and reload nginx", p.opt("reload"))
			p.notes = append(p.notes, "nginx must point at these files: ssl_certificate "+cert+"; ssl_certificate_key "+key+";")
			return nil
		},
	},
	{
		ID: "apache", Label: "Apache httpd", Transport: "ssh", DefaultPort: 22, VerifyWait: 30,
		Description: "Copies the certificate and key over SSH, checks the configuration and reloads Apache gracefully.",
		Fields: append([]Field{
			checkField("cert_path", "Certificate file", "/etc/ssl/certs/{cert}.crt", "SSLCertificateFile. Holds the full chain unless a chain file is set (Apache 2.4.8 and later read the chain from here)."),
			checkField("chain_path", "Chain file (optional)", "", "SSLCertificateChainFile, for Apache older than 2.4.8."),
			checkField("key_path", "Private key file", "/etc/ssl/private/{cert}.key", "SSLCertificateKeyFile."),
			checkField("owner", "File owner", "root:root", ""),
			checkField("reload", "Reload command", "apachectl configtest && apachectl graceful", "On Debian and Ubuntu, \"apache2ctl configtest && systemctl reload apache2\" also works."),
			checkField("https_port", "HTTPS port to check", "443", ""),
			checkField("check_name", "Host name to check", "", ""),
		}, sshFields...),
		build: func(p *planner) error {
			cert, err := p.path("cert_path")
			if err != nil {
				return err
			}
			key, err := p.path("key_path")
			if err != nil {
				return err
			}
			if chain := p.opt("chain_path"); chain != "" {
				if chain, err = p.path("chain_path"); err != nil {
					return err
				}
				p.write("Upload certificate", cert, []byte(p.m.LeafPEM), "0644", p.opt("owner"), "")
				p.write("Upload intermediate chain", chain, []byte(p.m.ChainPEM), "0644", p.opt("owner"), "")
			} else {
				p.write("Upload certificate and chain", cert, []byte(p.m.FullChainPEM), "0644", p.opt("owner"), "")
			}
			p.write("Upload private key", key, []byte(p.m.KeyPEM), "0600", p.opt("owner"), "")
			p.run("Check configuration and reload Apache", p.opt("reload"))
			return nil
		},
	},
	{
		ID: "tomcat", Label: "Apache Tomcat", Transport: "ssh", DefaultPort: 22, VerifyWait: 90,
		Description: "Builds a PKCS#12 keystore (or PEM files) for Tomcat's HTTPS connector, copies it over SSH and restarts Tomcat.",
		Fields: append([]Field{
			{Key: "format", Label: "Format", Default: "pkcs12", Type: "select", Choices: []string{"pkcs12", "pem"}, Help: "pkcs12 works with every Tomcat; PEM files need Tomcat 8.5 or later."},
			checkField("keystore_path", "Keystore file (pkcs12)", "/opt/tomcat/conf/{cert}.p12", "certificateKeystoreFile in server.xml."),
			checkField("cert_path", "Certificate file (pem)", "/opt/tomcat/conf/{cert}.crt", "certificateFile."),
			checkField("key_path", "Private key file (pem)", "/opt/tomcat/conf/{cert}.key", "certificateKeyFile."),
			checkField("chain_path", "Chain file (pem)", "/opt/tomcat/conf/{cert}-chain.crt", "certificateChainFile."),
			checkField("owner", "File owner", "root:tomcat", "Tomcat's user must be able to read the files (mode 0640)."),
			checkField("restart", "Restart command", "systemctl restart tomcat", "For example systemctl restart tomcat9 on Debian."),
			checkField("https_port", "HTTPS port to check", "8443", ""),
			checkField("check_name", "Host name to check", "", ""),
		}, sshFields...),
		Secrets: []Field{{Key: "keystore_password", Label: "Keystore password", Help: "Leave empty and NCC makes one on the first deploy and keeps it in the vault, so server.xml never has to change."}},
		build: func(p *planner) error {
			owner := p.opt("owner")
			if p.opt("format") == "pem" {
				cert, err := p.path("cert_path")
				if err != nil {
					return err
				}
				key, err := p.path("key_path")
				if err != nil {
					return err
				}
				p.write("Upload certificate", cert, []byte(p.m.LeafPEM), "0640", owner, "")
				attrs := `certificateFile="` + cert + `" certificateKeyFile="` + key + `"`
				if len(p.m.Chain) > 0 {
					chain, err := p.path("chain_path")
					if err != nil {
						return err
					}
					p.write("Upload intermediate chain", chain, []byte(p.m.ChainPEM), "0640", owner, "")
					attrs += ` certificateChainFile="` + chain + `"`
				}
				p.write("Upload private key", key, []byte(p.m.KeyPEM), "0640", owner, "")
				p.notes = append(p.notes, "server.xml connector: <Certificate "+attrs+" type=\"RSA\" />")
			} else {
				ks, err := p.path("keystore_path")
				if err != nil {
					return err
				}
				pw := p.secrets["keystore_password"]
				how := "keystore password from the vault"
				if pw == "" {
					pw = RandomPassword()
					p.saveSecrets = map[string]string{"keystore_password": pw}
					how = "new keystore password, saved to the vault on deploy"
				}
				pfx, err := p.m.PFX(pw)
				if err != nil {
					return fmt.Errorf("build keystore: %w", err)
				}
				p.write("Upload PKCS#12 keystore", ks, pfx, "0640", owner, fmt.Sprintf("%d bytes, mode 0640, %s", len(pfx), how))
				p.notes = append(p.notes, "server.xml connector: <Certificate certificateKeystoreFile=\""+ks+
					"\" certificateKeystoreType=\"PKCS12\" certificateKeystorePassword=\"(keystore_password from the vault)\" />")
			}
			p.run("Restart Tomcat", p.opt("restart"))
			return nil
		},
	},
	{
		ID: "splunk", Label: "Splunk Enterprise", Transport: "ssh", DefaultPort: 22, VerifyWait: 180,
		Description: "Installs the certificate for Splunk Web (port 8000) and optionally splunkd (port 8089), updates web.conf / server.conf and restarts Splunk.",
		Fields: append([]Field{
			checkField("splunk_home", "SPLUNK_HOME", "/opt/splunk", ""),
			{Key: "component", Label: "Install for", Default: "web", Type: "select", Choices: []string{"web", "web+splunkd", "splunkd"}, Help: "Splunk Web (the browser UI), splunkd (the management port, also used by forwarders and the REST API), or both."},
			checkField("web_cert_path", "Splunk Web certificate", "{splunk_home}/etc/auth/mycerts/{cert}-web.pem", "Leaf followed by the chain. Set as serverCert in web.conf."),
			checkField("key_path", "Splunk Web private key", "{splunk_home}/etc/auth/mycerts/{cert}.key", "Set as privKeyPath in web.conf."),
			checkField("server_cert_path", "splunkd certificate", "{splunk_home}/etc/auth/mycerts/{cert}-server.pem", "Leaf, key and chain in one file. Set as serverCert in server.conf [sslConfig]."),
			checkField("owner", "File owner", "splunk:splunk", ""),
			checkField("run_as", "Run restart as", "", "Leave empty for a systemd restart as root; set to splunk to run \"splunk restart\" as that user."),
			checkField("restart", "Restart command", "systemctl restart Splunkd", "Or {splunk_home}/bin/splunk restart with Run restart as = splunk."),
			checkField("https_port", "HTTPS port to check", "8000", "8000 for Splunk Web; use 8089 to check splunkd."),
			checkField("check_name", "Host name to check", "", ""),
		}, sshFields...),
		build: func(p *planner) error {
			comp := p.opt("component")
			home, err := p.path("splunk_home")
			if err != nil {
				return err
			}
			owner := p.opt("owner")
			if comp == "web" || comp == "web+splunkd" {
				cert, err := p.path("web_cert_path")
				if err != nil {
					return err
				}
				key, err := p.path("key_path")
				if err != nil {
					return err
				}
				p.write("Upload Splunk Web certificate and chain", cert, []byte(p.m.FullChainPEM), "0600", owner, "")
				p.write("Upload Splunk Web private key", key, []byte(p.m.KeyPEM), "0600", owner, "")
				kvs := []KV{{"enableSplunkWebSSL", "true"}, {"serverCert", cert}, {"privKeyPath", key}}
				p.edit("Point Splunk Web at the certificate", home+"/etc/system/local/web.conf", kvDetail("settings", kvs),
					func(old []byte) ([]byte, error) { return SetINI(old, "settings", kvs), nil })
			}
			if comp == "splunkd" || comp == "web+splunkd" {
				cert, err := p.path("server_cert_path")
				if err != nil {
					return err
				}
				p.write("Upload splunkd certificate (leaf, key and chain)", cert, []byte(p.m.CombinedPEM()), "0600", owner, "")
				kvs := []KV{{"serverCert", cert}}
				p.edit("Point splunkd at the certificate", home+"/etc/system/local/server.conf", kvDetail("sslConfig", kvs),
					func(old []byte) ([]byte, error) { return SetINI(old, "sslConfig", kvs), nil })
				p.notes = append(p.notes, "The private key is not encrypted, so server.conf sslPassword is left as it is; Splunk ignores it for an unencrypted key.")
			}
			if comp != "web" && comp != "splunkd" && comp != "web+splunkd" {
				return fmt.Errorf("unknown component %q", comp)
			}
			p.run("Restart Splunk", p.runAs(p.opt("restart")))
			p.notes = append(p.notes, "The old files and .conf files are kept next to the new ones with a .ncc-bak suffix. Splunk takes a minute or two to come back after a restart.")
			return nil
		},
	},
	{
		ID: "soar", Label: "Splunk SOAR", Transport: "ssh", DefaultPort: 22, VerifyWait: 90,
		Description: "Replaces the SOAR web certificate (httpd_cert.crt / httpd_cert.key) over SSH and restarts SOAR's nginx.",
		Fields: append([]Field{
			checkField("phantom_home", "SOAR install folder", "/opt/phantom", "PHANTOM_HOME."),
			checkField("cert_path", "Certificate file (full chain)", "{phantom_home}/etc/ssl/certs/httpd_cert.crt", ""),
			checkField("key_path", "Private key file", "{phantom_home}/etc/ssl/private/httpd_cert.key", ""),
			checkField("owner", "File owner", "", "Leave empty to keep the owner of the files being replaced (the SOAR user)."),
			checkField("run_as", "Run restart as", "", "The SOAR user (for example phantom) on unprivileged installs."),
			checkField("restart", "Restart command", "{phantom_home}/bin/phsvc restart nginx", ""),
			checkField("https_port", "HTTPS port to check", "443", "8443 on unprivileged installs that kept the default port."),
			checkField("check_name", "Host name to check", "", ""),
		}, sshFields...),
		build: func(p *planner) error {
			cert, err := p.path("cert_path")
			if err != nil {
				return err
			}
			key, err := p.path("key_path")
			if err != nil {
				return err
			}
			p.write("Upload certificate and chain", cert, []byte(p.m.FullChainPEM), "0644", p.opt("owner"), "")
			p.write("Upload private key", key, []byte(p.m.KeyPEM), "0600", p.opt("owner"), "")
			p.run("Restart SOAR web server", p.runAs(p.opt("restart")))
			return nil
		},
	},
	{
		ID: "foundryvtt", Label: "Foundry VTT", Transport: "ssh", DefaultPort: 22, VerifyWait: 60,
		Description: "Copies the certificate and key into Foundry's Config folder, sets sslCert and sslKey in options.json and restarts Foundry.",
		Fields: append([]Field{
			checkField("data_path", "Foundry user data folder", "/home/foundry/foundrydata", "The folder that holds Config, Data and Logs."),
			checkField("cert_path", "Certificate file (full chain)", "{data_path}/Config/{cert}-cert.pem", ""),
			checkField("key_path", "Private key file", "{data_path}/Config/{cert}-key.pem", ""),
			checkField("owner", "File owner", "", "Leave empty to use the owner of the Config folder (the Foundry user)."),
			checkField("run_as", "Run restart as", "", "For example foundry when Foundry runs under pm2 as that user."),
			checkField("restart", "Restart command", "systemctl restart foundryvtt", "For example pm2 restart foundry with Run restart as set."),
			checkField("https_port", "HTTPS port to check", "30000", ""),
			checkField("check_name", "Host name to check", "", ""),
		}, sshFields...),
		build: func(p *planner) error {
			data, err := p.path("data_path")
			if err != nil {
				return err
			}
			cert, err := p.path("cert_path")
			if err != nil {
				return err
			}
			key, err := p.path("key_path")
			if err != nil {
				return err
			}
			p.write("Upload certificate and chain", cert, []byte(p.m.FullChainPEM), "0644", p.opt("owner"), "")
			p.write("Upload private key", key, []byte(p.m.KeyPEM), "0600", p.opt("owner"), "")
			kvs := []KV{{"sslCert", cert}, {"sslKey", key}}
			p.edit("Turn on HTTPS in options.json", data+"/Config/options.json", kvDetail("", kvs),
				func(old []byte) ([]byte, error) { return SetJSON(old, kvs) })
			p.run("Restart Foundry VTT", p.runAs(p.opt("restart")))
			p.notes = append(p.notes, "If Foundry sits behind a reverse proxy, deploy to the proxy (nginx or Apache) instead and leave Foundry on plain HTTP.")
			return nil
		},
	},
	{
		ID: "linux", Label: "Other Linux service", Transport: "ssh", DefaultPort: 22, VerifyWait: 30,
		Description: "Any service that reads PEM files (HAProxy, Caddy, Postfix, a Docker volume...): copy the files over SSH and run your own reload command.",
		Fields: append([]Field{
			{Key: "format", Label: "Format", Default: "separate", Type: "select", Choices: []string{"separate", "combined"}, Help: "separate: full chain and key in two files. combined: leaf, chain and key in one file (HAProxy)."},
			checkField("cert_path", "Certificate file (full chain)", "/etc/ssl/ncc/{cert}.crt", ""),
			checkField("key_path", "Private key file", "/etc/ssl/ncc/{cert}.key", ""),
			checkField("combined_path", "Combined file", "/etc/ssl/ncc/{cert}.pem", "Used when the format is combined."),
			checkField("owner", "File owner", "", "Leave empty to keep the existing owner."),
			checkField("run_as", "Run reload as", "", ""),
			checkField("reload", "Reload command", "", "For example systemctl reload haproxy. Leave empty to only copy the files."),
			checkField("https_port", "TLS port to check", "443", "Leave empty to skip the check."),
			checkField("check_name", "Host name to check", "", ""),
		}, sshFields...),
		build: func(p *planner) error {
			if p.opt("format") == "combined" {
				f, err := p.path("combined_path")
				if err != nil {
					return err
				}
				p.write("Upload combined certificate, chain and key", f, []byte(p.m.LeafPEM+p.m.ChainPEM+p.m.KeyPEM), "0600", p.opt("owner"), "")
			} else {
				cert, err := p.path("cert_path")
				if err != nil {
					return err
				}
				key, err := p.path("key_path")
				if err != nil {
					return err
				}
				p.write("Upload certificate and chain", cert, []byte(p.m.FullChainPEM), "0644", p.opt("owner"), "")
				p.write("Upload private key", key, []byte(p.m.KeyPEM), "0600", p.opt("owner"), "")
			}
			p.run("Reload the service", p.runAs(p.opt("reload")))
			return nil
		},
	},
	{
		ID: "iis", Label: "IIS (Windows)", Transport: "winrm", DefaultPort: 5986, VerifyWait: 30,
		Description: "Over WinRM (HTTPS): imports a PFX into the Local Machine Personal store, puts intermediates in the Intermediate store, and binds it to an IIS site's HTTPS binding.",
		Fields: []Field{
			checkField("site", "IIS site", "Default Web Site", ""),
			checkField("https_port", "HTTPS binding port", "443", ""),
			checkField("host_header", "Host name (binding)", "", "Leave empty for the site's catch-all HTTPS binding."),
			{Key: "sni", Label: "Require SNI", Default: "false", Type: "bool", Help: "Needed when several sites share the port with different host names."},
			{Key: "auth", Label: "WinRM authentication", Default: "ntlm", Type: "select", Choices: []string{"ntlm", "basic"}, Help: "NTLM works with local and domain accounts. Basic needs Basic auth turned on in WinRM."},
			{Key: "verify_tls", Label: "Check WinRM certificate against CAs", Default: "false", Type: "bool", Help: "Off: pin the WinRM listener's certificate on first use (right for the usual self-signed listener)."},
			checkField("tls_pin", "WinRM certificate pin", "", "SHA-256 fingerprint of the WinRM listener's certificate. Set when you confirm it in the first preview."),
			checkField("check_name", "Host name to check", "", "Defaults to the binding's host name."),
		},
		build: func(p *planner) error {
			site := p.opt("site")
			port, err := strconv.Atoi(p.opt("https_port"))
			if err != nil || port < 1 || port > 65535 {
				return errors.New("set a valid HTTPS binding port")
			}
			if site == "" {
				return errors.New("set the IIS site")
			}
			host := p.opt("host_header")
			sni := p.bool("sni")
			if sni && host == "" {
				return errors.New("SNI needs a host name")
			}
			pw := RandomPassword()
			pfx, err := p.m.PFX(pw)
			if err != nil {
				return fmt.Errorf("build PFX: %w", err)
			}
			thumb := Thumbprint(p.m.Leaf)
			tmp := `C:\Windows\Temp\ncc-` + strings.ToLower(thumb[:12]) + `.pfx`
			p.write("Upload PFX (temporary file)", tmp, pfx, "", "", fmt.Sprintf("%d bytes, protected by a one-time password; deleted after import", len(pfx)))
			friendly := p.m.Name + " (NCC " + p.m.Leaf.NotAfter.Format("2006-01-02") + ")"
			p.runHiding("Import into Local Machine\\Personal", "try{$pw=ConvertTo-SecureString "+psQuote(pw)+" -AsPlainText -Force\n"+
				"Import-PfxCertificate -FilePath "+psQuote(tmp)+" -CertStoreLocation Cert:\\LocalMachine\\My -Password $pw|Out-Null\n"+
				"$c=Get-Item Cert:\\LocalMachine\\My\\"+thumb+";$c.FriendlyName="+psQuote(friendly)+"\n"+
				"'imported '+$c.Thumbprint}finally{Remove-Item -LiteralPath "+psQuote(tmp)+" -ErrorAction SilentlyContinue}", pw)
			if len(p.m.Chain) > 0 {
				var ts []string
				for _, c := range p.m.Chain {
					if c.Subject.String() == c.Issuer.String() {
						continue // a root that came with the chain stays wherever Windows put it
					}
					ts = append(ts, psQuote(Thumbprint(c)))
				}
				if len(ts) > 0 {
					p.run("Move intermediates to the Intermediate store", "$s=New-Object Security.Cryptography.X509Certificates.X509Store('CA','LocalMachine');$s.Open('ReadWrite')\n"+
						"foreach($t in @("+strings.Join(ts, ",")+")){$x=Get-Item ('Cert:\\LocalMachine\\My\\'+$t) -ErrorAction SilentlyContinue\n"+
						"if($x){$s.Add($x);Remove-Item $x.PSPath;'moved '+$t}}\n$s.Close()")
				}
			}
			flags := "0"
			if sni {
				flags = "1"
			}
			args := "-Name " + psQuote(site) + " -Protocol https -Port " + strconv.Itoa(port) + " -HostHeader " + psQuote(host)
			p.run(fmt.Sprintf("Bind to %s https/%d%s", site, port, map[bool]string{true: " (" + host + ")", false: ""}[host != ""]),
				"Import-Module WebAdministration\n"+
					"if(-not(Get-Website -Name "+psQuote(site)+")){throw 'IIS site not found: '+"+psQuote(site)+"}\n"+
					"$b=Get-WebBinding "+args+"\n"+
					"if(-not $b){New-WebBinding "+args+" -SslFlags "+flags+";$b=Get-WebBinding "+args+";'added binding'}\n"+
					"try{$b.RemoveSslCertificate()}catch{}\n"+
					"$b.AddSslCertificate('"+thumb+"','My')\n'bound "+thumb+"'")
			p.notes = append(p.notes, "The previous certificate stays in the Personal store so you can switch back in IIS Manager. Thumbprint of the new one: "+thumb+".")
			return nil
		},
	},
}

// Kinds lists the server types.
func Kinds() []*Kind { return kinds }

func kindByID(id string) *Kind {
	for _, k := range kinds {
		if k.ID == id {
			return k
		}
	}
	return nil
}
