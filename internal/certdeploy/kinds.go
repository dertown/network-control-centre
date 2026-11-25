package certdeploy

import (
	"crypto/x509"
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
	// Trust kinds install a CA certificate into the server's trust store instead of a server
	// certificate and key: pick a CA (or a certificate whose chain holds its root).
	Trust bool `json:"trust,omitempty"`

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

// caBundle writes the CA bundle (intermediates and root) to ca_path when that is set, and
// returns the path written ("" when skipped).
func (p *planner) caBundle(owner string) (string, error) {
	if p.opt("ca_path") == "" {
		return "", nil
	}
	path, err := p.path("ca_path")
	if err != nil {
		return "", err
	}
	if p.m.CABundlePEM == "" {
		p.warnings = append(p.warnings, "A CA bundle file is set ("+path+") but this certificate has no CA certificates stored with it, so it is not written. Add the CA bundle to the certificate under Vault & certificates.")
		return "", nil
	}
	what := fmt.Sprintf("%d CA certificate(s)", len(p.m.Chain))
	if len(p.m.Roots) > 0 {
		what += ", including the root"
	}
	p.write("Upload CA bundle", path, []byte(p.m.CABundlePEM), "0644", owner, fmt.Sprintf("%s, %d bytes, mode 0644", what, len(p.m.CABundlePEM)))
	return path, nil
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
	{Key: "use_sudo", Label: "Use sudo", Default: "true", Type: "bool", Help: "Run file writes and restarts through sudo (not needed when logging in as root). The login password is used for sudo unless a separate sudo password is saved. Turn off when the login user owns the service's files, e.g. the splunk user."},
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
			checkField("ca_path", "CA bundle file (optional)", "", "Intermediates and root in one file, e.g. for ssl_trusted_certificate (OCSP stapling). The certificate file already holds the intermediates."),
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
			if _, err := p.caBundle(p.opt("owner")); err != nil {
				return err
			}
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
			checkField("ca_path", "CA bundle file (optional)", "", "Intermediates and root in one file, e.g. for SSLCACertificateFile."),
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
			if _, err := p.caBundle(p.opt("owner")); err != nil {
				return err
			}
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
			checkField("ca_path", "CA bundle file (optional)", "", "Intermediates and root in one file, e.g. for a truststore or caCertificateFile. The keystore and chain file already hold the intermediates."),
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
				if p.m.ChainPEM != "" {
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
			if _, err := p.caBundle(owner); err != nil {
				return err
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
			checkField("ca_path", "CA bundle file (optional)", "", "Intermediates and root in one file. When splunkd is included, it is also set as sslRootCAPath in server.conf [sslConfig], which changes which CAs splunkd trusts for forwarders and clustering."),
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
			ca, err := p.caBundle(owner)
			if err != nil {
				return err
			}
			if comp == "splunkd" || comp == "web+splunkd" {
				cert, err := p.path("server_cert_path")
				if err != nil {
					return err
				}
				p.write("Upload splunkd certificate (leaf, key and chain)", cert, []byte(p.m.CombinedPEM()), "0600", owner, "")
				kvs := []KV{{"serverCert", cert}}
				if ca != "" {
					kvs = append(kvs, KV{"sslRootCAPath", ca})
				}
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
			checkField("ca_path", "CA bundle file (optional)", "", "Intermediates and root in one file, if something on the server needs them separately."),
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
			if _, err := p.caBundle(p.opt("owner")); err != nil {
				return err
			}
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
			checkField("ca_path", "CA bundle file (optional)", "", "Intermediates and root in one file, if something on the server needs them separately."),
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
			if _, err := p.caBundle(p.opt("owner")); err != nil {
				return err
			}
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
			checkField("ca_path", "CA bundle file (optional)", "", "Intermediates and root in one file, e.g. HAProxy ca-file."),
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
			if _, err := p.caBundle(p.opt("owner")); err != nil {
				return err
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
			{Key: "trust_root", Label: "Trust the root CA", Default: "false", Type: "bool", Help: "When the certificate's CA bundle includes a root, add it to Local Machine\\Trusted Root Certification Authorities."},
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
			if len(p.m.Roots) > 0 {
				var rs []string
				for _, c := range p.m.Roots {
					rs = append(rs, psQuote(Thumbprint(c)))
				}
				if p.bool("trust_root") {
					p.run("Add the root CA to Trusted Root Certification Authorities", "$s=New-Object Security.Cryptography.X509Certificates.X509Store('Root','LocalMachine');$s.Open('ReadWrite')\n"+
						"foreach($t in @("+strings.Join(rs, ",")+")){$x=Get-Item ('Cert:\\LocalMachine\\My\\'+$t) -ErrorAction SilentlyContinue\n"+
						"if($x){$s.Add($x);Remove-Item $x.PSPath;'trusted '+$t}}\n$s.Close()")
				} else {
					p.notes = append(p.notes, "The CA bundle's root is not added to Trusted Root Certification Authorities. Turn on \"Trust the root CA\" if this server should trust it (needed for a private CA the server itself must trust).")
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

// trustKinds put a CA certificate into a server's system trust store, so the server (and
// everything on it that uses the system store: curl, package managers, most services) trusts
// certificates the CA signs.
var trustKinds = []*Kind{
	{
		ID: "linux-trust", Label: "Linux trust store", Transport: "ssh", DefaultPort: 22, Trust: true,
		Description: "Adds a CA certificate (such as NCC's internal root) to a Linux server's system trust store over SSH: Debian, Ubuntu, Alpine, Fedora, RHEL, SUSE and Arch.",
		Fields: append([]Field{
			checkField("file_name", "File name", "ncc-{cert}", "Name of the file in the trust store folder (.crt is added)."),
		}, sshFields...),
		build: func(p *planner) error {
			base := safeName(p.opt("file_name"))
			if base == "" {
				return errors.New("set the file name")
			}
			stage := "/usr/local/share/ncc-ca/" + base + ".crt"
			p.write("Upload CA certificate", stage, []byte(p.m.TrustPEM), "0644", "", fmt.Sprintf("%d CA certificate(s): %s", len(p.m.Trust), trustNames(p.m)))
			p.run("Add it to the system trust store", linuxTrustScript(stage, base+".crt"))
			p.run("Check the system bundle holds it", linuxTrustCheck(p.m))
			p.notes = append(p.notes, "Firefox and Java keep their own trust stores; see the install instructions on the Certificate Authority page for those.")
			return nil
		},
	},
	{
		ID: "windows-trust", Label: "Windows trust store", Transport: "winrm", DefaultPort: 5986, Trust: true,
		Description: "Over WinRM (HTTPS): imports a CA certificate into Local Machine\\Trusted Root Certification Authorities (intermediates into Intermediate Certification Authorities).",
		Fields: []Field{
			{Key: "auth", Label: "WinRM authentication", Default: "ntlm", Type: "select", Choices: []string{"ntlm", "basic"}, Help: "NTLM works with local and domain accounts. Basic needs Basic auth turned on in WinRM."},
			{Key: "verify_tls", Label: "Check WinRM certificate against CAs", Default: "false", Type: "bool", Help: "Off: pin the WinRM listener's certificate on first use (right for the usual self-signed listener)."},
			checkField("tls_pin", "WinRM certificate pin", "", "SHA-256 fingerprint of the WinRM listener's certificate. Set when you confirm it in the first preview."),
		},
		build: func(p *planner) error {
			for _, c := range p.m.Trust {
				thumb := Thumbprint(c)
				store, label := "Root", "Trusted Root Certification Authorities"
				if c.Subject.String() != c.Issuer.String() {
					store, label = "CA", "Intermediate Certification Authorities"
				}
				tmp := `C:\Windows\Temp\ncc-ca-` + strings.ToLower(thumb[:12]) + `.cer`
				p.write("Upload "+c.Subject.CommonName+" (temporary file)", tmp, c.Raw, "", "", fmt.Sprintf("%d bytes, deleted after import", len(c.Raw)))
				p.run("Import "+c.Subject.CommonName+" into "+label,
					"try{Import-Certificate -FilePath "+psQuote(tmp)+" -CertStoreLocation Cert:\\LocalMachine\\"+store+"|Out-Null}finally{Remove-Item -LiteralPath "+psQuote(tmp)+" -ErrorAction SilentlyContinue}\n"+
						"if(Test-Path Cert:\\LocalMachine\\"+store+"\\"+thumb+"){'trusted "+thumb+"'}else{throw 'not found in LocalMachine\\"+store+" after import'}")
			}
			p.notes = append(p.notes, "For every computer in an Active Directory domain at once, publish the root with certutil -dspublish instead (see the install instructions).")
			return nil
		},
	},
}

func trustNames(m *Material) string {
	var n []string
	for _, c := range m.Trust {
		n = append(n, c.Subject.CommonName)
	}
	return strings.Join(n, ", ")
}

// linuxTrustScript copies the staged file into whichever trust store the distribution uses and
// rebuilds the system bundle.
func linuxTrustScript(stage, file string) string {
	return strings.Join([]string{
		"set -e",
		"src=" + shQuote(stage) + "; f=" + shQuote(file),
		`if [ -d /usr/local/share/ca-certificates ] && command -v update-ca-certificates >/dev/null 2>&1; then`,
		`  install -m 0644 "$src" "/usr/local/share/ca-certificates/$f"; update-ca-certificates; echo "added with update-ca-certificates"`,
		`elif [ -d /etc/pki/ca-trust/source/anchors ]; then`,
		`  install -m 0644 "$src" "/etc/pki/ca-trust/source/anchors/$f"; update-ca-trust extract; echo "added with update-ca-trust"`,
		`elif [ -d /etc/pki/trust/anchors ]; then`,
		`  install -m 0644 "$src" "/etc/pki/trust/anchors/$f"; update-ca-certificates; echo "added with update-ca-certificates (SUSE)"`,
		`elif [ -d /etc/ca-certificates/trust-source/anchors ]; then`,
		`  install -m 0644 "$src" "/etc/ca-certificates/trust-source/anchors/$f"; (update-ca-trust extract 2>/dev/null || trust extract-compat); echo "added with update-ca-trust"`,
		`else`,
		`  echo "NCC does not recognise this system's trust store (no update-ca-certificates or update-ca-trust); install the ca-certificates package" >&2; exit 1`,
		`fi`,
	}, "\n")
}

// linuxTrustCheck looks for each CA certificate in the rebuilt system bundle.
func linuxTrustCheck(m *Material) string {
	lines := []string{"set -e", "found=0", "for b in /etc/ssl/certs/ca-certificates.crt /etc/pki/tls/certs/ca-bundle.crt /var/lib/ca-certificates/ca-bundle.pem /etc/ssl/cert.pem; do [ -f \"$b\" ] && bundle=$b && break; done",
		`[ -n "$bundle" ] || { echo "no system CA bundle found" >&2; exit 1; }`}
	for _, c := range m.Trust {
		line := pemLine(c)
		lines = append(lines, "grep -qF "+shQuote(line)+` "$bundle" || { echo `+shQuote(c.Subject.CommonName+" is not in")+` "$bundle" >&2; exit 1; }`)
	}
	lines = append(lines, `echo "in $bundle"`)
	return strings.Join(lines, "\n")
}

// pemLine is a line from the middle of a certificate's PEM body: unique to it, and the same in
// every bundle since they all wrap base64 at 64 characters.
func pemLine(c *x509.Certificate) string {
	body := strings.Split(strings.TrimSpace(encodeCerts([]*x509.Certificate{c})), "\n")
	body = body[1 : len(body)-1]
	return body[len(body)/2]
}

func init() { kinds = append(kinds, trustKinds...) }

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
