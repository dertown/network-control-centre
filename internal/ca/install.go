package ca

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/xml"
	"fmt"
	"strings"
)

// Platform is how to make one kind of device trust the root CA.
type Platform struct {
	ID    string   `json:"id"`
	Label string   `json:"label"`
	Steps []string `json:"steps"`
	// Commands are copyable shell or PowerShell lines.
	Commands []string `json:"commands,omitempty"`
	// Pushable says NCC can do it for you from Certificate Deployment (kind id).
	Pushable string `json:"pushable,omitempty"`
}

// fileBase is a safe file name for a CA's downloads.
func fileBase(name string) string {
	var b strings.Builder
	for _, r := range name {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '-', r == '.', r == '_':
			b.WriteRune(r)
		default:
			b.WriteRune('-')
		}
	}
	return strings.Trim(b.String(), "-.")
}

// FileBase is the name NCC gives a CA's download files (without extension).
func (c *CA) FileBase() string { return fileBase(c.Name) }

// Install lists, per platform, how to trust the root CA. base is NCC's public address
// (e.g. https://ncc.home.arpa); files are linked under base/pki/ca/{id}.
func Install(root *CA, base string) []Platform {
	base = strings.TrimSuffix(base, "/")
	u := fmt.Sprintf("%s/pki/ca/%d", base, root.ID)
	f := root.FileBase()
	thumb := root.Thumbprint
	return []Platform{
		{
			ID: "windows", Label: "Windows", Pushable: "windows-trust",
			Steps: []string{
				"Download the .crt file, double-click it, choose Install Certificate, pick Local Machine and put it in Trusted Root Certification Authorities.",
				"Or run this in an elevated PowerShell:",
				"For a whole Active Directory domain, publish it once from a domain admin prompt (second command); domain members pick it up at their next Group Policy refresh.",
			},
			Commands: []string{
				fmt.Sprintf(`Invoke-WebRequest %s.crt -OutFile $env:TEMP\%s.crt; Import-Certificate -FilePath $env:TEMP\%s.crt -CertStoreLocation Cert:\LocalMachine\Root`, u, f, f),
				fmt.Sprintf(`certutil -dspublish -f %s.crt RootCA`, f),
			},
		},
		{
			ID: "macos", Label: "macOS",
			Steps: []string{
				"Download the .mobileconfig profile and open it, then approve it in System Settings > General > Device Management (Profiles).",
				"Or add the certificate to the System keychain from Terminal:",
			},
			Commands: []string{
				fmt.Sprintf(`curl -fsSLo /tmp/%s.crt %s.crt && sudo security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain /tmp/%s.crt`, f, u, f),
			},
		},
		{
			ID: "ios", Label: "iPhone and iPad",
			Steps: []string{
				"Open " + u + ".mobileconfig in Safari and allow the download.",
				"Settings > General > VPN & Device Management: install the downloaded profile.",
				"Settings > General > About > Certificate Trust Settings: turn on full trust for " + root.CommonName + ". Without this step Safari still warns.",
			},
		},
		{
			ID: "android", Label: "Android",
			Steps: []string{
				"Download the .crt file on the phone.",
				"Settings > Security > More security settings > Encryption & credentials > Install a certificate > CA certificate (names vary by maker), and pick the file.",
				"Android apps only trust user-installed CAs if they opt in; Chrome and most browsers do.",
			},
		},
		{
			ID: "linux", Label: "Linux", Pushable: "linux-trust",
			Steps: []string{
				"Debian, Ubuntu, Alpine:",
				"Fedora, RHEL, Rocky, Alma, Arch:",
				"Firefox keeps its own store: in Settings > Privacy & Security > Certificates, turn on \"Allow Firefox to automatically trust third-party root certificates\" (Windows and macOS) or import the .crt under View Certificates > Authorities.",
			},
			Commands: []string{
				fmt.Sprintf(`sudo curl -fsSLo /usr/local/share/ca-certificates/%s.crt %s.pem && sudo update-ca-certificates`, f, u),
				fmt.Sprintf(`sudo curl -fsSLo /etc/pki/ca-trust/source/anchors/%s.crt %s.pem && sudo update-ca-trust`, f, u),
			},
		},
		{
			ID: "other", Label: "Network gear, NAS and apps",
			Steps: []string{
				"Most routers, NAS boxes, printers and hypervisors have a \"Trusted CA\" or \"Import CA certificate\" page: upload the .pem (or .crt) file there.",
				"Java apps use their own truststore: keytool -importcert -cacerts -alias " + strings.ToLower(f) + " -file " + f + ".pem",
				"Python requests and Node.js use their own lists: point REQUESTS_CA_BUNDLE or NODE_EXTRA_CA_CERTS at the .pem file.",
				"Check the fingerprint before trusting: SHA-256 " + colonHex(root.Fingerprint) + " (Windows thumbprint " + thumb + ").",
			},
		},
	}
}

func colonHex(h string) string {
	h = strings.ToUpper(h)
	var parts []string
	for i := 0; i+2 <= len(h); i += 2 {
		parts = append(parts, h[i:i+2])
	}
	return strings.Join(parts, ":")
}

// InstallText is Install as plain text, for sharing a link with people who install it themselves.
func InstallText(root *CA, base string) string {
	var b strings.Builder
	fmt.Fprintf(&b, "Trusting %s\n%s\n\n", root.CommonName, strings.Repeat("=", len(root.CommonName)+9))
	fmt.Fprintf(&b, "Your network uses its own certificate authority. Install its root certificate once per\ndevice so internal sites open without warnings.\n\n")
	u := fmt.Sprintf("%s/pki/ca/%d", strings.TrimSuffix(base, "/"), root.ID)
	fmt.Fprintf(&b, "Files:\n  %s.crt          (Windows, Android: DER)\n  %s.pem          (Linux, apps, network gear)\n  %s.mobileconfig (iPhone, iPad, Mac)\n\n", u, u, u)
	fmt.Fprintf(&b, "SHA-256 fingerprint: %s\n\n", colonHex(root.Fingerprint))
	for _, p := range Install(root, base) {
		fmt.Fprintf(&b, "%s\n%s\n", p.Label, strings.Repeat("-", len(p.Label)))
		ci := 0
		for _, s := range p.Steps {
			fmt.Fprintf(&b, "- %s\n", s)
			if strings.HasSuffix(s, ":") && ci < len(p.Commands) {
				fmt.Fprintf(&b, "    %s\n", p.Commands[ci])
				ci++
			}
		}
		for ; ci < len(p.Commands); ci++ {
			fmt.Fprintf(&b, "    %s\n", p.Commands[ci])
		}
		b.WriteString("\n")
	}
	return b.String()
}

// MobileConfig is an Apple configuration profile that installs the root CA (iOS, iPadOS,
// macOS). It is unsigned, so devices show it as "Not Verified"; the fingerprint is in the
// description so people can compare it.
func MobileConfig(root *CA) []byte {
	uuid := func() string {
		b := make([]byte, 16)
		_, _ = rand.Read(b)
		b[6] = b[6]&0x0f | 0x40
		b[8] = b[8]&0x3f | 0x80
		h := strings.ToUpper(hex.EncodeToString(b))
		return h[0:8] + "-" + h[8:12] + "-" + h[12:16] + "-" + h[16:20] + "-" + h[20:]
	}
	esc := func(s string) string {
		var b bytes.Buffer
		_ = xml.EscapeText(&b, []byte(s))
		return b.String()
	}
	id := "ncc.ca." + strings.ToLower(root.Fingerprint[:16])
	der := base64.StdEncoding.EncodeToString(root.cert.Raw)
	var wrapped strings.Builder
	for i := 0; i < len(der); i += 52 {
		end := min(i+52, len(der))
		wrapped.WriteString("\t\t\t" + der[i:end] + "\n")
	}
	return []byte(`<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>PayloadContent</key>
	<array>
		<dict>
		<key>PayloadCertificateFileName</key>
		<string>` + esc(root.FileBase()) + `.cer</string>
		<key>PayloadContent</key>
		<data>
` + wrapped.String() + `		</data>
		<key>PayloadDisplayName</key>
		<string>` + esc(root.CommonName) + `</string>
		<key>PayloadIdentifier</key>
		<string>` + id + `.cert</string>
		<key>PayloadType</key>
		<string>com.apple.security.root</string>
		<key>PayloadUUID</key>
		<string>` + uuid() + `</string>
		<key>PayloadVersion</key>
		<integer>1</integer>
		</dict>
	</array>
	<key>PayloadDescription</key>
	<string>` + esc("Trusts "+root.CommonName+", this network's own certificate authority. SHA-256 "+colonHex(root.Fingerprint)) + `</string>
	<key>PayloadDisplayName</key>
	<string>` + esc(root.CommonName) + `</string>
	<key>PayloadIdentifier</key>
	<string>` + id + `</string>
	<key>PayloadRemovalDisallowed</key>
	<false/>
	<key>PayloadType</key>
	<string>Configuration</string>
	<key>PayloadUUID</key>
	<string>` + uuid() + `</string>
	<key>PayloadVersion</key>
	<integer>1</integer>
</dict>
</plist>
`)
}
