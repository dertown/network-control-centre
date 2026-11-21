package certdeploy

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/xml"
	"errors"
	"fmt"
	"html"
	"io"
	"io/fs"
	"net"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"
	"unicode/utf16"

	ntlmssp "github.com/Azure/go-ntlmssp"

	"github.com/dertown/network-control-centre/internal/netutil"
)

// WinRMOptions configures a WinRM (WS-Management) connection to a Windows server.
type WinRMOptions struct {
	Host     string
	Port     int    // 5986 for HTTPS (default), 5985 for HTTP
	HTTPS    bool   // HTTP is refused: NTLM over plain HTTP needs message encryption NCC does not do
	Auth     string // "ntlm" (default) or "basic"
	User     string
	Password string
	// TLSPin pins the WinRM listener's certificate (SHA-256). Empty with AcceptPin set trusts that
	// fingerprint (first use, confirmed in the preview). With both empty, normal CA checks apply
	// when Verify is true, and the connection is refused otherwise.
	TLSPin    string
	AcceptPin string
	Verify    bool
	Timeout   time.Duration
}

type tlsState = tls.ConnectionState

// ErrTLSPinUnknown means the WinRM listener's certificate has not been pinned yet.
type ErrTLSPinUnknown struct{ Seen string }

func (e *ErrTLSPinUnknown) Error() string {
	return "this server's WinRM certificate is not trusted yet (SHA-256 " + e.Seen + "); confirm it in the preview"
}

type winrmConn struct {
	url     string
	hc      *http.Client
	o       WinRMOptions
	shellID string
}

const (
	nsShell      = "http://schemas.microsoft.com/wbem/wsman/1/windows/shell"
	resourceCmd  = nsShell + "/cmd"
	actCreate    = "http://schemas.xmlsoap.org/ws/2004/09/transfer/Create"
	actDelete    = "http://schemas.xmlsoap.org/ws/2004/09/transfer/Delete"
	actCommand   = nsShell + "/Command"
	actReceive   = nsShell + "/Receive"
	actSignal    = nsShell + "/Signal"
	stateDone    = nsShell + "/CommandState/Done"
	signalTerm   = nsShell + "/signal/terminate"
	maxCmdLength = 8000 // cmd.exe's command line limit is 8191
)

// DialWinRM opens a remote shell. The returned string is the listener certificate fingerprint seen.
func DialWinRM(ctx context.Context, o WinRMOptions) (Conn, string, error) {
	if !o.HTTPS {
		return nil, "", errors.New("WinRM over plain HTTP is not supported; enable the HTTPS listener (port 5986) on the server")
	}
	if o.Port == 0 {
		o.Port = 5986
	}
	if o.Timeout == 0 {
		o.Timeout = 60 * time.Second
	}
	if o.User == "" || o.Password == "" {
		return nil, "", errors.New("no Windows user name and password saved for this server")
	}
	mode, pin := "pin", o.TLSPin
	if pin == "" {
		pin = o.AcceptPin
	}
	if pin == "" && o.Verify {
		mode = ""
	}
	tlsCfg, pinner := netutil.TLSConfig(mode, pin)
	if mode == "pin" && pin == "" {
		// learn the fingerprint, then refuse: the person confirms it in the preview first
		inner := tlsCfg.VerifyConnection
		tlsCfg.VerifyConnection = func(cs tlsState) error {
			_ = inner(cs)
			return &ErrTLSPinUnknown{Seen: pinner.Seen()}
		}
	}
	tr := &http.Transport{
		TLSClientConfig:     tlsCfg,
		DialContext:         (&net.Dialer{Timeout: 15 * time.Second}).DialContext,
		TLSHandshakeTimeout: 15 * time.Second,
		MaxIdleConnsPerHost: 1,
	}
	var rt http.RoundTripper = tr
	if !strings.EqualFold(o.Auth, "basic") {
		rt = ntlmssp.Negotiator{RoundTripper: tr}
	}
	c := &winrmConn{
		url: "https://" + net.JoinHostPort(o.Host, strconv.Itoa(o.Port)) + "/wsman",
		hc:  &http.Client{Transport: rt, Timeout: o.Timeout + 30*time.Second},
		o:   o,
	}
	body := `<rsp:Shell><rsp:InputStreams>stdin</rsp:InputStreams><rsp:OutputStreams>stdout stderr</rsp:OutputStreams></rsp:Shell>`
	opts := `<w:OptionSet><w:Option Name="WINRS_NOPROFILE">TRUE</w:Option><w:Option Name="WINRS_CODEPAGE">65001</w:Option></w:OptionSet>`
	resp, err := c.call(ctx, actCreate, "", opts, body)
	if err != nil {
		var pe *ErrTLSPinUnknown
		if errors.As(err, &pe) {
			return nil, pinner.Seen(), pe
		}
		return nil, pinner.Seen(), err
	}
	c.shellID = resp.ShellID
	if c.shellID == "" {
		return nil, pinner.Seen(), errors.New("WinRM did not return a shell id")
	}
	return c, pinner.Seen(), nil
}

func (c *winrmConn) Close() error {
	if c.shellID == "" {
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	_, err := c.call(ctx, actDelete, c.shellID, "", "")
	c.shellID = ""
	return err
}

// Run runs a PowerShell script and returns standard output.
func (c *winrmConn) Run(ctx context.Context, script string) (string, error) {
	wrapped := "$ErrorActionPreference='Stop';$ProgressPreference='SilentlyContinue';try{\n" + script +
		"\n}catch{[Console]::Error.WriteLine($_.Exception.Message);exit 1}"
	args := "-NoProfile -NonInteractive -ExecutionPolicy Bypass -EncodedCommand " + encodePS(wrapped)
	if len(args) > maxCmdLength {
		return "", fmt.Errorf("PowerShell script too long for one WinRM command (%d characters)", len(args))
	}
	body := `<rsp:CommandLine><rsp:Command>powershell.exe</rsp:Command><rsp:Arguments>` + args + `</rsp:Arguments></rsp:CommandLine>`
	opts := `<w:OptionSet><w:Option Name="WINRS_CONSOLEMODE_STDIN">TRUE</w:Option><w:Option Name="WINRS_SKIP_CMD_SHELL">TRUE</w:Option></w:OptionSet>`
	resp, err := c.call(ctx, actCommand, c.shellID, opts, body)
	if err != nil {
		return "", err
	}
	cmdID := resp.CommandID
	defer func() {
		sctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_, _ = c.call(sctx, actSignal, c.shellID, "",
			`<rsp:Signal CommandId="`+cmdID+`"><rsp:Code>`+signalTerm+`</rsp:Code></rsp:Signal>`)
	}()
	var stdout, stderr bytes.Buffer
	for {
		if err := ctx.Err(); err != nil {
			return stdout.String(), err
		}
		r, err := c.call(ctx, actReceive, c.shellID, "",
			`<rsp:Receive><rsp:DesiredStream CommandId="`+cmdID+`">stdout stderr</rsp:DesiredStream></rsp:Receive>`)
		if err != nil {
			if strings.Contains(err.Error(), "2150858793") { // operation timed out: nothing new yet
				continue
			}
			return stdout.String(), err
		}
		stdout.Write(r.Stdout)
		stderr.Write(r.Stderr)
		if r.Done {
			if r.ExitCode != 0 {
				msg := cleanCLIXML(stderr.String())
				if msg == "" {
					msg = strings.TrimSpace(stdout.String())
				}
				return stdout.String(), fmt.Errorf("exit code %d: %s", r.ExitCode, msg)
			}
			return stdout.String(), nil
		}
	}
}

// WriteFile sends a file in base64 chunks (WinRM has no file copy) and decodes it on the server.
func (c *winrmConn) WriteFile(ctx context.Context, path string, data []byte, _, _ string) error {
	b64 := base64.StdEncoding.EncodeToString(data)
	part := psQuote(path + ".b64")
	if _, err := c.Run(ctx, "Set-Content -LiteralPath "+part+" -Value '' -NoNewline"); err != nil {
		return err
	}
	const chunk = 2400
	for i := 0; i < len(b64); i += chunk {
		end := min(i+chunk, len(b64))
		if _, err := c.Run(ctx, "Add-Content -LiteralPath "+part+" -Value '"+b64[i:end]+"' -NoNewline"); err != nil {
			return err
		}
	}
	_, err := c.Run(ctx, "[IO.File]::WriteAllBytes("+psQuote(path)+",[Convert]::FromBase64String((Get-Content -LiteralPath "+part+
		" -Raw)));Remove-Item -LiteralPath "+part)
	return err
}

func (c *winrmConn) ReadFile(ctx context.Context, path string) ([]byte, error) {
	out, err := c.Run(ctx, "if(Test-Path -LiteralPath "+psQuote(path)+"){[Convert]::ToBase64String([IO.File]::ReadAllBytes("+psQuote(path)+"))}else{'__NCC_MISSING__'}")
	if err != nil {
		return nil, err
	}
	out = strings.TrimSpace(out)
	if out == "__NCC_MISSING__" {
		return nil, fs.ErrNotExist
	}
	return base64.StdEncoding.DecodeString(out)
}

type wsResp struct {
	ShellID, CommandID string
	Stdout, Stderr     []byte
	Done               bool
	ExitCode           int
}

func (c *winrmConn) call(ctx context.Context, action, shellID, options, body string) (*wsResp, error) {
	env := c.envelope(action, shellID, options, body)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.url, strings.NewReader(env))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/soap+xml;charset=UTF-8")
	req.SetBasicAuth(c.o.User, c.o.Password)
	res, err := c.hc.Do(req)
	if err != nil {
		var pe *ErrTLSPinUnknown
		if errors.As(err, &pe) {
			return nil, pe
		}
		return nil, err
	}
	defer res.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(res.Body, 16<<20))
	if res.StatusCode == http.StatusUnauthorized {
		return nil, errors.New("WinRM refused the user name or password (401)")
	}
	out, fault := parseWS(raw)
	if res.StatusCode != http.StatusOK {
		if fault == "" {
			fault = res.Status
		}
		return nil, errors.New("WinRM: " + fault)
	}
	return out, nil
}

func (c *winrmConn) envelope(action, shellID, options, body string) string {
	var b strings.Builder
	b.WriteString(`<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope" xmlns:a="http://schemas.xmlsoap.org/ws/2004/08/addressing" xmlns:w="http://schemas.dmtf.org/wbem/wsman/1/wsman.xsd" xmlns:p="http://schemas.microsoft.com/wbem/wsman/1/wsman.xsd" xmlns:rsp="http://schemas.microsoft.com/wbem/wsman/1/windows/shell"><s:Header>`)
	b.WriteString(`<a:To>` + html.EscapeString(c.url) + `</a:To>`)
	b.WriteString(`<w:ResourceURI s:mustUnderstand="true">` + resourceCmd + `</w:ResourceURI>`)
	b.WriteString(`<a:ReplyTo><a:Address s:mustUnderstand="true">http://schemas.xmlsoap.org/ws/2004/08/addressing/role/anonymous</a:Address></a:ReplyTo>`)
	b.WriteString(`<a:Action s:mustUnderstand="true">` + action + `</a:Action>`)
	b.WriteString(`<w:MaxEnvelopeSize s:mustUnderstand="true">512000</w:MaxEnvelopeSize>`)
	b.WriteString(`<a:MessageID>uuid:` + newUUID() + `</a:MessageID>`)
	b.WriteString(`<w:Locale xml:lang="en-US" s:mustUnderstand="false"/>`)
	b.WriteString(`<w:OperationTimeout>PT20S</w:OperationTimeout>`)
	if shellID != "" {
		b.WriteString(`<w:SelectorSet><w:Selector Name="ShellId">` + html.EscapeString(shellID) + `</w:Selector></w:SelectorSet>`)
	}
	b.WriteString(options)
	b.WriteString(`</s:Header><s:Body>` + body + `</s:Body></s:Envelope>`)
	return b.String()
}

// parseWS pulls the bits NCC needs out of a WS-Management response, ignoring namespaces.
func parseWS(raw []byte) (*wsResp, string) {
	out := &wsResp{}
	var fault []string
	dec := xml.NewDecoder(bytes.NewReader(raw))
	var stack []string
	var streamName string
	for {
		tok, err := dec.Token()
		if err != nil {
			break
		}
		switch t := tok.(type) {
		case xml.StartElement:
			stack = append(stack, t.Name.Local)
			switch t.Name.Local {
			case "Stream":
				streamName = attr(t, "Name")
			case "CommandState":
				if attr(t, "State") == stateDone {
					out.Done = true
				}
			}
		case xml.EndElement:
			if len(stack) > 0 {
				stack = stack[:len(stack)-1]
			}
		case xml.CharData:
			if len(stack) == 0 {
				continue
			}
			text := strings.TrimSpace(string(t))
			if text == "" {
				continue
			}
			inFault := false
			for _, s := range stack {
				if s == "Fault" {
					inFault = true
				}
			}
			switch cur := stack[len(stack)-1]; {
			case cur == "ShellId":
				out.ShellID = text
			case cur == "CommandId":
				out.CommandID = text
			case cur == "Stream":
				b, _ := base64.StdEncoding.DecodeString(text)
				if streamName == "stderr" {
					out.Stderr = append(out.Stderr, b...)
				} else {
					out.Stdout = append(out.Stdout, b...)
				}
			case cur == "ExitCode":
				out.ExitCode, _ = strconv.Atoi(text)
			case inFault && (cur == "Text" || cur == "Message" || cur == "Value"):
				fault = append(fault, text)
			}
		}
	}
	// WSManFault carries the numeric code as an attribute
	if m := regexp.MustCompile(`Code="(\d+)"`).FindSubmatch(raw); m != nil && len(fault) > 0 {
		fault = append(fault, "("+string(m[1])+")")
	}
	return out, strings.Join(fault, " ")
}

func attr(t xml.StartElement, name string) string {
	for _, a := range t.Attr {
		if a.Name.Local == name {
			return a.Value
		}
	}
	return ""
}

var clixmlRe = regexp.MustCompile(`<S S="Error">(.*?)</S>`)

// cleanCLIXML turns PowerShell's serialized error stream into plain text.
func cleanCLIXML(s string) string {
	if !strings.Contains(s, "CLIXML") {
		return strings.TrimSpace(s)
	}
	var parts []string
	for _, m := range clixmlRe.FindAllStringSubmatch(s, -1) {
		parts = append(parts, strings.ReplaceAll(html.UnescapeString(m[1]), "_x000D__x000A_", " "))
	}
	return strings.TrimSpace(strings.Join(parts, ""))
}

// encodePS encodes a script for powershell -EncodedCommand (UTF-16LE, base64).
func encodePS(s string) string {
	u := utf16.Encode([]rune(s))
	b := make([]byte, len(u)*2)
	for i, r := range u {
		binary.LittleEndian.PutUint16(b[i*2:], r)
	}
	return base64.StdEncoding.EncodeToString(b)
}

// psQuote quotes a string for PowerShell (single quotes, doubled inside).
func psQuote(s string) string { return "'" + strings.ReplaceAll(s, "'", "''") + "'" }

func newUUID() string {
	var b [16]byte
	_, _ = rand.Read(b[:])
	b[6] = b[6]&0x0f | 0x40
	b[8] = b[8]&0x3f | 0x80
	h := hex.EncodeToString(b[:])
	return h[:8] + "-" + h[8:12] + "-" + h[12:16] + "-" + h[16:20] + "-" + h[20:]
}
