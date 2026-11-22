// Package assistant is NCC's AI network assistant. It reads the whole network (routers,
// VLANs, clients, the IoT inventory, port forwards and DNS zones), asks an AI model for a plan
// (which IoT devices to move to which VLAN, which DNS zones to create and which VLANs they
// serve) and, once a person has approved the plan, deploys it step by step through the same
// code the VLANs and DNS pages use.
//
// The models are reached through the person's existing subscriptions, never through API keys:
// NCC runs the vendors' own command-line tools (Claude Code, GitHub Copilot CLI, Gemini CLI,
// OpenAI Codex), signed in with the person's account, or a local model server (Ollama) that
// needs no account at all. Each tool's sign-in is kept in the vault and only written to a
// private temporary home folder while the tool runs.
package assistant

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strings"
)

// Provider kinds.
const (
	KindClaude  = "claude-code"
	KindCopilot = "copilot-cli"
	KindGemini  = "gemini-cli"
	KindCodex   = "codex-cli"
	KindOllama  = "ollama"
)

// Kind describes one way of reaching a model.
type Kind struct {
	ID    string `json:"id"`
	Label string `json:"label"`
	// Account is the subscription or account the sign-in uses.
	Account string `json:"account"`
	// Binary is the command-line tool NCC runs (empty for HTTP providers).
	Binary string `json:"binary,omitempty"`
	// Install is how to install the tool on the NCC host.
	Install string `json:"install,omitempty"`
	// SignIn is the tool's own sign-in command (arguments after Binary), run by NCC in a
	// terminal whose output is shown in the browser. Empty when no sign-in is needed.
	SignIn []string `json:"sign_in,omitempty"`
	// SignInHelp explains the sign-in in a sentence.
	SignInHelp string `json:"sign_in_help,omitempty"`
	// Paste describes what can be pasted instead of signing in from NCC (the result of
	// signing in on another computer), or "" when pasting is not offered.
	Paste string `json:"paste,omitempty"`
	// Note is anything the person should know about the vendor's terms.
	Note string `json:"note,omitempty"`
	// DefaultModel is used when no model is set ("" lets the tool choose).
	DefaultModel string `json:"default_model,omitempty"`
	// HTTP is set for providers reached over HTTP (Ollama) rather than a tool.
	HTTP bool `json:"http,omitempty"`

	// credFiles are the files (relative to the tool's home) that hold its sign-in. They are
	// copied into the vault after sign-in and back into a private home for every run.
	credFiles []string
	// setupFiles are written into the tool's home before sign-in and each run (settings that
	// make the tool keep its sign-in in a file NCC can copy, and skip first-run questions).
	setupFiles map[string]string
	// signInEnv is extra environment for the sign-in command.
	signInEnv []string
	// tokenRe finds a sign-in token in the sign-in output; tokenEnv carries it to the tool.
	tokenRe  *regexp.Regexp
	tokenEnv string
	// pasteAs is where a pasted value goes: "env:NAME" or "file:relative/path".
	pasteAs string
	// args builds the tool's arguments for one prompt; the prompt goes on stdin when
	// stdin is true, otherwise it is in the arguments.
	args  func(model string) []string
	stdin bool
	// parse turns the tool's stdout into the model's answer.
	parse func(out []byte) (string, error)
}

// Kinds lists the providers in display order.
var Kinds = []*Kind{
	{
		ID: KindClaude, Label: "Claude (Claude Code)", Account: "Claude Pro, Max, Team or Enterprise subscription",
		Binary: "claude", Install: "npm install -g @anthropic-ai/claude-code",
		SignIn:     []string{"setup-token"},
		SignInHelp: "NCC runs `claude setup-token`. Open the link it shows, sign in with your Claude account, and paste the code you get back here.",
		Paste:      "Or run `claude setup-token` on any computer and paste the token it prints (it starts with sk-ant-oat).",
		Note: "Anthropic allows a subscription to be used through its own, unmodified Claude Code tool for your own use; " +
			"it does not allow a subscription to serve other people. Only connect your own account, for your own network.",
		tokenRe:  regexp.MustCompile(`sk-ant-oat[0-9A-Za-z_\-]{20,}`),
		tokenEnv: "CLAUDE_CODE_OAUTH_TOKEN",
		pasteAs:  "env:CLAUDE_CODE_OAUTH_TOKEN",
		args: func(model string) []string {
			a := []string{"-p", "--output-format", "text", "--max-turns", "1", "--disallowedTools", "Bash,Edit,Write,MultiEdit,NotebookEdit,WebFetch,WebSearch,Task"}
			if model != "" {
				a = append(a, "--model", model)
			}
			return a
		},
		stdin: true,
		parse: plainText,
	},
	{
		ID: KindCopilot, Label: "GitHub Copilot (Copilot CLI)", Account: "GitHub account with a Copilot plan (Free, Pro, Business or Enterprise)",
		Binary: "copilot", Install: "npm install -g @github/copilot",
		SignIn:     []string{"login", "--device-code"},
		SignInHelp: "NCC runs `copilot login`. Open github.com/login/device, enter the code it shows and approve. If it asks whether to store the sign-in in a file, answer y: NCC moves it into the vault.",
		Paste:      "Or paste a GitHub sign-in token from `gh auth token` (it starts with gho_).",
		credFiles:  []string{".copilot/config.json"},
		pasteAs:    "env:COPILOT_GITHUB_TOKEN",
		args: func(model string) []string {
			a := []string{"-s", "--no-color", "--deny-tool", "shell", "--deny-tool", "write", "--deny-tool", "url"}
			if model != "" {
				a = append(a, "--model", model)
			}
			return append(a, "-p")
		},
		parse: plainText,
	},
	{
		ID: KindGemini, Label: "Google Gemini (Gemini CLI)", Account: "Google account (free Gemini Code Assist, Google AI Pro or Ultra)",
		Binary: "gemini", Install: "npm install -g @google/gemini-cli",
		SignIn:     []string{"-p", "Reply with the single word OK."},
		SignInHelp: "NCC runs Gemini CLI with Login with Google. Open the link it shows, sign in with your Google account, and paste the authorization code here.",
		Paste:      "Or sign in to Gemini CLI on any computer and paste the contents of ~/.gemini/oauth_creds.json.",
		credFiles:  []string{".gemini/oauth_creds.json", ".gemini/google_accounts.json"},
		setupFiles: map[string]string{".gemini/settings.json": `{"security":{"auth":{"selectedType":"oauth-personal"}}}`},
		signInEnv:  []string{"NO_BROWSER=true"},
		pasteAs:    "file:.gemini/oauth_creds.json",
		args: func(model string) []string {
			a := []string{"--output-format", "json"}
			if model != "" {
				a = append(a, "--model", model)
			}
			return append(a, "-p")
		},
		parse: geminiJSON,
	},
	{
		ID: KindCodex, Label: "ChatGPT (OpenAI Codex CLI)", Account: "ChatGPT Plus, Pro, Business or Enterprise subscription",
		Binary: "codex", Install: "npm install -g @openai/codex",
		SignIn:     []string{"login", "--device-auth"},
		SignInHelp: "NCC runs `codex login --device-auth`. Open the link it shows, sign in with your ChatGPT account and enter the code.",
		Paste:      "Or sign in to Codex on any computer and paste the contents of ~/.codex/auth.json.",
		credFiles:  []string{".codex/auth.json"},
		setupFiles: map[string]string{".codex/config.toml": "cli_auth_credentials_store = \"file\"\n"},
		pasteAs:    "file:.codex/auth.json",
		args: func(model string) []string {
			a := []string{"exec", "--sandbox", "read-only", "--skip-git-repo-check", "--ephemeral"}
			if model != "" {
				a = append(a, "--model", model)
			}
			return append(a, "-")
		},
		stdin: true,
		parse: plainText,
	},
	{
		ID: KindOllama, Label: "Local model (Ollama)", Account: "No account: a model running on your own server",
		HTTP: true, Install: "https://ollama.com/download, then `ollama pull qwen2.5:14b`",
		DefaultModel: "qwen2.5:14b",
		Note:         "Nothing leaves your network. Small models make weaker plans; NCC checks every step either way.",
	},
}

// KindByID returns a provider kind.
func KindByID(id string) (*Kind, error) {
	for _, k := range Kinds {
		if k.ID == id {
			return k, nil
		}
	}
	return nil, fmt.Errorf("no AI provider %q", id)
}

func plainText(out []byte) (string, error) {
	s := strings.TrimSpace(stripANSI(string(out)))
	if s == "" {
		return "", errors.New("the tool answered with nothing")
	}
	return s, nil
}

func geminiJSON(out []byte) (string, error) {
	var r struct {
		Response string `json:"response"`
		Error    *struct {
			Message string `json:"message"`
		} `json:"error"`
	}
	// the JSON object is the last thing printed; anything before it is log noise
	if i := bytes.IndexByte(out, '{'); i >= 0 {
		out = out[i:]
	}
	if err := json.Unmarshal(out, &r); err != nil {
		return plainText(out)
	}
	if r.Error != nil && r.Error.Message != "" {
		return "", errors.New(r.Error.Message)
	}
	return plainText([]byte(r.Response))
}

var ansiRe = regexp.MustCompile(`\x1b\[[0-9;?]*[ -/]*[@-~]|\x1b\][^\x07\x1b]*(\x07|\x1b\\)|\x1b[()][0-9A-Za-z]|\x1b[=>78]`)

// stripANSI removes terminal colour and cursor codes.
func stripANSI(s string) string {
	s = ansiRe.ReplaceAllString(s, "")
	return strings.Map(func(r rune) rune {
		if r == '\r' {
			return -1
		}
		if r < 0x20 && r != '\n' && r != '\t' {
			return -1
		}
		return r
	}, s)
}
