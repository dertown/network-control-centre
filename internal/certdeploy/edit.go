package certdeploy

import (
	"bytes"
	"encoding/json"
	"strings"
)

// KV is one setting to write.
type KV struct{ Key, Value string }

// SetINI sets keys in one [section] of an INI-style file (Splunk .conf files), keeping
// everything else, including comments and the order of lines, as it was.
func SetINI(content []byte, section string, kvs []KV) []byte {
	nl := "\n"
	if bytes.Contains(content, []byte("\r\n")) {
		nl = "\r\n"
	}
	text := strings.ReplaceAll(string(content), "\r\n", "\n")
	lines := strings.Split(text, "\n")
	if len(lines) > 0 && lines[len(lines)-1] == "" {
		lines = lines[:len(lines)-1]
	}
	header := "[" + section + "]"
	start, end := -1, len(lines)
	for i, l := range lines {
		t := strings.TrimSpace(l)
		if strings.HasPrefix(t, "[") && strings.HasSuffix(t, "]") {
			if start >= 0 {
				end = i
				break
			}
			if t == header {
				start = i
			}
		}
	}
	done := map[string]bool{}
	if start >= 0 {
		for i := start + 1; i < end; i++ {
			t := strings.TrimSpace(lines[i])
			if t == "" || strings.HasPrefix(t, "#") || strings.HasPrefix(t, ";") {
				continue
			}
			k, _, ok := strings.Cut(t, "=")
			if !ok {
				continue
			}
			k = strings.TrimSpace(k)
			for _, kv := range kvs {
				if kv.Key == k && !done[k] {
					lines[i] = kv.Key + " = " + kv.Value
					done[k] = true
				}
			}
		}
	}
	var add []string
	for _, kv := range kvs {
		if !done[kv.Key] {
			add = append(add, kv.Key+" = "+kv.Value)
		}
	}
	if start < 0 {
		if len(lines) > 0 && strings.TrimSpace(lines[len(lines)-1]) != "" {
			lines = append(lines, "")
		}
		lines = append(lines, header)
		lines = append(lines, add...)
	} else if len(add) > 0 {
		// insert after the last non-blank line of the section
		at := end
		for at > start+1 && strings.TrimSpace(lines[at-1]) == "" {
			at--
		}
		rest := append([]string{}, lines[at:]...)
		lines = append(append(lines[:at], add...), rest...)
	}
	return []byte(strings.Join(lines, nl) + nl)
}

// SetJSON sets top-level keys in a JSON object file (FoundryVTT options.json), keeping the
// other keys and their order.
func SetJSON(content []byte, kvs []KV) ([]byte, error) {
	if len(bytes.TrimSpace(content)) == 0 {
		content = []byte("{}")
	}
	var obj map[string]json.RawMessage
	if err := json.Unmarshal(content, &obj); err != nil {
		return nil, err
	}
	order := keyOrder(content)
	for _, kv := range kvs {
		v, _ := json.Marshal(kv.Value)
		if _, ok := obj[kv.Key]; !ok {
			order = append(order, kv.Key)
		}
		obj[kv.Key] = v
	}
	var b bytes.Buffer
	b.WriteString("{\n")
	for i, k := range order {
		kb, _ := json.Marshal(k)
		var vb bytes.Buffer
		if err := json.Indent(&vb, obj[k], "  ", "  "); err != nil {
			return nil, err
		}
		b.WriteString("  " + string(kb) + ": " + vb.String())
		if i < len(order)-1 {
			b.WriteString(",")
		}
		b.WriteString("\n")
	}
	b.WriteString("}\n")
	return b.Bytes(), nil
}

func keyOrder(content []byte) []string {
	dec := json.NewDecoder(bytes.NewReader(content))
	var keys []string
	depth := 0
	expectKey := false
	for {
		tok, err := dec.Token()
		if err != nil {
			break
		}
		switch t := tok.(type) {
		case json.Delim:
			switch t {
			case '{', '[':
				depth++
				expectKey = t == '{' && depth == 1
			case '}', ']':
				depth--
				expectKey = depth == 1
			}
			continue
		case string:
			if depth == 1 && expectKey {
				keys = append(keys, t)
				expectKey = false
				continue
			}
		}
		if depth == 1 {
			expectKey = true
		}
	}
	return keys
}
