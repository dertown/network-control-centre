// Command ncc-licenses regenerates third_party_licenses.json: every Go module linked into
// cmd/ncc (plus the Go standard library) and every npm package bundled into the web UI, with
// its licence and the licence and notice files it ships. The About page shows this list.
//
// Run it from the repository root after changing dependencies (make licenses). It needs the
// Go modules downloaded and web/node_modules installed (npm ci).
package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strings"
)

// Package is one third-party component and the licence files it ships.
type Package struct {
	Name      string `json:"name"`
	Version   string `json:"version"`
	Ecosystem string `json:"ecosystem"` // go or npm
	License   string `json:"license"`   // SPDX identifier, or "see files"
	URL       string `json:"url,omitempty"`
	Files     []File `json:"files"`
}

// File is one licence or notice file, verbatim.
type File struct {
	Name string `json:"name"`
	Text string `json:"text"`
}

const out = "third_party_licenses.json"

func main() {
	var pkgs []Package
	goPkgs, err := goModules()
	if err != nil {
		fail(err)
	}
	pkgs = append(pkgs, goPkgs...)
	npmPkgs, err := npmPackages("web")
	if err != nil {
		fail(err)
	}
	pkgs = append(pkgs, npmPkgs...)
	sort.Slice(pkgs, func(i, j int) bool {
		if pkgs[i].Ecosystem != pkgs[j].Ecosystem {
			return pkgs[i].Ecosystem < pkgs[j].Ecosystem
		}
		return pkgs[i].Name < pkgs[j].Name
	})
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetIndent("", "  ")
	enc.SetEscapeHTML(false)
	if err := enc.Encode(pkgs); err != nil {
		fail(err)
	}
	if err := os.WriteFile(out, buf.Bytes(), 0o644); err != nil {
		fail(err)
	}
	fmt.Printf("wrote %s: %d packages\n", out, len(pkgs))
}

func fail(err error) {
	fmt.Fprintln(os.Stderr, "ncc-licenses:", err)
	os.Exit(1)
}

// goModules lists the modules whose packages are linked into cmd/ncc.
func goModules() ([]Package, error) {
	cmd := exec.Command("go", "list", "-deps", "-f", "{{with .Module}}{{if not .Main}}{{.Path}}\t{{.Version}}\t{{.Dir}}{{end}}{{end}}", "./cmd/ncc")
	cmd.Stderr = os.Stderr
	raw, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("go list: %w", err)
	}
	seen := map[string]bool{}
	var pkgs []Package
	sc := bufio.NewScanner(bytes.NewReader(raw))
	for sc.Scan() {
		f := strings.Split(sc.Text(), "\t")
		if len(f) != 3 || seen[f[0]] {
			continue
		}
		seen[f[0]] = true
		if f[2] == "" {
			return nil, fmt.Errorf("module %s is not downloaded (run go mod download)", f[0])
		}
		files, err := licenseFiles(f[2])
		if err != nil {
			return nil, err
		}
		if len(files) == 0 {
			return nil, fmt.Errorf("module %s has no licence file", f[0])
		}
		pkgs = append(pkgs, Package{Name: f[0], Version: f[1], Ecosystem: "go", License: classify(files), URL: "https://pkg.go.dev/" + f[0], Files: files})
	}
	// the standard library is linked in too
	goroot := runtime.GOROOT()
	if out, err := exec.Command("go", "env", "GOROOT").Output(); err == nil {
		goroot = strings.TrimSpace(string(out))
	}
	ver, _ := exec.Command("go", "env", "GOVERSION").Output()
	text, err := os.ReadFile(filepath.Join(goroot, "LICENSE"))
	if err != nil {
		return nil, fmt.Errorf("Go standard library licence: %w", err)
	}
	files := []File{{Name: "LICENSE", Text: string(text)}}
	pkgs = append(pkgs, Package{Name: "Go standard library", Version: strings.TrimSpace(string(ver)), Ecosystem: "go", License: classify(files), URL: "https://go.dev/", Files: files})
	return pkgs, nil
}

// npmPackages lists the packages bundled into the built UI: the non-dev entries of
// package-lock.json (dev tools such as Vite and TypeScript don't ship).
func npmPackages(dir string) ([]Package, error) {
	raw, err := os.ReadFile(filepath.Join(dir, "package-lock.json"))
	if err != nil {
		return nil, err
	}
	var lock struct {
		Packages map[string]struct {
			Version string `json:"version"`
			License string `json:"license"`
			Dev     bool   `json:"dev"`
		} `json:"packages"`
	}
	if err := json.Unmarshal(raw, &lock); err != nil {
		return nil, fmt.Errorf("package-lock.json: %w", err)
	}
	var pkgs []Package
	for path, p := range lock.Packages {
		if path == "" || p.Dev {
			continue
		}
		name := path[strings.LastIndex(path, "node_modules/")+len("node_modules/"):]
		files, err := licenseFiles(filepath.Join(dir, path))
		if err != nil {
			return nil, fmt.Errorf("%s: %w (run npm ci in web)", name, err)
		}
		if len(files) == 0 {
			return nil, fmt.Errorf("npm package %s has no licence file", name)
		}
		lic := p.License
		if lic == "" {
			lic = classify(files)
		}
		pkgs = append(pkgs, Package{Name: name, Version: p.Version, Ecosystem: "npm", License: lic, URL: "https://www.npmjs.com/package/" + name, Files: files})
	}
	return pkgs, nil
}

var licenseName = regexp.MustCompile(`(?i)^(licen[cs]e|copying|notice|unlicense)([-._].*)?$`)

// licenseFiles reads the licence and notice files at the top of a module or package.
func licenseFiles(dir string) ([]File, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	var files []File
	for _, e := range entries {
		if !e.Type().IsRegular() || !licenseName.MatchString(e.Name()) {
			continue
		}
		switch strings.ToLower(filepath.Ext(e.Name())) {
		case "", ".txt", ".md":
		default:
			continue // e.g. cytoscape's license-update.js
		}
		b, err := os.ReadFile(filepath.Join(dir, e.Name()))
		if err != nil {
			return nil, err
		}
		files = append(files, File{Name: e.Name(), Text: strings.ReplaceAll(string(b), "\r\n", "\n")})
	}
	return files, nil
}

// classify names the licence of a module from its main licence file's text.
func classify(files []File) string {
	for _, f := range files {
		n := strings.ToLower(f.Name)
		if strings.Contains(n, "notice") || strings.Contains(n, "3rd-party") || strings.Contains(n, "third") {
			continue
		}
		t := strings.Join(strings.Fields(strings.ToLower(f.Text)), " ")
		switch {
		case strings.Contains(t, "apache license") && strings.Contains(t, "version 2.0"):
			if strings.Contains(t, "permission is hereby granted, free of charge") {
				return "MIT AND Apache-2.0"
			}
			return "Apache-2.0"
		case strings.Contains(t, "mozilla public license") && strings.Contains(t, "2.0"):
			return "MPL-2.0"
		case strings.Contains(t, "permission is hereby granted, free of charge"):
			return "MIT"
		case strings.Contains(t, "permission to use, copy, modify, and/or distribute"), strings.Contains(t, "permission to use, copy, modify, and distribute this software for any purpose with or without fee"):
			return "ISC"
		case strings.Contains(t, "redistribution and use in source and binary forms"):
			if strings.Contains(t, "neither the name") || strings.Contains(t, "names of its contributors") {
				return "BSD-3-Clause"
			}
			return "BSD-2-Clause"
		}
	}
	return "see files"
}
