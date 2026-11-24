// Package ncc carries the project's legal files (LICENSE, NOTICE and the generated
// third_party_licenses.json) into the binary, so the About page serves the files in this
// repository rather than a copy of them. It lives at the repository root because go:embed
// can't reach files above the embedding package.
package ncc

import _ "embed"

// License is the text of LICENSE (Apache License 2.0).
//
//go:embed LICENSE
var License string

// Notice is the text of NOTICE.
//
//go:embed NOTICE
var Notice string

// ThirdPartyJSON lists the third-party Go modules and npm packages built into NCC with their
// licence files. Regenerate it with make licenses (go run ./cmd/ncc-licenses).
//
//go:embed third_party_licenses.json
var ThirdPartyJSON []byte
