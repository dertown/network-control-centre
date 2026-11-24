.PHONY: all web build test demo licenses

all: build

web:
	cd web && npm ci && npm run build

build: web
	CGO_ENABLED=0 go build -trimpath -ldflags "-s -w -X main.version=$$(git describe --tags --always --dirty 2>/dev/null || echo dev)" -o bin/ncc ./cmd/ncc

test:
	go vet ./...
	go test ./...
	cd web && npm run typecheck

# Regenerate third_party_licenses.json (shown on the About page) after changing Go or npm
# dependencies. go test fails while it is out of date.
licenses:
	cd web && npm ci
	go mod download
	go run ./cmd/ncc-licenses

# Run NCC against a pretend UniFi console and PowerDNS server (see README).
demo: build
	go build -o bin/ncc-mock ./cmd/ncc-mock
	./bin/ncc-mock & ./bin/ncc -config config.example.yaml
