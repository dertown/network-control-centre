# syntax=docker/dockerfile:1
FROM node:22-alpine AS web
WORKDIR /src/web
COPY web/package.json web/package-lock.json ./
RUN npm ci
COPY web/ ./
RUN npm run build

FROM golang:1.26-alpine AS go
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
COPY --from=web /src/web/dist ./web/dist
RUN CGO_ENABLED=0 go build -trimpath -ldflags "-s -w" -o /out/ncc ./cmd/ncc

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=go /out/ncc /usr/local/bin/ncc
COPY deploy/config.docker.yaml /etc/ncc/config.yaml
ENV NCC_CONFIG=/etc/ncc/config.yaml
VOLUME ["/data"]
EXPOSE 8443
USER nonroot:nonroot
ENTRYPOINT ["/usr/local/bin/ncc"]
