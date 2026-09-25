# syntax=docker/dockerfile:1.7
FROM --platform=$BUILDPLATFORM golang:1.27.1-alpine AS build

# Without a release VERSION the build stamps the VCS revision, which needs git.
RUN apk add --no-cache git

WORKDIR /src
COPY go.mod go.sum ./
RUN --mount=type=cache,target=/go/pkg/mod \
    go mod download

ARG TARGETOS TARGETARCH
ARG VERSION=""
COPY . .
RUN --mount=type=cache,target=/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH \
    go build -trimpath -ldflags "-s -w -X main.version=${VERSION}" -o /out/vaultwarden-agentic-mcp ./cmd/vaultwarden-agentic-mcp

FROM gcr.io/distroless/static-debian12:nonroot

COPY --from=build /out/vaultwarden-agentic-mcp /usr/local/bin/vaultwarden-agentic-mcp

USER nonroot:nonroot
EXPOSE 8080

# No shell and no curl in the image, so the binary probes itself.
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD ["/usr/local/bin/vaultwarden-agentic-mcp", "healthcheck"]

ENTRYPOINT ["/usr/local/bin/vaultwarden-agentic-mcp"]
