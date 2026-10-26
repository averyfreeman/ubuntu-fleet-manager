# The multi-platform manifest digest pins the Go builder image and its CA bundle.
FROM --platform=$BUILDPLATFORM docker.io/library/golang:1.27.3-bookworm@sha256:972b4110ba0f47539a975c31e52c64765e1ff19f2d74469ae4a595c6676e80a5 AS build

WORKDIR /src
ARG TARGETOS
ARG TARGETARCH
COPY go.mod go.sum ./
RUN go mod download
COPY cmd/ ./cmd/
COPY internal/ ./internal/
RUN CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} go build -trimpath -ldflags="-s -w" -o /out/ubuntu-fleet-manager ./cmd/ubuntu-fleet-manager

FROM scratch
COPY --from=build /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
COPY --from=build --chown=10001:10001 /out/ubuntu-fleet-manager /usr/local/bin/ubuntu-fleet-manager

USER 10001:10001
EXPOSE 8080
ENTRYPOINT ["/usr/local/bin/ubuntu-fleet-manager"]
