FROM docker.io/library/golang:1.27.3-bookworm AS build

WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY cmd/ ./cmd/
COPY internal/ ./internal/
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w" -o /out/ubuntu-fleet-manager ./cmd/ubuntu-fleet-manager

FROM docker.io/library/debian:bookworm-slim

RUN apt-get update \
    && apt-get install --no-install-recommends --yes ca-certificates curl \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd --system --gid 10001 ubuntu-fleet-manager \
    && useradd --system --uid 10001 --gid 10001 --home-dir /nonexistent --shell /usr/sbin/nologin ubuntu-fleet-manager

COPY --from=build /out/ubuntu-fleet-manager /usr/local/bin/ubuntu-fleet-manager

USER 10001:10001
EXPOSE 8080
ENTRYPOINT ["/usr/local/bin/ubuntu-fleet-manager"]
