# syntax=docker/dockerfile:1.7

FROM golang:1.23-bookworm AS build

WORKDIR /app

COPY go.mod go.sum ./

RUN --mount=type=cache,target=/go/pkg/mod \
    go mod download

COPY . .

RUN --mount=type=cache,target=/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    CGO_ENABLED=1 GOOS=linux \
    go build -o /app/bin/server ./cmd/server

FROM debian:bookworm-slim

WORKDIR /app

RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        ca-certificates \
        wget \
        tini && \
    rm -rf /var/lib/apt/lists/*

RUN useradd --system --create-home --shell /usr/sbin/nologin appuser

COPY --from=build /app/bin/server ./server
COPY --from=build /app/migrations ./migrations

RUN chown -R appuser:appuser /app

USER appuser

EXPOSE 8081

ENTRYPOINT ["/usr/bin/tini", "--"]

CMD ["./server"]