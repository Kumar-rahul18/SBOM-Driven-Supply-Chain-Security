# Stage 1: build the Go binary
FROM golang:1.23-alpine AS builder

WORKDIR /app

COPY go.mod ./
# go mod tidy generates go.sum inside the build environment
RUN go mod tidy

COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-w -s" -o sbom-ingester .

# Stage 2: fetch the grype binary
FROM alpine:3.19 AS grype-fetcher

ARG GRYPE_VERSION=0.80.0
RUN apk add --no-cache curl && \
    curl -sSfL \
      "https://github.com/anchore/grype/releases/download/v${GRYPE_VERSION}/grype_${GRYPE_VERSION}_linux_amd64.tar.gz" \
    | tar -xz -C /usr/local/bin grype

# Stage 3: minimal runtime image
FROM alpine:3.19

RUN apk add --no-cache ca-certificates

COPY --from=builder      /app/sbom-ingester        /sbom-ingester
COPY --from=grype-fetcher /usr/local/bin/grype      /usr/local/bin/grype

# Grype caches its vulnerability DB here; mount a volume to persist between restarts
ENV GRYPE_DB_CACHE_DIR=/grype-db

EXPOSE 8080

ENTRYPOINT ["/sbom-ingester"]
