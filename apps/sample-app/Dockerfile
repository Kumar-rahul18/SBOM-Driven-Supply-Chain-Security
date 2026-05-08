# Stage 1: build
FROM golang:1.23-alpine AS builder

WORKDIR /app

# Cache dependency downloads separately from source changes
COPY go.mod ./
RUN go mod download

COPY *.go ./

ARG VERSION=dev
ARG COMMIT=unknown

RUN CGO_ENABLED=0 GOOS=linux go build \
    -ldflags="-w -s -X main.version=${VERSION} -X main.commit=${COMMIT}" \
    -o sample-app .

# Stage 2: minimal runtime — distroless has no shell, reduces attack surface
FROM gcr.io/distroless/static-debian12:nonroot

COPY --from=builder /app/sample-app /sample-app

EXPOSE 8080

ENTRYPOINT ["/sample-app"]
