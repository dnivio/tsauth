# Dnivio Approval Service — Production Docker Image
# Multi-stage build for minimal attack surface

FROM golang:1.23-alpine AS builder

RUN apk add --no-cache git ca-certificates

WORKDIR /build

# Copy module files for dependency caching
COPY go.work go.work.sum ./
COPY contracts/go.mod contracts/go.sum contracts/
COPY service/go.mod service/go.sum service/
COPY sdk/go/go.mod sdk/go/go.sum sdk/go/

# Cache dependencies
RUN cd contracts && go mod download && \
    cd ../service && go mod download && \
    cd ../sdk/go && go mod download

# Copy source
COPY contracts/ contracts/
COPY service/ service/
COPY sdk/ sdk/

# Build with security flags
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
    go build -trimpath -buildvcs=false \
    -ldflags="-s -w -extldflags '-static'" \
    -o /dnivio-approval-service \
    ./service/cmd/approval-service/

# ─── Runtime Stage ────────────────────────────────────────────────────────

FROM gcr.io/distroless/static-debian12:nonroot

COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
COPY --from=builder /dnivio-approval-service /usr/local/bin/dnivio-approval-service
COPY service/migrations/ /etc/dnivio/migrations/

USER nonroot:nonroot

EXPOSE 8443 8444 9090

HEALTHCHECK --interval=15s --timeout=3s --start-period=5s --retries=3 \
    CMD ["/usr/local/bin/dnivio-approval-service", "-healthcheck"]

ENTRYPOINT ["/usr/local/bin/dnivio-approval-service"]
