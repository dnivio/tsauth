# Dnivio Enforcement Daemon — Production Docker Image
FROM golang:1.23-alpine AS builder

RUN apk add --no-cache git ca-certificates

WORKDIR /build
COPY go.work go.work.sum ./
COPY contracts/go.mod contracts/go.sum contracts/
COPY daemon/go.mod daemon/go.sum daemon/ 2>/dev/null || true

RUN cd contracts && go mod download

COPY contracts/ contracts/
COPY daemon/ daemon/

RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
    go build -trimpath -buildvcs=false \
    -ldflags="-s -w -extldflags '-static'" \
    -o /dnv-daemon \
    ./daemon/cmd/dnv-daemon/

FROM gcr.io/distroless/static-debian12:nonroot

COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
COPY --from=builder /dnv-daemon /usr/local/bin/dnv-daemon

USER nonroot:nonroot

EXPOSE 8443

ENTRYPOINT ["/usr/local/bin/dnv-daemon"]
