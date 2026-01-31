# Debug Proxy Container
# A minimal container that runs the CDP debug proxy for secure debugging

FROM golang:1.22-alpine AS builder

WORKDIR /build

# Copy go mod files
COPY go.mod go.sum ./
RUN go mod download

# Copy source code
COPY . .

# Build the debug proxy binary
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -o /debugproxy ./cmd/debugproxy

# Final minimal image
FROM alpine:3.19

# Install ca-certificates for HTTPS (if needed)
RUN apk add --no-cache ca-certificates

# Copy the binary
COPY --from=builder /debugproxy /usr/local/bin/debugproxy

# Create non-root user
RUN adduser -D -u 1000 proxy
USER proxy

# Expose the proxy port
EXPOSE 9229

# Health check
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD wget -q --spider http://localhost:9229/stats || exit 1

# Default command
ENTRYPOINT ["/usr/local/bin/debugproxy"]
CMD ["-listen", ":9229", "-filter", "filtered", "-audit"]
