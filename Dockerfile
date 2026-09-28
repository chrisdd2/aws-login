# Stage 1: Build the Go binary
FROM golang:1.27 AS builder

WORKDIR /app

COPY go.mod go.sum ./
RUN go mod download

COPY . .

# Build the Go binary
RUN CGO_ENABLED=0 go build -o main ./cmd/cli

# Stage 2: Minimal non-root runtime image with certificates
FROM gcr.io/distroless/static-debian12:nonroot

COPY --from=builder /app/main /main

USER nonroot:nonroot

ENTRYPOINT ["/main"]
