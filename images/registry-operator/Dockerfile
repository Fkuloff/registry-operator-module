FROM golang:1.23-alpine AS builder
WORKDIR /src
COPY src/go.mod src/go.sum ./
RUN go mod download
COPY src/ ./
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -o /controller ./cmd/main.go

FROM alpine:3.20
RUN apk --no-cache add ca-certificates
COPY --from=builder /controller /controller
USER 65532:65532
ENTRYPOINT ["/controller"]
