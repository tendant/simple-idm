FROM golang:1.23-alpine

RUN apk add --no-cache git && \
    go install github.com/pressly/goose/v3/cmd/goose@latest

# Ensure Go binaries (like goose) are in PATH
ENV PATH="/go/bin:$PATH"

WORKDIR /app

# ENTRYPOINT ["goose"]
