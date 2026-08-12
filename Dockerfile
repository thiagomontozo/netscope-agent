# syntax=docker/dockerfile:1
FROM golang:1.26-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY cmd ./cmd
COPY internal ./internal
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/netscope-agent ./cmd/netscope-agent

FROM alpine:3.23
RUN addgroup -S netscope && adduser -S -G netscope -h /var/lib/netscope-agent netscope \
    && apk add --no-cache ca-certificates
COPY --from=build /out/netscope-agent /usr/local/bin/netscope-agent
RUN install -d -o netscope -g netscope -m 0700 /var/lib/netscope-agent
USER netscope:netscope
ENV NETSCOPE_DATA_DIR=/var/lib/netscope-agent
ENTRYPOINT ["/usr/local/bin/netscope-agent"]
