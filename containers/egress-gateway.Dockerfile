# syntax=docker/dockerfile:1.7
FROM golang:1.27.1-bookworm@sha256:69a7b9788769bec032d238959b61854e9ae87f57be9029ec04e9885fabf99195 AS build

WORKDIR /src/broker
COPY broker/go.mod ./
COPY broker/ ./

RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
    go build -trimpath -ldflags="-s -w" -o /out/awf-egress-gateway ./cmd/awf-egress-gateway \
    && mkdir -p /rootfs/etc/ssl/certs /rootfs/run/secrets /rootfs/tmp \
    && cp /etc/ssl/certs/ca-certificates.crt /rootfs/etc/ssl/certs/ca-certificates.crt

FROM scratch

LABEL org.opencontainers.image.title="Autonomous Worker Egress Gateway" \
      org.opencontainers.image.description="Attempt-scoped least-authority LLM egress gateway"

COPY --from=build /rootfs/ /
COPY --from=build /out/awf-egress-gateway /awf-egress-gateway

USER 65532:65532
ENTRYPOINT ["/awf-egress-gateway"]
