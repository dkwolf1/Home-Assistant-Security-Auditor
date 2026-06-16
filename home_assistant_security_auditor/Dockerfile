FROM alpine:3.22

ARG BUILD_VERSION
ARG BUILD_ARCH

LABEL \
  io.hass.version="${BUILD_VERSION}" \
  io.hass.type="app" \
  io.hass.arch="${BUILD_ARCH}"

RUN apk add --no-cache python3 py3-pip openssl ca-certificates

COPY rootfs /
COPY run.sh /
RUN chmod a+x /run.sh

CMD ["/run.sh"]
