ARG APP_WORKDIR="/app"
ARG APP_SOURCE_ARCHIVE="./app.tar.gz"
ARG CERTIFICATE_DIR="certs"
ARG FROM_IMAGE="ubuntu:latest"

FROM ${FROM_IMAGE}

ARG APP_WORKDIR
ARG APP_SOURCE_ARCHIVE
ARG CERTIFICATE_DIR

LABEL org.opencontainers.image.source="https://github.com/polarlabs/kodiak-web-server"
LABEL org.opencontainers.image.description="Kodiak's web server."
LABEL org.opencontainers.image.licenses="AGPL-3.0-only"

COPY ${APP_SOURCE_ARCHIVE} .
RUN tar -xzf ${APP_SOURCE_ARCHIVE}

WORKDIR ${APP_WORKDIR}

VOLUME ${APP_WORKDIR}/${CERTIFICATE_DIR}

EXPOSE 8080
EXPOSE 8443

CMD ["./kodiak-web-server"]
