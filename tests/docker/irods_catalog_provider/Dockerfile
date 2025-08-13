FROM ubuntu:22.04

ARG DEBIAN_FRONTEND=noninteractive
ARG APT_KEY_DONT_WARN_ON_DANGEROUS_USAGE=true

RUN apt-get update && \
    apt-get install -y \
        ca-certificates \
        lsb-release \
        gnupg \
        wget \
    && \
    rm -rf /tmp/*

RUN mkdir -p /etc/apt/keyrings && \
    wget -qO - https://packages.irods.org/irods-signing-key.asc | \
        gpg \
            --no-options \
            --no-default-keyring \
            --no-auto-check-trustdb \
            --homedir /dev/null \
            --no-keyring \
            --import-options import-export \
            --output /etc/apt/keyrings/renci-irods-archive-keyring.pgp \
            --import \
        && \
    echo "deb [signed-by=/etc/apt/keyrings/renci-irods-archive-keyring.pgp arch=amd64] https://packages.irods.org/apt/ $(lsb_release -sc) main" | \
        tee /etc/apt/sources.list.d/renci-irods.list

RUN apt-get update && \
    apt-get install -y \
        libcurl4-gnutls-dev \
        python3 \
        python3-distro \
        python3-jsonschema \
        python3-pip \
        python3-psutil \
        python3-requests \
        rsyslog \
        unixodbc \
    && \
    rm -rf /tmp/*

ARG irods_version=4.3.1
ARG irods_package_version_suffix=-0~jammy
ARG irods_package_version=${irods_version}${irods_package_version_suffix}

RUN apt-get update && \
    apt-get install -y \
        irods-database-plugin-postgres=${irods_package_version} \
        irods-runtime=${irods_package_version} \
        irods-server=${irods_package_version} \
        irods-icommands=${irods_package_version} \
    && \
    rm -rf /tmp/*

WORKDIR /
COPY irods_setup.input .
COPY --chmod=755 entrypoint.sh .
ENTRYPOINT "./entrypoint.sh"
