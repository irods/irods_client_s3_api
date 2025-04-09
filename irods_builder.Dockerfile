FROM ubuntu:22.04

SHELL ["/bin/bash", "-c"]
ENV DEBIAN_FRONTEND=noninteractive

# Re-enable apt caching for RUN --mount
RUN rm -f /etc/apt/apt.conf.d/docker-clean && \
    echo 'Binary::apt::APT::Keep-Downloaded-Packages "true";' > /etc/apt/apt.conf.d/keep-cache

# Make sure we're starting with an up-to-date image
RUN --mount=type=cache,target=/var/cache/apt,sharing=locked \
    --mount=type=cache,target=/var/lib/apt,sharing=locked \
    apt-get update && \
    apt-get upgrade -y && \
    apt-get autoremove -y --purge && \
    rm -rf /tmp/*
# To mark all installed packages as manually installed:
#apt-mark showauto | xargs -r apt-mark manual

RUN --mount=type=cache,target=/var/cache/apt,sharing=locked \
    --mount=type=cache,target=/var/lib/apt,sharing=locked \
    apt-get update && \
    apt-get install -y \
        git \
        gnupg \
        lsb-release \
        wget \
    && \
    rm -rf /tmp/*

RUN wget -qO - https://packages.irods.org/irods-signing-key.asc | apt-key add - && \
    echo "deb [arch=amd64] https://packages.irods.org/apt/ $(lsb_release -sc) main" | tee /etc/apt/sources.list.d/renci-irods.list

ARG irods_version=4.3.1-0~jammy
RUN --mount=type=cache,target=/var/cache/apt,sharing=locked \
    --mount=type=cache,target=/var/lib/apt,sharing=locked \
    apt-get update && \
    apt-get install -y \
        apt-transport-https \
        flex \
        bison \
        g++-11 \
        gcc-11 \
        cmake \
        irods-dev=${irods_version} \
        irods-runtime=${irods_version} \
        irods-externals-clang13.0.0-0 \
        irods-externals-fmt8.1.1-0 \
        irods-externals-json3.10.4-0 \
        irods-externals-jwt-cpp0.6.99.0-0 \
        irods-externals-nanodbc2.13.0-1 \
        irods-externals-spdlog1.9.2-1 \
        libcurl4-gnutls-dev \
        libssl-dev \
        libssl3 \
        ninja-build \
    && \
    rm -rf /tmp/*

COPY --chmod=755 build_packages.sh /
ENTRYPOINT ["/build_packages.sh"]
