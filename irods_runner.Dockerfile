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
        gnupg \
        lsb-release \
        python3 \
        python3-pip \
        wget \
    && \
    rm -rf /tmp/* && \
    python3 -m pip install jsonschema

RUN wget -qO - https://packages.irods.org/irods-signing-key.asc | apt-key add - && \
    echo "deb [arch=amd64] https://packages.irods.org/apt/ $(lsb_release -sc) main" | tee /etc/apt/sources.list.d/renci-irods.list

ARG irods_version=4.3.1-0~jammy
RUN --mount=type=cache,target=/var/cache/apt,sharing=locked \
    --mount=type=cache,target=/var/lib/apt,sharing=locked \
    apt-get update && \
    apt-get install -y \
        apt-transport-https \
        g++-11 \
        gcc \
        gcc-11 \
        irods-runtime=${irods_version} \
        irods-externals-clang-runtime13.0.0-0 \
    && \
    rm -rf /tmp/*

COPY ./*.deb /

RUN --mount=type=cache,target=/var/cache/apt,sharing=locked \
    --mount=type=cache,target=/var/lib/apt,sharing=locked \
    apt-get update && \
    apt-get install -y /*.deb && \
    rm -rf /tmp/*

# Create a dedicated user for running the S3 API.
ARG s3_api_user=irods_s3_api
RUN adduser --disabled-password ${s3_api_user}
USER ${s3_api_user}

# Remove once the environment_properties::capture provides an option for
# not printing error messages when irods_environment.json does not exist.
RUN mkdir /home/${s3_api_user}/.irods && \
    echo '{}' > /home/${s3_api_user}/.irods/irods_environment.json

ENTRYPOINT ["irods_s3_api", "/config.json"]
