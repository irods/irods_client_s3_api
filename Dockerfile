FROM ubuntu:20.04

SHELL [ "/bin/bash", "-c" ]

ENV DEBIAN_FRONTEND=noninteractive

# Make sure we're starting with an up-to-date image
RUN apt-get update && \
    apt-get upgrade -y && \
    apt-get autoremove -y --purge && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/* /tmp/*
# To mark all installed packages as manually installed:
#apt-mark showauto | xargs -r apt-mark manual

RUN apt-get update && \
    apt-get install -y \
        apt-transport-https \
        ccache \
        g++-10 \
        gcc \
        gcc-10 \
        git \
        gnupg \
        help2man \
        libbz2-dev \
        libcurl4-gnutls-dev \
        libfuse-dev \
        libjson-perl \
        libkrb5-dev \
        libpam0g-dev \
        libssl-dev \
        libxml2-dev \
        lsb-release \
        lsof \
        make \
        ninja-build \
        odbc-postgresql \
        postgresql \
        python3 \
        python3-dev \
        python3-pip \
        python3-distro \
        python3-jsonschema \
        python3-packaging \
        python3-psutil \
        python3-pyodbc \
        python3-requests \
        sudo \
        super \
        unixodbc-dev \
        wget \
        zlib1g-dev \
    && \
    pip3 --no-cache-dir install lief && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/* /tmp/*

RUN wget -qO - https://packages.irods.org/irods-signing-key.asc | apt-key add - && \
    echo "deb [arch=amd64] https://packages.irods.org/apt/ $(lsb_release -sc) main" | tee /etc/apt/sources.list.d/renci-irods.list && \
    wget -qO - https://core-dev.irods.org/irods-core-dev-signing-key.asc | apt-key add - && \
    echo "deb [arch=amd64] https://core-dev.irods.org/apt/ $(lsb_release -sc) main" | tee /etc/apt/sources.list.d/renci-irods-core-dev.list

RUN apt-get update && \
    apt-get install -y \
        'irods-externals*' \
    && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/* /tmp/*

RUN update-alternatives --install /usr/local/bin/gcc gcc /usr/bin/gcc-10 1 && \
    update-alternatives --install /usr/local/bin/g++ g++ /usr/bin/g++-10 1 && \
    hash -r

ARG cmake_path="/opt/irods-externals/cmake3.21.4-0/bin"
ENV PATH=${cmake_path}:$PATH

# This is where the dockerfile deviates from the one used by the development environment's docker
# file

# Build boost 1.81
RUN wget https://boostorg.jfrog.io/artifactory/main/release/1.81.0/source/boost_1_81_0.tar.bz2 && \
    tar xaf boost_1_81_0.tar.bz2

WORKDIR boost_1_81_0

RUN ./bootstrap.sh && \
    ./b2 -j 10 link=static

# Go back to the root
WORKDIR /

COPY scripts scripts

COPY ./irods-dev_4.3.0-1~focal_amd64.deb ./irods-runtime_4.3.0-1~focal_amd64.deb /irods43X_packages/

RUN bash scripts/get_build_deps.sh

RUN mkdir irods_s3_bridge

COPY . irods_s3_bridge

RUN bash scripts/build_bridge.sh

RUN dpkg -i /irods_s3_bridge/build/irods_s3_bridge_0.1.1-~focal_amd64.deb

RUN chmod +x scripts/run_bridge.sh

ENV LD_LIBRARY_PATH=/opt/irods-externals/clang13.0.0-0/lib:/boost-1.81.0/stage/lib:$LD_LIBRARY_PATH

RUN mkdir -p /root/.irods

ENTRYPOINT [ "scripts/run_bridge.sh" ]
