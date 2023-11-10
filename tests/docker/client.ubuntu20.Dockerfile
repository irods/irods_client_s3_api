FROM ubuntu:22.04

ADD start.client.ubuntu20.sh /
RUN chmod u+x /start.client.ubuntu20.sh

RUN mkdir /root/.aws
ADD aws_credentials /root/.aws/credentials

ARG DEBIAN_FRONTEND=noninteractive
ARG APT_KEY_DONT_WARN_ON_DANGEROUS_USAGE=true

#### Get and install iRODS repo ####
RUN apt-get update && apt-get install -y wget gnupg2 lsb-release
RUN wget -qO - https://packages.irods.org/irods-signing-key.asc | apt-key add -
RUN echo "deb [arch=amd64] https://packages.irods.org/apt/ $(lsb_release -sc) main" | tee /etc/apt/sources.list.d/renci-irods.list
RUN apt-get update

#### Install icommands - used to set up, validate and tear down tests. ####
RUN apt-get install -y irods-icommands

#### install basic packages ####
RUN apt-get install -y curl \
    unzip \
    python3 \
    python3-distro \
    python3-psutil \
    python3-jsonschema \
    python3-requests \
    python3-pip \
    python3-pyodbc

RUN pip3 install botocore boto3 minio

# install AWS CLI #

RUN curl "https://awscli.amazonaws.com/awscli-exe-linux-x86_64.zip" -o "awscliv2.zip"
RUN unzip awscliv2.zip
RUN ./aws/install

# install MinIO client (mc) #

RUN wget https://dl.min.io/client/mc/release/linux-amd64/mc
RUN chmod +x mc
RUN mv mc /usr/bin

ENTRYPOINT "/start.client.ubuntu20.sh"
