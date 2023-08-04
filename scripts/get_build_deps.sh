#!/bin/bash

# Add the package sources.
sudo apt-get update
sudo apt install -y irods-dev irods-externals-\* irods-icommands

# Install the packages.
dpkg -i irods43X_packages/irods-dev_4.3.0-1~focal_amd64.deb
dpkg -i irods43X_packages/irods-runtime_4.3.0-1~focal_amd64.deb
