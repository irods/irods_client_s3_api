#!/usr/bin/env bash
# Configure

pushd irods_s3_bridge || exit
mkdir build
cd build
cmake ..
make package -j
