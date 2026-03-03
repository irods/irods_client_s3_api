#! /bin/bash -e

set -x

mkdir -p /_build_s3_api
cd /_build_s3_api
cmake -GNinja /s3_api_source
ninja package
cp ./*.deb /packages_output
