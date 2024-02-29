# build the builder
docker build -t irods-s3-api-builder -f irods_builder.Dockerfile .

# build a package for the s3-api
docker run -it --rm \
    -v `pwd`/../..:/s3_api_source:ro \
    -v `pwd`/../..:/packages_output \
    irods-s3-api-builder

# build the runner image
#docker build -t irods-s3-api-runner -f ../../irods_runner.Dockerfile ../..
