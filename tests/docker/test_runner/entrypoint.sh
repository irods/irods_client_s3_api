#! /bin/bash -ex

# Create an iRODS client environment for a rodsadmin user for use in the tests.
echo 'irods-catalog-provider
1247
rods
tempZone
rods' | iinit

cp ~/.irods/irods_environment.json ~/.irods/irods_environment.json.rods

# Remove the rodsadmin client environment so that the rodsuser client environment can be created.
iexit -f
rm ~/.irods/irods_environment.json

#### Give root an environment to connect to iRODS as Alice ####
#### Needed to set up testing.                             ####
echo 'irods-catalog-provider
1247
alice
tempZone
apass' | iinit

cp ~/.irods/irods_environment.json ~/.irods/irods_environment.json.alice

##### Configure mc client #### 
mc alias set s3-api-alice http://irods-s3-api:8080 s3_key2 s3_secret_key2
mc alias set s3-api-rods http://irods-s3-api:8080 s3_key1 s3_secret_key1

#### Run All Tests ####
cd /irods_client_s3_cpp/tests
export AWS_EC2_METADATA_DISABLED=true

if [[ -z $@ ]]; then
    # If no arguments were specified, run all of the tests via the unittest discovery feature.
    # The quotation marks are required here; otherwise, shell expansion will be applied and an error will occur.
    UNITTEST_ARGS=(discover -p "*_test.py" -v)
else
    UNITTEST_ARGS=($@)
fi

python3 -m unittest "${UNITTEST_ARGS[@]}"
