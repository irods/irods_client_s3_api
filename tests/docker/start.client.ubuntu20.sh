#! /bin/bash

#### Give root an environment to connect to iRODS as Alice ####
#### Needed to set up testing.                             ####
echo 'irods
1247
alice
tempZone
apass' | iinit

##### Configure mc client #### 
mc alias set s3-api-alice http://s3-api:8080 s3_key2 s3_secret_key2
mc alias set s3-api-rods http://s3-api:8080 s3_key1 s3_secret_key1

#### Run All Tests ####
cd /irods_client_s3_cpp/tests
python3 run_all_tests.py
