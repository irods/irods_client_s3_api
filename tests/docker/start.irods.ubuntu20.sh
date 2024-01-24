#! /bin/bash

# Start the Postgres database.
service postgresql start
counter=0
until pg_isready -q
do
    sleep 1
    ((counter += 1))
done
echo Postgres took approximately $counter seconds to fully start ...

#### Set up iRODS ####
/var/lib/irods/scripts/setup_irods.py < /var/lib/irods/packaging/localhost_setup_postgres.input

#### Start iRODS ####
service irods start

#### Create user1 and alice in iRODS ####
sudo -H -u irods bash -c "iadmin mkuser user1 rodsuser"
sudo -H -u irods bash -c "iadmin moduser user1 password user1"
sudo -H -u irods bash -c "iadmin mkuser alice rodsuser"
sudo -H -u irods bash -c "iadmin moduser alice password apass"

#### Create newResc resource in iRODS ####
sudo -H -u irods bash -c "iadmin mkresc newResc unixfilesystem `hostname`:/tmp/newRescVault"

#### Give root an environment to connect to iRODS ####
echo 'localhost
1247
rods
tempZone
rods' | iinit

#### Add user1 and alice as a local user for testing ####
useradd user1 -m
useradd alice -m

#### Give alice an environment to connect to iRODS ####
sudo -H -u alice bash -c "
echo 'localhost
1247
alice
tempZone
apass' | iinit"

#### Create collections for Alice's buckets ####
sudo -H -u alice bash -c "imkdir alice-bucket"
sudo -H -u alice bash -c "imkdir alice-bucket2"

mkdir -p /projects/irods/vsphere-testing/externals/

cd /

#### Keep container running ####
tail -f /dev/null
