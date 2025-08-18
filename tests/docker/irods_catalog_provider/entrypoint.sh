#! /bin/bash

# Wait for the Postgres database.
catalog_db_hostname=irods-catalog
counter=0
echo "Waiting for iRODS catalog database to be ready"
until pg_isready -h ${catalog_db_hostname} -d ICAT -U irods -q
do
    sleep 1
    ((counter += 1))
done
echo Postgres took approximately $counter seconds to fully start ...

#### Set up iRODS ####
setup_input_file=/irods_setup.input
if [ -f ${setup_input_file} ]; then
    /var/lib/irods/scripts/setup_irods.py < ${setup_input_file}

    #### Start iRODS ####
    su irods -c 'bash -c "/var/lib/irods/irodsctl start"'

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

    rm ${setup_input_file}

    su irods -c 'bash -c "/var/lib/irods/irodsctl stop"'
fi

cd /usr/sbin
su irods -c 'bash -c "./irodsServer -u"'
