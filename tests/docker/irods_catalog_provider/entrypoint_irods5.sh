#! /bin/bash -e

catalog_db_hostname=irods-catalog

echo "Waiting for iRODS catalog database to be ready"

until pg_isready -h ${catalog_db_hostname} -d ICAT -U irods -q
do
    sleep 1
done

echo "iRODS catalog database is ready"

unattended_install_file=/unattended_install.json
if [ -f ${unattended_install_file} ]; then
    echo "Running iRODS setup"
    sed -i "s/THE_HOSTNAME/${HOSTNAME}/g" ${unattended_install_file}

    # unattended workaround for 5.0.1
    sed -i '/^\s*setup_server_host(irods_config)/s/^/    /' /var/lib/irods/scripts/setup_irods.py
    sed -i '/^\s*setup_server_host(irods_config)/{h;d;};/^\s*json_configuration_dict = None/{G;}' /var/lib/irods/scripts/setup_irods.py

    python3 /var/lib/irods/scripts/setup_irods.py --json_configuration_file ${unattended_install_file}
    rm ${unattended_install_file}

    echo "Initializing server"
    su - irods -c 'irodsServer -d'

    # wait for server to respond
    until su irods -c 'ils'
    do
        sleep 1
    done

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

    # kill server and wait for it to stop
    kill $(cat /var/run/irods/irods-server.pid)
    while ps -p $(cat /var/run/irods/irods-server.pid) ; do
        sleep 1
    done
fi

echo "Starting server"
cd /usr/sbin
su irods -c 'irodsServer --stdout'
