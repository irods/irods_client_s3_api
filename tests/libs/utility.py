import datetime
import json
import os
import random
import subprocess as sp
from typing import Optional

from . import execute

def touch_file(filename, access_level=None, user='rods', contents: Optional[bytes] = None):
    if contents is None:
        sp.run(["itouch", f"{filename}"], check=True)
    else:
        iput_com = sp.Popen(
            ['iput', '-', f"{filename}"], stdin=sp.PIPE, shell=False)
        iput_com.stdin.write(contents)
        iput_com.stdin.close()
    if access_level is not None:
        set_access(filename, access_level, user)

def make_local_file(f_name, f_size, contents='zero', block_size_in_bytes=1000):
    if contents not in ['arbitrary', 'random', 'zero']:
        raise AssertionError
    if contents == 'arbitrary' or f_size == 0:
        execute.execute_command(['truncate', '-s', str(f_size), f_name])
        return

    source = {'zero': '/dev/zero',
              'random': '/dev/urandom'}[contents]

    # Use integer division as dd's count argument must be an integer
    count = f_size // block_size_in_bytes
    if count > 0:
        execute.execute_command(['dd', 'if='+source, 'of='+f_name, 'count='+str(count), 'bs='+str(block_size_in_bytes)])
        leftover_size = f_size % block_size_in_bytes
        if leftover_size > 0:
            execute.execute_command(['dd', 'if='+source, 'of='+f_name, 'count=1', 'bs='+str(leftover_size), 'oflag=append', 'conv=notrunc'])
    else:
        execute.execute_command(['dd', 'if='+source, 'of='+f_name, 'count=1', 'bs='+str(f_size)])

def make_arbitrary_file(f_name, f_size, buffer_size=32*1024*1024):
    # do not care about true randomness
    # note that this method does not use up system entropy
    random.seed(5)
    bytes_written = 0
    buffer = buffer_size * [0x78]       # 'x' - bytearray() below appears to require int instead
                                        #       of char which was valid in python2
    with open(f_name, "wb") as out:

        while bytes_written < f_size:

            if f_size - bytes_written < buffer_size:
                to_write = f_size - bytes_written
                buffer = to_write * [0x78]  # 'x'
            else:
                to_write = buffer_size

            current_char = random.randrange(256)

            # just write some random byte each 1024 chars
            for i in range(0, to_write, 1024):
                buffer[i] = current_char
                current_char = random.randrange(256)
            buffer[len(buffer)-1] = random.randrange(256)

            out.write(bytearray(buffer))

            bytes_written += to_write


def set_access(filename, access_level, user, recursive: bool = False):
    sp.run(["ichmod"]+(['-r'] if recursive else []) +
           #["-M", access_level, user, filename])
           [access_level, user, filename])


def read_file(client, bucket, key):
    print(key)
    return client.get_object(Bucket=bucket, Key=key)


def mkdir(dirname, access_level=None):
    sp.run(['imkdir', '-p', dirname], check=True)
    if access_level is not None:
        set_access(dirname, access_level, recursive=True)

def remove_file(client, filename, recursive: bool = False):
    """
    Remove a file or directory
    """
    sp.run(['irm'] + (["-r"] if recursive else []) +
           [f'{filename}{"/" if recursive else ""}'])

def execute_irods_command_as_user(cmd, host, port, username, zonename, password, original_password):
    irods_environment_file = 'irods_environment_' + datetime.datetime.utcnow().strftime('%Y-%m-%dZ%H:%M:%S') + '.json'
    os.environ['IRODS_ENVIRONMENT_FILE'] =  irods_environment_file
    print(os.environ.get('IRODS_ENVIRONMENT_FILE'))
    env_file_dict = { 
            'irods_host': host,
            'irods_port': port,
            'irods_user_name': username,
            'irods_zone_name': zonename
        }
    print(env_file_dict)
    json_object = json.dumps(env_file_dict, indent=4)
    print(json_object)
    with open(irods_environment_file, 'w') as outfile:
            outfile.write(json_object)
    print('before iinit')
    execute.execute_command('iinit', input=password)
    print('after iinit')

    execute.execute_command(cmd)

    print(os.environ.get('IRODS_ENVIRONMENT_FILE'))
    os.environ.pop('IRODS_ENVIRONMENT_FILE')
    execute.execute_command(f'rm {irods_environment_file}')
    print('before iinit')
    execute.execute_command('iinit', input=original_password)
    print('after iinit')
