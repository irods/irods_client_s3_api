import unittest
import boto3
from boto3.s3.transfer import TransferConfig
import inspect
import os
from libs.execute import *
from libs.command import *
from libs.utility import *
from datetime import datetime
from minio import Minio

class GetObject_Test(TestCase):

    bucket_irods_path = '/tempZone/home/alice/alice-bucket'
    bucket_name = 'alice-bucket'
    key = 's3_key2'
    secret_key = 's3_secret_key2'
    s3_api_host_port = 's3-api:8080'
    s3_api_url = f'http://{s3_api_host_port}'

    def __init__(self, *args, **kwargs):
        super(GetObject_Test, self).__init__(*args, **kwargs)

    def setUp(self):

        self.boto3_client = boto3.client('s3',
                                          use_ssl=False,
                                          endpoint_url=self.s3_api_url,
                                          aws_access_key_id=self.key,
                                          aws_secret_access_key=self.secret_key)

        self.minio_client = Minio(self.s3_api_host_port,
                                  access_key=self.key,
                                  secret_key=self.secret_key,
                                  secure=False)

    def tearDown(self):
        self.boto3_client.close()

    def test_botocore_get_in_bucket_root_small_file(self):

        put_filename = inspect.currentframe().f_code.co_name 
        get_filename = f"{put_filename}.get"

        try:

            make_arbitrary_file(put_filename, 100*1024)
            assert_command(f'iput {put_filename} {self.bucket_irods_path}/{put_filename}')
            with open(get_filename, 'wb') as f:
                    self.boto3_client.download_fileobj(self.bucket_name, put_filename, f)
            assert_command(f'diff {put_filename} {get_filename}')

        finally:
            os.remove(put_filename)
            os.remove(get_filename)
            assert_command(f'irm -f {self.bucket_irods_path}/{put_filename}')

    def test_botocore_get_in_bucket_root_large_file(self):

        put_filename = inspect.currentframe().f_code.co_name 
        get_filename = f"{put_filename}.get"

        try:

            make_arbitrary_file(put_filename, 20*1024*1024)
            assert_command(f'iput {put_filename} {self.bucket_irods_path}/{put_filename}')
            with open(get_filename, 'wb') as f:
                self.boto3_client.download_fileobj(self.bucket_name, put_filename, f)
            assert_command(f'diff {put_filename} {get_filename}')

        finally:
            os.remove(put_filename)
            os.remove(get_filename)
            assert_command(f'irm -f {self.bucket_irods_path}/{put_filename}')

    def test_botocore_put_in_subdirectory(self):

        put_filename = inspect.currentframe().f_code.co_name 
        put_directory = f'{put_filename}_dir'
        get_filename = f'{put_filename}.get'

        try:

            make_arbitrary_file(put_filename, 100*1024)
            assert_command(f'imkdir {self.bucket_irods_path}/{put_directory}')
            assert_command(f'iput {put_filename} {self.bucket_irods_path}/{put_directory}/{put_filename}')
            with open(get_filename, 'wb') as f:
                self.boto3_client.download_fileobj(self.bucket_name, f'{put_directory}/{put_filename}', f)
            assert_command(f'diff {put_filename} {get_filename}')

        finally:
            os.remove(put_filename)
            os.remove(get_filename)
            assert_command(f'irm -rf {self.bucket_irods_path}/{put_directory}')

    def test_aws_get_in_bucket_root_small_file(self):

        put_filename = inspect.currentframe().f_code.co_name 
        get_filename = f"{put_filename}.get"

        try:

            make_arbitrary_file(put_filename, 100*1024)
            assert_command(f'iput {put_filename} {self.bucket_irods_path}/{put_filename}')
            with open(get_filename, 'wb') as f:
                    self.boto3_client.download_fileobj(self.bucket_name, put_filename, f)
            assert_command(f'aws --profile s3_api_alice --endpoint-url {self.s3_api_url} '
                    f's3 cp s3://{self.bucket_name}/{put_filename} {get_filename}',
                    'STDOUT_SINGLELINE',
                    f'download: s3://{self.bucket_name}/{put_filename} to ./{get_filename}')
            assert_command(f'diff {put_filename} {get_filename}')

        finally:
            os.remove(put_filename)
            os.remove(get_filename)
            assert_command(f'irm -f {self.bucket_irods_path}/{put_filename}')

    def test_aws_get_in_bucket_root_large_file(self):

        put_filename = inspect.currentframe().f_code.co_name 
        get_filename = f"{put_filename}.get"

        try:

            make_arbitrary_file(put_filename, 20*1024*1024)
            assert_command(f'iput {put_filename} {self.bucket_irods_path}/{put_filename}')
            with open(get_filename, 'wb') as f:
                    self.boto3_client.download_fileobj(self.bucket_name, put_filename, f)
            assert_command(f'aws --profile s3_api_alice --endpoint-url {self.s3_api_url} '
                    f's3 cp s3://{self.bucket_name}/{put_filename} {get_filename}',
                    'STDOUT_SINGLELINE',
                    f'download: s3://{self.bucket_name}/{put_filename} to ./{get_filename}')
            assert_command(f'diff {put_filename} {get_filename}')

        finally:
            os.remove(put_filename)
            os.remove(get_filename)
            assert_command(f'irm -f {self.bucket_irods_path}/{put_filename}')

    def test_aws_get_in_subdirectory(self):

        put_filename = inspect.currentframe().f_code.co_name 
        put_directory = f'{put_filename}_dir'
        get_filename = f'{put_filename}.get'

        try:

            make_arbitrary_file(put_filename, 100*1024)
            assert_command(f'imkdir {self.bucket_irods_path}/{put_directory}')
            assert_command(f'iput {put_filename} {self.bucket_irods_path}/{put_directory}/{put_filename}')
            assert_command(f'aws --profile s3_api_alice --endpoint-url {self.s3_api_url} '
                    f's3 cp s3://{self.bucket_name}/{put_directory}/{put_filename} {get_filename}',
                    'STDOUT_SINGLELINE',
                    f'download: s3://{self.bucket_name}/{put_directory}/{put_filename} to ./{get_filename}')
            assert_command(f'diff {put_filename} {get_filename}')

        finally:
            os.remove(put_filename)
            os.remove(get_filename)
            assert_command(f'irm -rf {self.bucket_irods_path}/{put_directory}')

    def test_minio_get_in_bucket_root_small_file(self):

        put_filename = inspect.currentframe().f_code.co_name 
        get_filename = f"{put_filename}.get"

        try:

            make_arbitrary_file(put_filename, 100*1024)
            assert_command(f'iput {put_filename} {self.bucket_irods_path}/{put_filename}')

            # read the data into get_filename
            data = self.minio_client.get_object(self.bucket_name, put_filename)
            with open(get_filename, 'wb') as file_data:
                for d in data.stream(32*1024):
                    file_data.write(d)
 
            # compare the put file and get file 
            assert_command(f'diff {put_filename} {get_filename}')

        finally:
            os.remove(put_filename)
            os.remove(get_filename)
            assert_command(f'irm -f {self.bucket_irods_path}/{put_filename}')
            data.close()
            data.release_conn()

    def test_minio_get_in_bucket_root_large_file(self):

        put_filename = inspect.currentframe().f_code.co_name 
        get_filename = f"{put_filename}.get"

        try:

            make_arbitrary_file(put_filename, 20*1024*1024)
            assert_command(f'iput {put_filename} {self.bucket_irods_path}/{put_filename}')

            # read the data into get_filename
            data = self.minio_client.get_object(self.bucket_name, put_filename)
            with open(get_filename, 'wb') as file_data:
                for d in data.stream(32*1024):
                    file_data.write(d)
 
            # compare the put file and get file 
            assert_command(f'diff {put_filename} {get_filename}')


        finally:
            os.remove(put_filename)
            os.remove(get_filename)
            assert_command(f'irm -f {self.bucket_irods_path}/{put_filename}')

    def test_minio_get_in_subdirectory(self):

        put_filename = inspect.currentframe().f_code.co_name 
        put_directory = f'{put_filename}_dir'
        get_filename = f'{put_filename}.get'

        try:
            make_arbitrary_file(put_filename, 100*1024)
            assert_command(f'imkdir {self.bucket_irods_path}/{put_directory}')
            assert_command(f'iput {put_filename} {self.bucket_irods_path}/{put_directory}/{put_filename}')

            # read the data into get_filename
            data = self.minio_client.get_object(self.bucket_name, f'{put_directory}/{put_filename}')
            with open(get_filename, 'wb') as file_data:
                for d in data.stream(32*1024):
                    file_data.write(d)
 
            # compare the put file and get file 
            assert_command(f'diff {put_filename} {get_filename}')

        finally:
            os.remove(put_filename)
            os.remove(get_filename)
            assert_command(f'irm -rf {self.bucket_irods_path}/{put_directory}')
