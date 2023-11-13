import unittest
import boto3
from boto3.s3.transfer import TransferConfig
import botocore
import botocore.session
import inspect
import os
from libs.execute import *
from libs.command import *
from libs.utility import *
from datetime import datetime
from minio import Minio
from minio.commonconfig import CopySource as MinioCopySource

class CopyObject_Test(TestCase):

    bucket_irods_path = '/tempZone/home/alice/alice-bucket'
    bucket_name = 'alice-bucket'
    bucket_irods_path2 = '/tempZone/home/alice/alice-bucket2'
    bucket_name2 = 'alice-bucket2'
    bucket_owner_irods = 'alice'
    key = 's3_key2'
    secret_key = 's3_secret_key2'
    s3_api_host_port = 's3-api:8080'
    s3_api_url = f'http://{s3_api_host_port}'

    def __init__(self, *args, **kwargs):
        super(CopyObject_Test, self).__init__(*args, **kwargs)

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

    def test_botocore_copy_object_root_small_file(self):

        put_filename = inspect.currentframe().f_code.co_name 
        copy_filename = f'{put_filename}.copy'
        get_filename = f'{put_filename}.get'

        try:
            make_arbitrary_file(put_filename, 100*1024)
            assert_command(f'iput {put_filename} {self.bucket_irods_path}/{put_filename}')
            self.boto3_client.copy_object(Bucket=self.bucket_name, CopySource=f'{self.bucket_name}/{put_filename}', Key=copy_filename)
            assert_command(f'iget {self.bucket_irods_path}/{copy_filename} {get_filename}')
            assert_command(f'diff {put_filename} {get_filename}')

        finally:
            os.remove(put_filename)
            os.remove(get_filename)
            assert_command(f'irm -f {self.bucket_irods_path}/{put_filename} {self.bucket_irods_path}/{copy_filename}')

    def test_botocore_copy_object_overwrite(self):

        put_filename = inspect.currentframe().f_code.co_name 
        overwritten_filename = f'{put_filename}.to_be_overwritten' 
        copy_filename = f'{put_filename}.copy'
        get_filename = f'{put_filename}.get'

        try:
            make_arbitrary_file(put_filename, 100*1024)
            make_arbitrary_file(overwritten_filename, 100)
            assert_command(f'iput {put_filename} {self.bucket_irods_path}/{put_filename}')
            assert_command(f'iput {overwritten_filename} {self.bucket_irods_path}/{copy_filename}')  # file to be overwritten
            self.boto3_client.copy_object(Bucket=self.bucket_name, CopySource=f'{self.bucket_name}/{put_filename}', Key=copy_filename)
            assert_command(f'iget {self.bucket_irods_path}/{copy_filename} {get_filename}')
            assert_command(f'diff {put_filename} {get_filename}')

        finally:
            os.remove(put_filename)
            os.remove(get_filename)
            os.remove(overwritten_filename)
            assert_command(f'irm -f {self.bucket_irods_path}/{put_filename} {self.bucket_irods_path}/{copy_filename}')

    def test_botocore_copy_object_root_large_file(self):

        put_filename = inspect.currentframe().f_code.co_name 
        copy_filename = f'{put_filename}.copy'
        get_filename = f'{put_filename}.get'

        try:
            make_arbitrary_file(put_filename, 20*1024*1024)
            assert_command(f'iput {put_filename} {self.bucket_irods_path}/{put_filename}')
            self.boto3_client.copy_object(Bucket=self.bucket_name, CopySource=f'{self.bucket_name}/{put_filename}', Key=copy_filename)
            assert_command(f'iget {self.bucket_irods_path}/{copy_filename} {get_filename}')
            assert_command(f'diff {put_filename} {get_filename}')

        finally:
            os.remove(put_filename)
            os.remove(get_filename)
            assert_command(f'irm -f {self.bucket_irods_path}/{put_filename} {self.bucket_irods_path}/{copy_filename}')

    def test_botocore_copy_object_in_different_subdirectories(self):

        put_filename = inspect.currentframe().f_code.co_name 
        put_directory = f'{put_filename}_dir'
        copy_directory = f'{put_filename}_copydir'
        copy_filename = f'{put_filename}.copy'
        get_filename = f'{put_filename}.get'

        try:
            make_arbitrary_file(put_filename, 20*1024*1024)
            assert_command(f'imkdir {self.bucket_irods_path}/{put_directory}')
            assert_command(f'iput {put_filename} {self.bucket_irods_path}/{put_directory}/{put_filename}')
            self.boto3_client.copy_object(Bucket=self.bucket_name, CopySource=f'{self.bucket_name}/{put_directory}/{put_filename}', Key=f'{copy_directory}/{copy_filename}')
            assert_command(f'iget {self.bucket_irods_path}/{copy_directory}/{copy_filename} {get_filename}')
            assert_command(f'diff {put_filename} {get_filename}')

        finally:
            os.remove(put_filename)
            os.remove(get_filename)
            assert_command(f'irm -rf {self.bucket_irods_path}/{put_directory} {self.bucket_irods_path}/{copy_directory}')

    def test_botocore_copy_object_in_different_buckets(self):

        # Note that these operations operate with the same key pairs.  Since the key pair maps to the iRODS user, these operations
        # must be between buckets/collections that the same iRODS user has access to.

        put_filename = inspect.currentframe().f_code.co_name 
        put_directory = f'{put_filename}_dir'
        copy_directory = f'{put_filename}_copydir'
        copy_filename = f'{put_filename}.copy'
        get_filename = f'{put_filename}.get'

        try:
            make_arbitrary_file(put_filename, 20*1024*1024)
            assert_command(f'imkdir {self.bucket_irods_path}/{put_directory}')
            assert_command(f'iput {put_filename} {self.bucket_irods_path}/{put_directory}/{put_filename}')
            self.boto3_client.copy_object(Bucket=self.bucket_name2, CopySource=f'{self.bucket_name}/{put_directory}/{put_filename}', Key=f'{copy_directory}/{copy_filename}')
            assert_command(f'iget {self.bucket_irods_path2}/{copy_directory}/{copy_filename} {get_filename}')
            assert_command(f'diff {put_filename} {get_filename}')

        finally:
            os.remove(put_filename)
            os.remove(get_filename)
            assert_command(f'irm -rf {self.bucket_irods_path}/{put_directory} {self.bucket_irods_path2}/{copy_directory}')

    def test_aws_copy_object_root_small_file(self):

        put_filename = inspect.currentframe().f_code.co_name 
        copy_filename = f'{put_filename}.copy'
        get_filename = f'{put_filename}.get'

        try:
            make_arbitrary_file(put_filename, 100*1024)
            assert_command(f'iput {put_filename} {self.bucket_irods_path}/{put_filename}')
            assert_command(f'aws --profile s3_api_alice_nomultipart --endpoint-url {self.s3_api_url} '
                    f's3 cp s3://{self.bucket_name}/{put_filename} s3://{self.bucket_name}/{copy_filename}',
                    'STDOUT_SINGLELINE',
                    f'copy: s3://{self.bucket_name}/{put_filename} to s3://{self.bucket_name}/{copy_filename}')
            assert_command(f'iget {self.bucket_irods_path}/{copy_filename} {get_filename}')
            assert_command(f'diff {put_filename} {get_filename}')

        finally:
            os.remove(put_filename)
            os.remove(get_filename)
            assert_command(f'irm -f {self.bucket_irods_path}/{put_filename} {self.bucket_irods_path}/{copy_filename}')

    def test_aws_copy_object_overwrite(self):

        put_filename = inspect.currentframe().f_code.co_name 
        overwritten_filename = f'{put_filename}.to_be_overwritten' 
        copy_filename = f'{put_filename}.copy'
        get_filename = f'{put_filename}.get'

        try:
            make_arbitrary_file(put_filename, 100*1024)
            make_arbitrary_file(overwritten_filename, 100)
            assert_command(f'iput {put_filename} {self.bucket_irods_path}/{put_filename}')
            assert_command(f'iput {overwritten_filename} {self.bucket_irods_path}/{copy_filename}')  # file to be overwritten
            assert_command(f'aws --profile s3_api_alice_nomultipart --endpoint-url {self.s3_api_url} '
                    f's3 cp s3://{self.bucket_name}/{put_filename} s3://{self.bucket_name}/{copy_filename}',
                    'STDOUT_SINGLELINE',
                    f'copy: s3://{self.bucket_name}/{put_filename} to s3://{self.bucket_name}/{copy_filename}')
            assert_command(f'iget {self.bucket_irods_path}/{copy_filename} {get_filename}')
            assert_command(f'diff {put_filename} {get_filename}')

        finally:
            os.remove(put_filename)
            os.remove(get_filename)
            os.remove(overwritten_filename)
            assert_command(f'irm -f {self.bucket_irods_path}/{put_filename} {self.bucket_irods_path}/{copy_filename}')

    def test_aws_copy_object_root_large_file(self):

        put_filename = inspect.currentframe().f_code.co_name 
        copy_filename = f'{put_filename}.copy'
        get_filename = f'{put_filename}.get'

        try:
            make_arbitrary_file(put_filename, 20*1024*1024)
            assert_command(f'iput {put_filename} {self.bucket_irods_path}/{put_filename}')
            assert_command(f'aws --profile s3_api_alice_nomultipart --endpoint-url {self.s3_api_url} '
                    f's3 cp s3://{self.bucket_name}/{put_filename} s3://{self.bucket_name}/{copy_filename}',
                    'STDOUT_SINGLELINE',
                    f'copy: s3://{self.bucket_name}/{put_filename} to s3://{self.bucket_name}/{copy_filename}')
            assert_command(f'iget {self.bucket_irods_path}/{copy_filename} {get_filename}')
            assert_command(f'diff {put_filename} {get_filename}')

        finally:
            os.remove(put_filename)
            os.remove(get_filename)
            assert_command(f'irm -f {self.bucket_irods_path}/{put_filename} {self.bucket_irods_path}/{copy_filename}')

    def test_aws_copy_object_in_different_subdirectories(self):

        put_filename = inspect.currentframe().f_code.co_name 
        put_directory = f'{put_filename}_dir'
        copy_directory = f'{put_filename}_copydir'
        copy_filename = f'{put_filename}.copy'
        get_filename = f'{put_filename}.get'

        try:
            make_arbitrary_file(put_filename, 20*1024*1024)
            assert_command(f'imkdir {self.bucket_irods_path}/{put_directory}')
            assert_command(f'iput {put_filename} {self.bucket_irods_path}/{put_directory}/{put_filename}')
            assert_command(f'aws --profile s3_api_alice_nomultipart --endpoint-url {self.s3_api_url} '
                    f's3 cp s3://{self.bucket_name}/{put_directory}/{put_filename} s3://{self.bucket_name}/{copy_directory}/{copy_filename}',
                    'STDOUT_SINGLELINE',
                    f'copy: s3://{self.bucket_name}/{put_directory}/{put_filename} to s3://{self.bucket_name}/{copy_directory}/{copy_filename}')
            assert_command(f'iget {self.bucket_irods_path}/{copy_directory}/{copy_filename} {get_filename}')
            assert_command(f'diff {put_filename} {get_filename}')

        finally:
            os.remove(put_filename)
            os.remove(get_filename)
            assert_command(f'irm -rf {self.bucket_irods_path}/{put_directory} {self.bucket_irods_path}/{copy_directory}')

    def test_aws_copy_object_in_different_buckets(self):

        put_filename = inspect.currentframe().f_code.co_name 
        put_directory = f'{put_filename}_dir'
        copy_directory = f'{put_filename}_copydir'
        copy_filename = f'{put_filename}.copy'
        get_filename = f'{put_filename}.get'

        try:
            make_arbitrary_file(put_filename, 20*1024*1024)
            assert_command(f'imkdir {self.bucket_irods_path}/{put_directory}')
            assert_command(f'iput {put_filename} {self.bucket_irods_path}/{put_directory}/{put_filename}')
            assert_command(f'aws --profile s3_api_alice_nomultipart --endpoint-url {self.s3_api_url} '
                    f's3 cp s3://{self.bucket_name}/{put_directory}/{put_filename} s3://{self.bucket_name2}/{copy_directory}/{copy_filename}',
                    'STDOUT_SINGLELINE',
                    f'copy: s3://{self.bucket_name}/{put_directory}/{put_filename} to s3://{self.bucket_name2}/{copy_directory}/{copy_filename}')
            assert_command(f'iget {self.bucket_irods_path2}/{copy_directory}/{copy_filename} {get_filename}')
            assert_command(f'diff {put_filename} {get_filename}')

        finally:
            os.remove(put_filename)
            os.remove(get_filename)
            assert_command(f'irm -rf {self.bucket_irods_path}/{put_directory} {self.bucket_irods_path2}/{copy_directory}')

    def test_minio_copy_object_root_small_file(self):

        put_filename = inspect.currentframe().f_code.co_name 
        copy_filename = f'{put_filename}.copy'
        get_filename = f'{put_filename}.get'

        try:
            make_arbitrary_file(put_filename, 100*1024)
            assert_command(f'iput {put_filename} {self.bucket_irods_path}/{put_filename}')
            self.minio_client.copy_object(self.bucket_name, copy_filename, MinioCopySource(self.bucket_name, put_filename))

            assert_command(f'iget {self.bucket_irods_path}/{copy_filename} {get_filename}')
            assert_command(f'diff {put_filename} {get_filename}')

        finally:
            os.remove(put_filename)
            os.remove(get_filename)
            assert_command(f'irm -f {self.bucket_irods_path}/{put_filename} {self.bucket_irods_path}/{copy_filename}')

    def test_minio_copy_object_overwrite(self):

        put_filename = inspect.currentframe().f_code.co_name 
        overwritten_filename = f'{put_filename}.to_be_overwritten' 
        copy_filename = f'{put_filename}.copy'
        get_filename = f'{put_filename}.get'

        try:
            make_arbitrary_file(put_filename, 100*1024)
            make_arbitrary_file(overwritten_filename, 100)
            assert_command(f'iput {put_filename} {self.bucket_irods_path}/{put_filename}')
            assert_command(f'iput {overwritten_filename} {self.bucket_irods_path}/{copy_filename}')  # file to be overwritten
            self.minio_client.copy_object(self.bucket_name, copy_filename, MinioCopySource(self.bucket_name, put_filename))
            assert_command(f'iget {self.bucket_irods_path}/{copy_filename} {get_filename}')
            assert_command(f'diff {put_filename} {get_filename}')

        finally:
            os.remove(put_filename)
            os.remove(get_filename)
            os.remove(overwritten_filename)
            assert_command(f'irm -f {self.bucket_irods_path}/{put_filename} {self.bucket_irods_path}/{copy_filename}')

    def test_minio_copy_object_root_large_file(self):

        put_filename = inspect.currentframe().f_code.co_name 
        copy_filename = f'{put_filename}.copy'
        get_filename = f'{put_filename}.get'

        try:
            make_arbitrary_file(put_filename, 20*1024*1024)
            assert_command(f'iput {put_filename} {self.bucket_irods_path}/{put_filename}')
            self.minio_client.copy_object(self.bucket_name, copy_filename, MinioCopySource(self.bucket_name, put_filename))
            assert_command(f'iget {self.bucket_irods_path}/{copy_filename} {get_filename}')
            assert_command(f'diff {put_filename} {get_filename}')

        finally:
            os.remove(put_filename)
            os.remove(get_filename)
            assert_command(f'irm -f {self.bucket_irods_path}/{put_filename} {self.bucket_irods_path}/{copy_filename}')

    def test_minio_copy_object_in_different_subdirectories(self):

        put_filename = inspect.currentframe().f_code.co_name 
        put_directory = f'{put_filename}_dir'
        copy_directory = f'{put_filename}_copydir'
        copy_filename = f'{put_filename}.copy'
        get_filename = f'{put_filename}.get'

        try:
            make_arbitrary_file(put_filename, 20*1024*1024)
            assert_command(f'imkdir {self.bucket_irods_path}/{put_directory}')
            assert_command(f'iput {put_filename} {self.bucket_irods_path}/{put_directory}/{put_filename}')
            self.minio_client.copy_object(self.bucket_name, f'{copy_directory}/{copy_filename}', MinioCopySource(self.bucket_name, f'{put_directory}/{put_filename}'))
            assert_command(f'iget {self.bucket_irods_path}/{copy_directory}/{copy_filename} {get_filename}')
            assert_command(f'diff {put_filename} {get_filename}')

        finally:
            os.remove(put_filename)
            os.remove(get_filename)
            assert_command(f'irm -rf {self.bucket_irods_path}/{put_directory} {self.bucket_irods_path}/{copy_directory}')

    def test_minio_copy_object_in_different_buckets(self):

        put_filename = inspect.currentframe().f_code.co_name 
        put_directory = f'{put_filename}_dir'
        copy_directory = f'{put_filename}_copydir'
        copy_filename = f'{put_filename}.copy'
        get_filename = f'{put_filename}.get'

        try:
            make_arbitrary_file(put_filename, 20*1024*1024)
            assert_command(f'imkdir {self.bucket_irods_path}/{put_directory}')
            assert_command(f'iput {put_filename} {self.bucket_irods_path}/{put_directory}/{put_filename}')
            self.minio_client.copy_object(self.bucket_name2, f'{copy_directory}/{copy_filename}', MinioCopySource(self.bucket_name, f'{put_directory}/{put_filename}'))
            assert_command(f'iget {self.bucket_irods_path2}/{copy_directory}/{copy_filename} {get_filename}')
            assert_command(f'diff {put_filename} {get_filename}')

        finally:
            os.remove(put_filename)
            os.remove(get_filename)
            assert_command(f'irm -rf {self.bucket_irods_path}/{put_directory} {self.bucket_irods_path2}/{copy_directory}')

    def test_permissions(self):
        put_filename = inspect.currentframe().f_code.co_name 
        copy_filename = f'{put_filename}.copy'
        get_filename = f'{put_filename}.get'

        try:
            make_arbitrary_file(put_filename, 100*1024)
            assert_command(f'iput {put_filename} {self.bucket_irods_path}/{put_filename}')
            execute_irods_command_as_user(f'ichmod -M null alice {self.bucket_irods_path}/{put_filename}', 'irods', 1247, 'rods', 'tempZone', 'rods', 'apass')
            self.assertRaises(Exception,
                          lambda: self.boto3_client.copy_object(Bucket=self.bucket_name, 
                              CopySource=f'{self.bucket_name}/{put_directory}/{put_filename}', Key=f'{copy_directory}/{copy_filename}'))
            execute_irods_command_as_user(f'ichmod -M own alice {self.bucket_irods_path}/{put_filename}', 'irods', 1247, 'rods', 'tempZone', 'rods', 'apass')

        finally:
            os.remove(put_filename)
            assert_command(f'irm -f {self.bucket_irods_path}/{put_filename}')

#if __name__ == '__main__':
#    unittest.main()
