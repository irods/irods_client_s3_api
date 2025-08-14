import boto3
import inspect
import os
import unittest

from host_port import s3_api_host_port, irods_host
from libs import command, utility

class DeleteObject_Test(unittest.TestCase):

    # ======== Construction, setUp, tearDown =========

    bucket_irods_path = '/tempZone/home/alice/alice-bucket'
    bucket_name = 'alice-bucket'
    key = 's3_key2'
    secret_key = 's3_secret_key2'
    s3_api_url = f'http://{s3_api_host_port}'

    def __init__(self, *args, **kwargs):
        super(DeleteObject_Test, self).__init__(*args, **kwargs)

    def setUp(self):

        self.boto3_client = boto3.client('s3',
                                        use_ssl=False,
                                        endpoint_url=self.s3_api_url,
                                        aws_access_key_id=self.key,
                                        aws_secret_access_key=self.secret_key)

    def tearDown(self):
        self.boto3_client.close()

    # ======== Tests =========

    def test_botocore_delete_object_in_root_directory(self):
        put_filename = inspect.currentframe().f_code.co_name 
        try:
            # put file via icommands
            utility.make_arbitrary_file(put_filename, 100*1024)
            command.assert_command(f'iput {put_filename} {self.bucket_irods_path}/{put_filename}')

            # delete file via S3 bridge
            self.boto3_client.delete_object(Bucket=self.bucket_name, Key=f'{put_filename}')

            # check file has been deleted
            command.assert_command_fail(f'ils {self.bucket_irods_path}/{put_filename}', 'STDOUT_SINGLELINE', put_filename)
            
        finally:
            os.remove(put_filename)

    def test_botocore_delete_object_in_subdirectory(self):
        put_filename = inspect.currentframe().f_code.co_name 
        put_directory = f'{put_filename}.dir'
        try:
            # put file via icommands
            utility.make_arbitrary_file(put_filename, 100*1024)
            command.assert_command(f'imkdir {self.bucket_irods_path}/{put_directory}')
            command.assert_command(f'iput {put_filename} {self.bucket_irods_path}/{put_directory}/{put_filename}')

            # delete file via S3 bridge
            self.boto3_client.delete_object(Bucket=self.bucket_name, Key=f'{put_directory}/{put_filename}')

            # check file has been deleted
            command.assert_command_fail(f'ils {self.bucket_irods_path}/{put_directory}/{put_filename}', 'STDOUT_SINGLELINE', put_filename)
            
        finally:
            os.remove(put_filename)
            command.assert_command(f'irm -rf {self.bucket_irods_path}/{put_directory}')

    def test_aws_delete_object_in_root_directory(self):
        put_filename = inspect.currentframe().f_code.co_name 
        try:
            # put file via icommands
            utility.make_arbitrary_file(put_filename, 100*1024)
            command.assert_command(f'iput {put_filename} {self.bucket_irods_path}/{put_filename}')

            # delete file via S3 bridge
            command.assert_command(f'aws --profile s3_api_alice --endpoint-url {self.s3_api_url} s3 rm s3://{self.bucket_name}/{put_filename}',
                    'STDOUT_SINGLELINE', f'delete: s3://{self.bucket_name}/{put_filename}')

            # check file has been deleted
            command.assert_command_fail(f'ils {self.bucket_irods_path}/{put_filename}', 'STDOUT_SINGLELINE', put_filename)
            
        finally:
            os.remove(put_filename)

    def test_aws_delete_object_in_subdirectory(self):
        put_filename = inspect.currentframe().f_code.co_name 
        put_directory = f'{put_filename}.dir'
        try:
            # put file via icommands
            utility.make_arbitrary_file(put_filename, 100*1024)
            command.assert_command(f'imkdir {self.bucket_irods_path}/{put_directory}')
            command.assert_command(f'iput {put_filename} {self.bucket_irods_path}/{put_directory}/{put_filename}')

            # delete file via S3 bridge
            command.assert_command(f'aws --profile s3_api_alice --endpoint-url {self.s3_api_url} s3 rm s3://{self.bucket_name}/{put_directory}/{put_filename}',
                    'STDOUT_SINGLELINE', f'delete: s3://{self.bucket_name}/{put_directory}/{put_filename}')

            # check file has been deleted
            command.assert_command_fail(f'ils {self.bucket_irods_path}/{put_directory}/{put_filename}', 'STDOUT_SINGLELINE', put_filename)
            
        finally:
            os.remove(put_filename)
            command.assert_command(f'irm -rf {self.bucket_irods_path}/{put_directory}')

    def test_permission(self):
        put_filename = inspect.currentframe().f_code.co_name 
        try:
            utility.make_arbitrary_file(put_filename, 100*1024)
            command.assert_command(f'iput {put_filename} {self.bucket_irods_path}/{put_filename}')
            utility.execute_irods_command_as_user(f'ichmod -M null alice {self.bucket_irods_path}/{put_filename}', irods_host, 1247, 'rods', 'tempZone', 'rods', 'apass')
            self.assertRaises(Exception,
                          lambda: self.boto3_client.delete_object(Bucket=self.bucket_name, Key=f'{put_filename}'))
            utility.execute_irods_command_as_user(f'ichmod -M own alice {self.bucket_irods_path}/{put_filename}', irods_host, 1247, 'rods', 'tempZone', 'rods', 'apass')

        finally:
            os.remove(put_filename)
            command.assert_command(f'irm -f {self.bucket_irods_path}/{put_filename}')
