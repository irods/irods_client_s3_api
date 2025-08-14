import boto3
import inspect
import os
import unittest

from host_port import s3_api_host_port, irods_host
from libs import command, utility

class PutObject_Test(unittest.TestCase):

    bucket_irods_path = '/tempZone/home/alice/alice-bucket'
    bucket_name = 'alice-bucket'
    bucket_owner_irods = 'alice'
    key = 's3_key2'
    secret_key = 's3_secret_key2'
    s3_api_url = f'http://{s3_api_host_port}'

    def __init__(self, *args, **kwargs):
        super(PutObject_Test, self).__init__(*args, **kwargs)

    def setUp(self):

        self.boto3_client = boto3.client('s3',
                                        use_ssl=False,
                                        endpoint_url=self.s3_api_url,
                                        aws_access_key_id=self.key,
                                        aws_secret_access_key=self.secret_key)

    def tearDown(self):
        self.boto3_client.close()

    def test_botocore_put_in_bucket_root_small_file(self):

        put_filename = inspect.currentframe().f_code.co_name 
        get_filename = f'{put_filename}.get'

        try:

            utility.make_arbitrary_file(put_filename, 100*1024)
            self.boto3_client.upload_file(put_filename, self.bucket_name, put_filename)
            command.assert_command(f'iget {self.bucket_irods_path}/{put_filename} {get_filename}')
            command.assert_command(f'diff -q {put_filename} {get_filename}')

        finally:
            os.remove(put_filename)
            os.remove(get_filename)
            command.assert_command(f'irm -f {self.bucket_irods_path}/{put_filename}')

    def test_botocore_put_in_bucket_root_large_file(self):

        put_filename = inspect.currentframe().f_code.co_name 
        get_filename = f'{put_filename}.get'

        try:

            utility.make_arbitrary_file(put_filename, 20*1024*1024)

            self.boto3_client.upload_file(put_filename, self.bucket_name, put_filename)
            command.assert_command(f'iget {self.bucket_irods_path}/{put_filename} {get_filename}')
            command.assert_command(f'diff -q {put_filename} {get_filename}')

            # perform upload a second time to make sure original file was closed properly
            self.boto3_client.upload_file(put_filename, self.bucket_name, put_filename)
            command.assert_command(f'iget -f {self.bucket_irods_path}/{put_filename} {get_filename}')
            command.assert_command(f'diff -q {put_filename} {get_filename}')

        finally:
            os.remove(put_filename)
            os.remove(get_filename)
            command.assert_command(f'irm -f {self.bucket_irods_path}/{put_filename}')

    def test_botocore_put_in_subdirectory(self):

        put_filename = inspect.currentframe().f_code.co_name 
        put_directory = f'{put_filename}_dir'
        get_filename = f'{put_filename}.get'

        try:

            utility.make_arbitrary_file(put_filename, 100*1024)
            self.boto3_client.upload_file(put_filename, self.bucket_name, f'{put_directory}/{put_filename}')
            command.assert_command(f'iget {self.bucket_irods_path}/{put_directory}/{put_filename} {get_filename}')
            command.assert_command(f'diff -q {put_filename} {get_filename}')

        finally:
            os.remove(put_filename)
            os.remove(get_filename)
            command.assert_command(f'irm -rf {self.bucket_irods_path}/{put_directory}')

    def test_aws_put_in_bucket_root_small_file(self):

        put_filename = inspect.currentframe().f_code.co_name 
        get_filename = f'{put_filename}.get'

        try:

            utility.make_arbitrary_file(put_filename, 100*1024)
            command.assert_command(f'aws --profile s3_api_alice --endpoint-url {self.s3_api_url} '
                    f's3 cp {put_filename} s3://{self.bucket_name}/{put_filename}',
                    'STDOUT_SINGLELINE',
                    f'upload: ./{put_filename} to s3://{self.bucket_name}/{put_filename}')
            command.assert_command(f'iget {self.bucket_irods_path}/{put_filename} {get_filename}')
            command.assert_command(f'diff -q {put_filename} {get_filename}')

        finally:
            os.remove(put_filename)
            os.remove(get_filename)
            command.assert_command(f'irm -f {self.bucket_irods_path}/{put_filename}')

    def test_aws_put_in_bucket_root_large_file(self):

        put_filename = inspect.currentframe().f_code.co_name 
        get_filename = f'{put_filename}.get'

        try:

            utility.make_arbitrary_file(put_filename, 20*1024*1024)
            command.assert_command(f'aws --profile s3_api_alice --endpoint-url {self.s3_api_url} '
                    f's3 cp {put_filename} s3://{self.bucket_name}/{put_filename}',
                    'STDOUT_SINGLELINE',
                    f'upload: ./{put_filename} to s3://{self.bucket_name}/{put_filename}')
            command.assert_command(f'iget {self.bucket_irods_path}/{put_filename} {get_filename}')
            command.assert_command(f'diff -q {put_filename} {get_filename}')

            # perform upload a second time to make sure original file was closed properly
            command.assert_command(f'aws --profile s3_api_alice --endpoint-url {self.s3_api_url} '
                    f's3 cp {put_filename} s3://{self.bucket_name}/{put_filename}',
                    'STDOUT_SINGLELINE',
                    f'upload: ./{put_filename} to s3://{self.bucket_name}/{put_filename}')
            command.assert_command(f'iget -f {self.bucket_irods_path}/{put_filename} {get_filename}')
            command.assert_command(f'diff -q {put_filename} {get_filename}')

        finally:
            os.remove(put_filename)
            os.remove(get_filename)
            command.assert_command(f'irm -f {self.bucket_irods_path}/{put_filename}')

    def test_aws_put_in_subdirectory(self):

        put_filename = inspect.currentframe().f_code.co_name 
        put_directory = f'{put_filename}_dir'
        get_filename = f'{put_filename}.get'

        try:

            utility.make_arbitrary_file(put_filename, 100*1024)
            self.boto3_client.upload_file(put_filename, self.bucket_name, f'{put_directory}/{put_filename}')
            command.assert_command(f'aws --profile s3_api_alice --endpoint-url {self.s3_api_url} '
                    f's3 cp {put_filename} s3://{self.bucket_name}/{put_directory}/{put_filename}',
                    'STDOUT_SINGLELINE',
                    f'upload: ./{put_filename} to s3://{self.bucket_name}/{put_directory}/{put_filename}')
            command.assert_command(f'iget {self.bucket_irods_path}/{put_directory}/{put_filename} {get_filename}')
            command.assert_command(f'diff -q {put_filename} {get_filename}')

        finally:
            os.remove(put_filename)
            os.remove(get_filename)
            command.assert_command(f'irm -rf {self.bucket_irods_path}/{put_directory}')

    def test_mc_put_small_file_in_bucket_root(self):

        put_filename = inspect.currentframe().f_code.co_name 
        get_filename = f'{put_filename}.get'

        try:
            utility.make_arbitrary_file(put_filename, 100*1024)
            command.assert_command(f'mc cp {put_filename} s3-api-alice/{self.bucket_name}/{put_filename}',
                    'STDOUT_SINGLELINE',
                    'small_file')
            command.assert_command(f'iget {self.bucket_irods_path}/{put_filename} {get_filename}')
            command.assert_command(f'diff -q {put_filename} {get_filename}')

        finally:
            os.remove(put_filename)
            os.remove(get_filename)
            command.assert_command(f'irm -f {self.bucket_irods_path}/{put_filename}')

    def test_mc_put_large_file_in_bucket_root(self):

        put_filename = inspect.currentframe().f_code.co_name 
        get_filename = f'{put_filename}.get'

        try:

            utility.make_arbitrary_file(put_filename, 20*1024*1024)
            command.assert_command(f'mc cp {put_filename} s3-api-alice/{self.bucket_name}/{put_filename}',
                    'STDOUT_SINGLELINE',
                    'large_file')
            command.assert_command(f'iget {self.bucket_irods_path}/{put_filename} {get_filename}')
            command.assert_command(f'diff -q {put_filename} {get_filename}')

            # perform upload a second time to make sure original file was closed properly
            command.assert_command(f'mc cp {put_filename} s3-api-alice/{self.bucket_name}/{put_filename}',
                    'STDOUT_SINGLELINE',
                    'large_file')
            command.assert_command(f'iget -f {self.bucket_irods_path}/{put_filename} {get_filename}')
            command.assert_command(f'diff -q {put_filename} {get_filename}')

        finally:
            os.remove(put_filename)
            os.remove(get_filename)
            command.assert_command(f'irm -f {self.bucket_irods_path}/{put_filename}')

    def test_mc_put_in_subdirectory(self):

        put_filename = inspect.currentframe().f_code.co_name 
        put_directory = f'{put_filename}_dir'
        get_filename = f'{put_filename}.get'

        try:

            utility.make_arbitrary_file(put_filename, 100*1024)
            self.boto3_client.upload_file(put_filename, self.bucket_name, f'{put_directory}/{put_filename}')
            command.assert_command(f'mc cp {put_filename} s3-api-alice/{self.bucket_name}/{put_directory}/{put_filename}',
                    'STDOUT_SINGLELINE',
                    'in_subdirectory')
            command.assert_command(f'iget {self.bucket_irods_path}/{put_directory}/{put_filename} {get_filename}')
            command.assert_command(f'diff -q {put_filename} {get_filename}')

        finally:
            os.remove(put_filename)
            os.remove(get_filename)
            command.assert_command(f'irm -rf {self.bucket_irods_path}/{put_directory}')

    def test_put_fails(self):
        """
        Tests that that putobject works properly in the failure case.
        """

        try:
            put_filename = inspect.currentframe().f_code.co_name 
            get_filename = f'{put_filename}.get'

            # Check if the permissions of the directory are properly honored. Namely,
            # it should return a 403 status code if it cannot write.
            command.assert_command(f'ichmod -r read_metadata alice {self.bucket_irods_path}') 
            self.assertRaises(Exception,
                              lambda: self.boto3_client.upload_file(put_filename, self.bucket_name, put_filename))

            utility.execute_irods_command_as_user(f'ichmod -Mr own alice {self.bucket_irods_path}', irods_host, 1247, 'rods', 'tempZone', 'rods', 'apass')

            # This is overwriting a file directly that the user cannot overwrite. 
            # It should provide a 403 status code
            utility.touch_file(f'{self.bucket_irods_path}/{put_filename}', access_level='read_metadata', user=self.bucket_owner_irods)
            self.assertRaises(Exception,
                              lambda: self.boto3_client.upload_file(put_filename, self.bucket_name, put_filename))
            utility.execute_irods_command_as_user(f'ichmod -M own alice {self.bucket_irods_path}/{put_filename}', irods_host, 1247, 'rods', 'tempZone', 'rods', 'apass')

        finally:
            command.assert_command(f'irm -f {self.bucket_irods_path}/{put_filename}')
