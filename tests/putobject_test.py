from unittest import *
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

class PutObject_Test(TestCase):

    bucket_irods_path = '/tempZone/home/alice/alice-bucket'
    bucket_name = 'alice-bucket'
    bucket_owner_irods = 'alice'
    key = 's3_key2'
    secret_key = 's3_secret_key2'
    s3_api_url = 'http://s3-api:8080'

    def __init__(self, *args, **kwargs):
        super(PutObject_Test, self).__init__(*args, **kwargs)

    def setUp(self):

        self.boto3_client = boto3.client('s3',
                                        use_ssl=False,
                                        endpoint_url=self.s3_api_url,
                                        aws_access_key_id=self.key,
                                        aws_secret_access_key=self.secret_key)

    def tearDown(self):
        pass

    def test_botocore_put_in_bucket_root_small_file(self):

        put_filename = inspect.currentframe().f_code.co_name 
        get_filename = f'{put_filename}.get'

        try:

            make_arbitrary_file(put_filename, 100*1024)
            self.boto3_client.upload_file(put_filename, self.bucket_name, put_filename)
            assert_command(f'iget {self.bucket_irods_path}/{put_filename} {get_filename}')
            assert_command(f'diff {put_filename} {get_filename}')

        finally:
            os.remove(put_filename)
            os.remove(get_filename)
            assert_command(f'irm -f {self.bucket_irods_path}/{put_filename}')

    def test_botocore_put_in_bucket_root_large_file(self):

        put_filename = inspect.currentframe().f_code.co_name 
        get_filename = f'{put_filename}.get'

        try:

            make_arbitrary_file(put_filename, 20*1024*1024)

            # make sure we don't attempt multipart which is not supported
            config = TransferConfig(multipart_threshold=5*1024*1024*1024)

            self.boto3_client.upload_file(put_filename, self.bucket_name, put_filename, Config=config)
            assert_command(f'iget {self.bucket_irods_path}/{put_filename} {get_filename}')
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
            self.boto3_client.upload_file(put_filename, self.bucket_name, f'{put_directory}/{put_filename}')
            assert_command(f'iget {self.bucket_irods_path}/{put_directory}/{put_filename} {get_filename}')
            assert_command(f'diff {put_filename} {get_filename}')

        finally:
            os.remove(put_filename)
            os.remove(get_filename)
            assert_command(f'irm -rf {self.bucket_irods_path}/{put_directory}')

    def test_aws_put_in_bucket_root_small_file(self):

        put_filename = inspect.currentframe().f_code.co_name 
        get_filename = f'{put_filename}.get'

        try:

            make_arbitrary_file(put_filename, 100*1024)
            assert_command(f'aws --profile s3_api_alice_nomultipart --endpoint-url {self.s3_api_url} '
                    f's3 cp {put_filename} s3://{self.bucket_name}/{put_filename}',
                    'STDOUT_SINGLELINE',
                    f'upload: ./{put_filename} to s3://{self.bucket_name}/{put_filename}')
            assert_command(f'iget {self.bucket_irods_path}/{put_filename} {get_filename}')
            assert_command(f'diff {put_filename} {get_filename}')

        finally:
            os.remove(put_filename)
            os.remove(get_filename)
            assert_command(f'irm -f {self.bucket_irods_path}/{put_filename}')

    def test_aws_put_in_bucket_root_large_file(self):

        put_filename = inspect.currentframe().f_code.co_name 
        get_filename = f'{put_filename}.get'

        try:

            make_arbitrary_file(put_filename, 20*1024*1024)
            assert_command(f'aws --profile s3_api_alice_nomultipart --endpoint-url {self.s3_api_url} '
                    f's3 cp {put_filename} s3://{self.bucket_name}/{put_filename}',
                    'STDOUT_SINGLELINE',
                    f'upload: ./{put_filename} to s3://{self.bucket_name}/{put_filename}')
            assert_command(f'iget {self.bucket_irods_path}/{put_filename} {get_filename}')
            assert_command(f'diff {put_filename} {get_filename}')

        finally:
            os.remove(put_filename)
            os.remove(get_filename)
            assert_command(f'irm -f {self.bucket_irods_path}/{put_filename}')

    def test_aws_put_in_subdirectory(self):

        put_filename = inspect.currentframe().f_code.co_name 
        put_directory = f'{put_filename}_dir'
        get_filename = f'{put_filename}.get'

        try:

            make_arbitrary_file(put_filename, 100*1024)
            self.boto3_client.upload_file(put_filename, self.bucket_name, f'{put_directory}/{put_filename}')
            assert_command(f'aws --profile s3_api_alice_nomultipart --endpoint-url {self.s3_api_url} '
                    f's3 cp {put_filename} s3://{self.bucket_name}/{put_directory}/{put_filename}',
                    'STDOUT_SINGLELINE',
                    f'upload: ./{put_filename} to s3://{self.bucket_name}/{put_directory}/{put_filename}')
            assert_command(f'iget {self.bucket_irods_path}/{put_directory}/{put_filename} {get_filename}')
            assert_command(f'diff {put_filename} {get_filename}')

        finally:
            os.remove(put_filename)
            os.remove(get_filename)
            assert_command(f'irm -rf {self.bucket_irods_path}/{put_directory}')

    def test_put_fails(self):
        """
        Tests that that putobject works properly in the failure case.
        """

        try:
            put_filename = inspect.currentframe().f_code.co_name 
            get_filename = f'{put_filename}.get'

            # Check if the permissions of the directory are properly honored. Namely,
            # it should return a 403 status code if it cannot write.
            assert_command(f'ichmod -r read_metadata alice {self.bucket_irods_path}') 
            self.assertRaises(Exception,
                              lambda: self.boto3_client.upload_file(put_filename, self.bucket_name, put_filename))

            execute_irods_command_as_user(f'ichmod -Mr own alice {self.bucket_irods_path}', 'irods', 1247, 'rods', 'tempZone', 'rods', 'apass')

            # This is overwriting a file directly that the user cannot overwrite. 
            # It should provide a 403 status code
            touch_file(f'{self.bucket_irods_path}/{put_filename}', access_level='read_metadata', user=self.bucket_owner_irods)
            self.assertRaises(Exception,
                              lambda: self.boto3_client.upload_file(put_filename, self.bucket_name, put_filename))
            execute_irods_command_as_user(f'ichmod -M own alice {self.bucket_irods_path}/{put_filename}', 'irods', 1247, 'rods', 'tempZone', 'rods', 'apass')

        finally:
            assert_command(f'irm -f {self.bucket_irods_path}/{put_filename}')
