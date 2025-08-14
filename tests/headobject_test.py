from datetime import datetime
import boto3
import botocore
import inspect
import os
import unittest

from host_port import s3_api_host_port, irods_host
from libs import command, utility

class HeadObject_Test(unittest.TestCase):

    # ======== Construction, setUp, tearDown =========

    bucket_irods_path = '/tempZone/home/alice/alice-bucket'
    bucket_name = 'alice-bucket'
    key = 's3_key2'
    secret_key = 's3_secret_key2'
    s3_api_url = f'http://{s3_api_host_port}'

    def __init__(self, *args, **kwargs):
        super(HeadObject_Test, self).__init__(*args, **kwargs)

    def setUp(self):

        self.boto3_client = boto3.client('s3',
                                        use_ssl=False,
                                        endpoint_url=self.s3_api_url,
                                        aws_access_key_id=self.key,
                                        aws_secret_access_key=self.secret_key)

    def tearDown(self):
        self.boto3_client.close()

    # ======== Tests =========

    # Note:  Minio mc client does not have a head-object command but this is called behind the
    # scenes on other tests such as list-object.

    def test_botocore_head_object_in_root_directory(self):
        put_filename = inspect.currentframe().f_code.co_name 
        try:
            # create and put a file
            file_size = 100*1024
            utility.make_arbitrary_file(put_filename, file_size)
            command.assert_command(f'iput {put_filename} {self.bucket_irods_path}/{put_filename}')

            # get file last modified time for comparison below
            _,out,_ = command.assert_command(f'iquest "%s" "select DATA_MODIFY_TIME where COLL_NAME = \'{self.bucket_irods_path}\' and DATA_NAME = \'{put_filename}\'"', 'STDOUT')
            object_create_time = datetime.fromtimestamp(int(out))
            print(out)

            head_object_result = self.boto3_client.head_object(Bucket=self.bucket_name, Key=f'{put_filename}')
            self.assertEqual(head_object_result['ResponseMetadata']['HTTPStatusCode'], 200)
            self.assertEqual(head_object_result['ContentLength'], file_size)
            self.assertEqual(head_object_result['LastModified'].replace(tzinfo=None), datetime.fromtimestamp(int(out)).replace(tzinfo=None))
        finally:
            os.remove(put_filename)
            command.assert_command(f'irm -f {self.bucket_irods_path}/{put_filename}')

    def test_botocore_head_object_in_subdirectory(self):
        put_filename = inspect.currentframe().f_code.co_name 
        put_directory = f'{put_filename}.dir'
        try:
            # create and put a file
            file_size = 100*1024
            utility.make_arbitrary_file(put_filename, file_size)
            command.assert_command(f'imkdir {self.bucket_irods_path}/{put_directory}')
            command.assert_command(f'iput {put_filename} {self.bucket_irods_path}/{put_directory}/{put_filename}')

            # get file last modified time for comparison below
            _,out,_ = command.assert_command(f'iquest "%s" "select DATA_MODIFY_TIME where COLL_NAME = \'{self.bucket_irods_path}/{put_directory}\' and DATA_NAME = \'{put_filename}\'"', 'STDOUT')
            object_create_time = datetime.fromtimestamp(int(out))
            print(out)

            head_object_result = self.boto3_client.head_object(Bucket=self.bucket_name, Key=f'{put_directory}/{put_filename}')
            self.assertEqual(head_object_result['ResponseMetadata']['HTTPStatusCode'], 200)
            self.assertEqual(head_object_result['ContentLength'], file_size)
            self.assertEqual(head_object_result['LastModified'].replace(tzinfo=None), datetime.fromtimestamp(int(out)).replace(tzinfo=None))
        finally:
            os.remove(put_filename)
            command.assert_command(f'irm -rf {self.bucket_irods_path}/{put_directory}')

    def test_aws_head_object_in_root_directory(self):
        put_filename = inspect.currentframe().f_code.co_name 
        try:
            # create and put a file
            file_size = 100*1024
            utility.make_arbitrary_file(put_filename, file_size)
            command.assert_command(f'iput {put_filename} {self.bucket_irods_path}/{put_filename}')

            # get file last modified time for comparison below
            _,out,_ = command.assert_command(f'iquest "%s" "select DATA_MODIFY_TIME where COLL_NAME = \'{self.bucket_irods_path}\' and DATA_NAME = \'{put_filename}\'"', 'STDOUT')
            object_create_time = datetime.fromtimestamp(int(out))
            object_create_time_formatted = datetime.fromtimestamp(int(out)).strftime("%Y-%m-%dT%H:%M:%S")

            # Note:  When checking LastModified, we are not looking at the timezone offset which is printed in the AWS tools
            command.assert_command(f'aws --profile s3_api_alice --endpoint-url {self.s3_api_url} s3api head-object --bucket {self.bucket_name} --key {put_filename}',
                    'STDOUT_MULTILINE', [f'"ContentLength": {file_size}', f'"LastModified": "{object_create_time_formatted}'])
        finally:
            os.remove(put_filename)
            command.assert_command(f'irm -f {self.bucket_irods_path}/{put_filename}')

    def test_aws_head_object_in_subdirectory(self):
        put_filename = inspect.currentframe().f_code.co_name 
        put_directory = f'{put_filename}.dir'
        try:
            # create and put a file
            file_size = 100*1024
            utility.make_arbitrary_file(put_filename, file_size)
            command.assert_command(f'imkdir {self.bucket_irods_path}/{put_directory}')
            command.assert_command(f'iput {put_filename} {self.bucket_irods_path}/{put_directory}/{put_filename}')

            # get file last modified time for comparison below
            _,out,_ = command.assert_command(f'iquest "%s" "select DATA_MODIFY_TIME where COLL_NAME = \'{self.bucket_irods_path}/{put_directory}\' and DATA_NAME = \'{put_filename}\'"', 'STDOUT')
            object_create_time = datetime.fromtimestamp(int(out))
            object_create_time_formatted = datetime.fromtimestamp(int(out)).strftime("%Y-%m-%dT%H:%M:%S")

            command.assert_command(f'aws --profile s3_api_alice --endpoint-url {self.s3_api_url} s3api head-object --bucket {self.bucket_name} --key {put_directory}/{put_filename}',
                    'STDOUT_MULTILINE', [f'"ContentLength": {file_size}', f'"LastModified": "{object_create_time_formatted}'])
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
                          lambda: self.boto3_client.head_object(Bucket=self.bucket_name, Key=f'{put_filename}'))
            utility.execute_irods_command_as_user(f'ichmod -M own alice {self.bucket_irods_path}/{put_filename}', irods_host, 1247, 'rods', 'tempZone', 'rods', 'apass')

        finally:
            os.remove(put_filename)
            command.assert_command(f'irm -f {self.bucket_irods_path}/{put_filename}')

    def test_head_nonexistent_bucket_and_file(self):
        self.assertRaises(botocore.exceptions.ClientError, lambda: self.boto3_client.head_object(Bucket="dne", Key="dne"))
        self.assertRaises(botocore.exceptions.ClientError, lambda: self.boto3_client.head_object(Bucket=self.bucket_name, Key="dne"))

