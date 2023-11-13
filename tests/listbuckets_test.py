from unittest import *
import botocore
import botocore.session
import os
from libs.execute import *
from libs.command import *
from libs.utility import *
from datetime import datetime

class ListBuckets_Test(TestCase):

    # ======== Construction, setUp, tearDown =========
    key_alice = 's3_key2'
    secret_key_alice = 's3_secret_key2'

    key_rods = 's3_key1'
    secret_key_rods = 's3_secret_key1'

    bucket_irods_path_alice_bucket = '/tempZone/home/alice/alice-bucket'
    bucket_irods_path_alice_bucket2 = '/tempZone/home/alice/alice-bucket2'
    bucket_irods_path_test_bucket = '/tempZone/home/alice/test-bucket'

    s3_api_url = 'http://s3-api:8080'

    def __init__(self, *args, **kwargs):
        super(ListBuckets_Test, self).__init__(*args, **kwargs)

    def setUp(self):

        session = botocore.session.get_session()
        self.client_rods = session.create_client('s3',
                                            use_ssl=False,
                                            endpoint_url=self.s3_api_url,
                                            aws_access_key_id=self.key_rods,
                                            aws_secret_access_key=self.secret_key_rods)
        self.client_alice = session.create_client('s3',
                                            use_ssl=False,
                                            endpoint_url=self.s3_api_url,
                                            aws_access_key_id=self.key_alice,
                                            aws_secret_access_key=self.secret_key_alice)

    def tearDown(self):
        self.client_rods.close()
        self.client_alice.close()

    # ======== Helper Functions =========

    def assert_bucket_in_list_bucket_result(self, list_buckets_result, bucket_name, bucket_creation_date=None):
        buckets_list = list_buckets_result['Buckets']
        matching_bucket_name = None
        matching_creation_date = None
        for entry in buckets_list:
            if entry['Name'] == bucket_name:
                matching_bucket_name = entry['Name']
                matching_creation_date = entry['CreationDate']
                break
    
        self.assertIsNotNone(bucket_name, f'Bucket not found [{bucket_name}]')
        self.assertIsNotNone(matching_creation_date, f'CreationDate not found for bucket [{bucket_name}]')
        if bucket_creation_date != None:
            self.assertEqual(matching_creation_date.replace(tzinfo=None), bucket_creation_date.replace(tzinfo=None))
    
    # ======== Tests =========

    def test_botocore_list_bucket(self):

        # Read the creation date for the two collections that alice can read for comparison below.
        # Note we will not compare the creation date for test-bucket.
        _,out,_ = assert_command(f'iquest "%s" "select COLL_CREATE_TIME where COLL_NAME = \'{self.bucket_irods_path_alice_bucket}\'"', 'STDOUT')
        alice_bucket_create_time = datetime.fromtimestamp(int(out))
        _,out,_ = assert_command(f'iquest "%s" "select COLL_CREATE_TIME where COLL_NAME = \'{self.bucket_irods_path_alice_bucket2}\'"', 'STDOUT')
        alice_bucket2_create_time = datetime.fromtimestamp(int(out))

        # rods can read all three buckets 
        list_buckets_result = self.client_rods.list_buckets()
        print(list_buckets_result)
        self.assertEqual(list_buckets_result['ResponseMetadata']['HTTPStatusCode'], 200)
        self.assert_bucket_in_list_bucket_result(list_buckets_result, 'alice-bucket', alice_bucket_create_time)
        self.assert_bucket_in_list_bucket_result(list_buckets_result, 'alice-bucket2', alice_bucket2_create_time)
        self.assert_bucket_in_list_bucket_result(list_buckets_result, 'test-bucket')

        # alice can read only the two alice buckets 
        list_buckets_result = self.client_alice.list_buckets()
        print(list_buckets_result)
        self.assertEqual(list_buckets_result['ResponseMetadata']['HTTPStatusCode'], 200)
        self.assertEqual(len(list_buckets_result['Buckets']), 2)
        self.assert_bucket_in_list_bucket_result(list_buckets_result, 'alice-bucket', alice_bucket_create_time)
        self.assert_bucket_in_list_bucket_result(list_buckets_result, 'alice-bucket2', alice_bucket2_create_time)

    def test_aws_list_bucket(self):

        # rods can read all three buckets 
        assert_command(f'aws --profile s3_api_rods --endpoint-url {self.s3_api_url} s3 ls s3://',
                'STDOUT_MULTILINE', ['alice-bucket', 'alice-bucket2', 'test-bucket'])

        # alice can read only the two alice buckets 
        assert_command(f'aws --profile s3_api_alice --endpoint-url {self.s3_api_url} s3 ls s3://',
                'STDOUT_MULTILINE', ['alice-bucket', 'alice-bucket2'])

    def test_mc_list_bucket(self):

        # rods can read all three buckets 
        # mc ls s3-api-alice
        assert_command(f'mc ls s3-api-rods',
                'STDOUT_MULTILINE', ['alice-bucket', 'alice-bucket2', 'test-bucket'])

        # alice can read only the two alice buckets 
        assert_command(f'mc ls s3-api-alice',
                'STDOUT_MULTILINE', ['alice-bucket', 'alice-bucket2'])
