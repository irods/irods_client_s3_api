from unittest import *
import boto3
import botocore
import inspect
import os
from libs.execute import *
from libs.command import *
from libs.utility import *
from datetime import datetime

class HeadBucket_Test(TestCase):

    # ======== Construction, setUp, tearDown =========
    rods_key = 's3_key1'
    rods_secret_key = 's3_secret_key1'
    alice_key = 's3_key2'
    alice_secret_key = 's3_secret_key2'
    s3_api_url = 'http://s3-api:8080'

    def __init__(self, *args, **kwargs):
        super(HeadBucket_Test, self).__init__(*args, **kwargs)

    def setUp(self):

        self.boto3_client_rods = boto3.client('s3',
                                        use_ssl=False,
                                        endpoint_url=self.s3_api_url,
                                        aws_access_key_id=self.rods_key,
                                        aws_secret_access_key=self.rods_secret_key)

        self.boto3_client_alice = boto3.client('s3',
                                        use_ssl=False,
                                        endpoint_url=self.s3_api_url,
                                        aws_access_key_id=self.alice_key,
                                        aws_secret_access_key=self.alice_secret_key)

    def tearDown(self):
        self.boto3_client_rods.close()
        self.boto3_client_alice.close()

    # ======== Tests =========

    # Note:  Minio mc client does not have a head-object command but this is called behind the
    # scenes on other tests such as list-object.

    def test_botocore_head_bucket_as_rods_user(self):
        # rods can see test-bucket
        head_bucket_result = self.boto3_client_rods.head_bucket(Bucket='test-bucket')
        self.assertEqual(head_bucket_result['ResponseMetadata']['HTTPStatusCode'], 200)

        # rods can see alice-bucket
        head_bucket_result = self.boto3_client_rods.head_bucket(Bucket='alice-bucket')
        self.assertEqual(head_bucket_result['ResponseMetadata']['HTTPStatusCode'], 200)

        # rods can see alice-bucket2
        head_bucket_result = self.boto3_client_rods.head_bucket(Bucket='alice-bucket2')
        self.assertEqual(head_bucket_result['ResponseMetadata']['HTTPStatusCode'], 200)

        # bucket does not exist
        with self.assertRaises(botocore.exceptions.ClientError) as e:
            self.boto3_client_rods.head_bucket(Bucket='bucketdoesnotexist')
        the_exception = e.exception
        self.assertEqual(the_exception.response['ResponseMetadata']['HTTPStatusCode'], 403)

    def test_botocore_head_bucket_as_alice_user(self):
        # alice can't see test-bucket
        with self.assertRaises(botocore.exceptions.ClientError) as e:
            self.boto3_client_alice.head_bucket(Bucket='test-bucket')
        the_exception = e.exception
        self.assertEqual(the_exception.response['ResponseMetadata']['HTTPStatusCode'], 403)

        # alice can see alice-bucket
        head_bucket_result = self.boto3_client_alice.head_bucket(Bucket='alice-bucket')
        self.assertEqual(head_bucket_result['ResponseMetadata']['HTTPStatusCode'], 200)

        # alice can see alice-bucket2
        head_bucket_result = self.boto3_client_alice.head_bucket(Bucket='alice-bucket2')
        self.assertEqual(head_bucket_result['ResponseMetadata']['HTTPStatusCode'], 200)

        # bucket does not exist
        with self.assertRaises(botocore.exceptions.ClientError) as e:
            self.boto3_client_alice.head_bucket(Bucket='bucketdoesnotexist')
        the_exception = e.exception
        self.assertEqual(the_exception.response['ResponseMetadata']['HTTPStatusCode'], 403)
