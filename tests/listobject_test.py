import unittest
import botocore
import botocore.session
import os
from libs.execute import *
from libs.command import *
from libs.utility import *
from datetime import datetime

class ListObject_Test(TestCase):

    # ======== Construction, setUp, tearDown =========
    bucket_irods_path = '/tempZone/home/alice/alice-bucket'
    bucket_name = 'alice-bucket'
    key = 's3_key2'
    secret_key = 's3_secret_key2'
    s3_api_url = 'http://s3-api:8080'

    def __init__(self, *args, **kwargs):
        super(ListObject_Test, self).__init__(*args, **kwargs)

    @classmethod 
    def setUpClass(cls):

        # create collections/data objects
        make_local_file('f1', 100)
        make_local_file('f2', 200)

        assert_command(f'imkdir {cls.bucket_irods_path}/dir1')
        assert_command(f'iput f1 {cls.bucket_irods_path}/f1')
        assert_command(f'iput f1 {cls.bucket_irods_path}/dir1/d1f1')
        assert_command(f'iput f2 {cls.bucket_irods_path}/dir1/d1f2')
        assert_command(f'imkdir {cls.bucket_irods_path}/dir1/dir1a')
        assert_command(f'iput f1 {cls.bucket_irods_path}/dir1/dir1a/d1af1')
        assert_command(f'iput f2 {cls.bucket_irods_path}/dir1/dir1a/d1af2')
        assert_command(f'imkdir {cls.bucket_irods_path}/dir1/dir1b')
        assert_command(f'iput f1 {cls.bucket_irods_path}/dir1/dir1b/d1bf1')
        assert_command(f'iput f2 {cls.bucket_irods_path}/dir1/dir1b/d1bf2')
        assert_command(f'imkdir {cls.bucket_irods_path}/dir2')

    @classmethod 
    def tearDownClass(cls):
        assert_command(f'irm -rf {cls.bucket_irods_path}/f1 {cls.bucket_irods_path}/f2 {cls.bucket_irods_path}/dir1 {cls.bucket_irods_path}/dir2')
        os.remove('f1')
        os.remove('f2')

    def setUp(self):
        session = botocore.session.get_session()
        self.client = session.create_client('s3',
                                            use_ssl=False,
                                            endpoint_url=self.s3_api_url,
                                            aws_access_key_id=self.key,
                                            aws_secret_access_key=self.secret_key)
    def tearDown(self):
        pass

    # ======== Helper Functions =========

    # used to assert keys are in the contents list returned by botocore
    # possibly checking the size and LastModified time.
    def assert_key_in_contents_list(self, list_objects_result, key, size=None, lastmodified=None):
        contents_list = list_objects_result['Contents']
        matching_key = None
        matching_size = None
        matching_lastmodified = None
        for entry in contents_list:
            if entry['Key'] == key:
                matching_key = entry['Key']
                matching_size = entry['Size']
                matching_lastmodified = entry['LastModified']
                break
    
        self.assertIsNotNone(matching_key, f'Key not found [{key}]')
        self.assertIsNotNone(matching_size, f'Size not found for key [{key}]')
        self.assertIsNotNone(matching_lastmodified, f'LastModified is not found for key {key}')
        if size != None:
            self.assertEqual(matching_size, size, f'Size does not match for key {key}')
        if lastmodified != None:
            # Only checking year/month/day.  This could fail if the time between
            # writing the file to iRODS and  getting the current datetime object
            # rolled over to a new day.
            self.assertEqual(matching_lastmodified.year, lastmodified.year, f'Year does not match for key {key}') 
            self.assertEqual(matching_lastmodified.month, lastmodified.month, f'Month does not match for key {key}')
            self.assertEqual(matching_lastmodified.day,  lastmodified.day, f'Day does not match for key {key}')
    
    # used to assert keys are in the CommonPrefixes list returned by botocore
    def assert_prefix_in_common_prefixes_list(self, list_objects_result, prefix):
        common_prefixes_list = list_objects_result['CommonPrefixes']
        matching_key = None
        for entry in common_prefixes_list:
            if entry['Prefix'] == prefix:
                matching_key = entry['Prefix']
        self.assertIsNotNone(matching_key, f'Prefix [{prefix}] not found')

    # ======== Tests =========

    def test_botocore_list_with_delimiter_no_prefix(self):
        listobjects_result = self.client.list_objects_v2(Bucket=self.bucket_name, Delimiter='/')
        print(listobjects_result)

        assert_command('ils -l %s' % self.bucket_irods_path, 'STDOUT') #debug
        current_time = datetime.now()
        self.assertEqual(len(listobjects_result['Contents']), 1, 'Wrong number of results')
        self.assert_key_in_contents_list(listobjects_result, 'f1', size=100, lastmodified=current_time)

        self.assertEqual(len(listobjects_result['CommonPrefixes']), 2, 'Wrong number of results')
        self.assert_prefix_in_common_prefixes_list(listobjects_result, 'dir1/')
        self.assert_prefix_in_common_prefixes_list(listobjects_result, 'dir2/')

    def test_botocore_list_with_delimiter_prefix_ending_with_slash(self):

        # With a delimiter and ending in a slash, this works just like a directory listing
        # Example:   A search for prefix "dir1/" will only show collections and files directly
        # under dir1.
        listobjects_result = self.client.list_objects_v2(Bucket=self.bucket_name, Delimiter='/', Prefix='dir1/')
        self.assertEqual(len(listobjects_result['Contents']), 2, 'Wrong number of results')
        self.assert_key_in_contents_list(listobjects_result, 'dir1/d1f1', size=100)
        self.assert_key_in_contents_list(listobjects_result, 'dir1/d1f2', size=200)
        self.assertEqual(len(listobjects_result['CommonPrefixes']), 2, 'Wrong number of results')
        self.assert_prefix_in_common_prefixes_list(listobjects_result, 'dir1/dir1a/')
        self.assert_prefix_in_common_prefixes_list(listobjects_result, 'dir1/dir1b/')

        listobjects_result = self.client.list_objects_v2(Bucket=self.bucket_name, Delimiter='/', Prefix='dir1/dir1a/')
        print(listobjects_result)
        self.assertEqual(len(listobjects_result['Contents']), 2, 'Wrong number of results')
        self.assert_key_in_contents_list(listobjects_result, 'dir1/dir1a/d1af1')
        self.assert_key_in_contents_list(listobjects_result, 'dir1/dir1a/d1af2')

    def test_botocore_list_with_delimiter_prefix_no_slash(self):
        try:
            # With a delimiter and not ending in a slash, this will return all keys beginning with the common
            # prefix but will not descend into collections
            assert_command(f'imkdir {self.bucket_irods_path}/commonkeyprefix_dir')
            assert_command(f'iput f1 {self.bucket_irods_path}/commonkeyprefix_f1')
            assert_command(f'iput f1 {self.bucket_irods_path}/commonkeyprefix_dir/f1')  # this one will not show up in this query

            listobjects_result = self.client.list_objects_v2(Bucket=self.bucket_name, Delimiter='/', Prefix='commonkeyprefix')
            print(listobjects_result)
            self.assertEqual(len(listobjects_result['Contents']), 1, 'Wrong number of results')
            self.assert_key_in_contents_list(listobjects_result, 'commonkeyprefix_f1')
            self.assertEqual(len(listobjects_result['CommonPrefixes']), 1, 'Wrong number of results')
            self.assert_prefix_in_common_prefixes_list(listobjects_result, 'commonkeyprefix_dir/')

        finally:
            # local cleanup
            assert_command(f'irm -rf {self.bucket_irods_path}/commonkeyprefix_dir {self.bucket_irods_path}/commonkeyprefix_f1')

    def test_botocore_list_no_delimiter(self):

       # With no delimiter this will return all keys beginning with the common prefix and will descend into all collections

       listobjects_result = self.client.list_objects_v2(Bucket=self.bucket_name, Prefix='di')
       print(listobjects_result)
       self.assertEqual(len(listobjects_result['Contents']), 6, 'Wrong number of results')
       self.assert_key_in_contents_list(listobjects_result, 'dir1/d1f1')
       self.assert_key_in_contents_list(listobjects_result, 'dir1/d1f2')
       self.assert_key_in_contents_list(listobjects_result, 'dir1/dir1a/d1af1')
       self.assert_key_in_contents_list(listobjects_result, 'dir1/dir1a/d1af2')
       self.assert_key_in_contents_list(listobjects_result, 'dir1/dir1b/d1bf1')
       self.assert_key_in_contents_list(listobjects_result, 'dir1/dir1b/d1bf2')

       # No common prefixes when there isn't a delimiter
       self.assertRaises(KeyError, lambda: listobjects_result['CommonPrefixes'])

    def test_botocore_list_nothing_found(self):
       listobjects_result = self.client.list_objects_v2(Bucket=self.bucket_name, Prefix='doesnotexist')
       print(listobjects_result)
       self.assertRaises(KeyError, lambda: listobjects_result['Contents'])

    def test_aws_list_with_delimiter_no_prefix(self):
        assert_command(f'aws --profile s3_api_alice --endpoint-url {self.s3_api_url} s3 ls s3://{self.bucket_name}/',
                'STDOUT_MULTILINE', ['f1', 'dir1/', 'dir2/'])

    def test_aws_list_with_delimiter_prefix_ending_with_slash(self):

        # With a delimiter and ending in a slash, this works just like a directory listing
        # Example:   A search for prefix "dir1/" will only show collections and files directly
        # under dir1.
        assert_command(f'aws --profile s3_api_alice --endpoint-url {self.s3_api_url} s3 ls s3://{self.bucket_name}/dir1/',
                'STDOUT_MULTILINE', ['d1f1', 'd1f2', 'dir1a/', 'dir1b/'])

        assert_command(f'aws --profile s3_api_alice --endpoint-url {self.s3_api_url} s3 ls s3://{self.bucket_name}/dir1/dir1a/',
                'STDOUT_MULTILINE', ['d1af1', 'd1af2'])

    def test_aws_list_with_delimiter_prefix_no_slash(self):

        try:
            # With a delimiter and not ending in a slash, this will return all keys beginning with the common
            # prefix but will not descend into collections
            assert_command(f'imkdir {self.bucket_irods_path}/commonkeyprefix_dir')
            assert_command(f'iput f1 {self.bucket_irods_path}/commonkeyprefix_f1')
            assert_command(f'iput f1 {self.bucket_irods_path}/commonkeyprefix_dir/f1')  # this one will not show up in this query

            assert_command(f'aws --profile s3_api_alice --endpoint-url {self.s3_api_url} s3 ls s3://{self.bucket_name}/commonkeyprefix',
                    'STDOUT_MULTILINE', ['commonkeyprefix_f1', 'commonkeyprefix_dir'])

        finally:
            # local cleanup
            assert_command(f'irm -rf {self.bucket_irods_path}/commonkeyprefix_dir {self.bucket_irods_path}/commonkeyprefix_f1')

    def test_aws_list_no_delimiter(self):

        # With no delimiter, it is simply a key prefix search.  Since the delimiter does not exist, the search will 
        # descend into all objects.
        assert_command(f'aws --profile s3_api_alice --endpoint-url {self.s3_api_url} s3 ls --recursive s3://{self.bucket_name}/di',
                'STDOUT_MULTILINE', ['dir1/d1f1', 'dir1/d1f2', 'dir1/dir1a/d1af1', 'dir1/dir1a/d1af2', 'dir1/dir1b/d1bf1', 'dir1/dir1b/d1bf2'])

    def test_aws_list_nothing_found(self):
        _, out, _ = assert_command(f'aws --profile s3_api_alice --endpoint-url {self.s3_api_url} s3 ls --recursive s3://{self.bucket_name}/doesnotexist')
        self.assertEqual(len(out), 0)

    def test_mc_list_with_delimiter_no_prefix(self):
        assert_command(f'mc ls s3-api-alice/{self.bucket_name}/',
                'STDOUT_MULTILINE', ['f1', 'dir1/', 'dir2/'])

    def test_mc_list_with_delimiter_prefix_ending_with_slash(self):

        # With a delimiter and ending in a slash, this works just like a directory listing
        # Example:   A search for prefix "dir1/" will only show collections and files directly
        # under dir1.
        assert_command(f'mc ls s3-api-alice/{self.bucket_name}/dir1/',
                'STDOUT_MULTILINE', ['d1f1', 'd1f2', 'dir1a/', 'dir1b/'])

        assert_command(f'mc ls s3-api-alice/{self.bucket_name}/dir1/dir1a/',
                'STDOUT_MULTILINE', ['d1af1', 'd1af2'])

    def test_mc_list_with_delimiter_prefix_no_slash(self):

        try:
            # With a delimiter and not ending in a slash, this will return all keys beginning with the common
            # prefix but will not descend into collections
            assert_command(f'imkdir {self.bucket_irods_path}/commonkeyprefix_dir')
            assert_command(f'iput f1 {self.bucket_irods_path}/commonkeyprefix_f1')
            assert_command(f'iput f1 {self.bucket_irods_path}/commonkeyprefix_dir/f1')  # this one will not show up in this query

            assert_command(f'mc ls s3-api-alice/{self.bucket_name}/commonkeyprefix',
                    'STDOUT_MULTILINE', ['commonkeyprefix_f1', 'commonkeyprefix_dir'])

        finally:
            # local cleanup
            assert_command(f'irm -rf {self.bucket_irods_path}/commonkeyprefix_dir {self.bucket_irods_path}/commonkeyprefix_f1')

    @unittest.skip('mc client is setting a delimiter even with the --recursive flag set')
    def test_mc_list_no_delimiter(self):
        pass

    def test_mc_list_nothing_found(self):
        _, out, _ = assert_command(f'mc ls s3-api-alice/{self.bucket_name}/doesnotexist')
        self.assertEqual(len(out), 0)
