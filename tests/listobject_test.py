from datetime import datetime
import botocore
import botocore.session
import inspect
import itertools
import os
import socket
import unittest

from host_port import s3_api_host_port
from libs import command, utility


def switch_client_user(username, password):
    client_environment_file = "/root/.irods/irods_environment.json"
    new_client_environment_file = f"/root/.irods/irods_environment.json.{username}"
    command.assert_command(['iexit'])
    command.assert_command(['cp', new_client_environment_file, client_environment_file])
    command.assert_command(['iinit'], 'STDOUT', "Enter your current iRODS password", input=password)


class ListObject_Test(unittest.TestCase):

    # ======== Construction, setUp, tearDown =========
    bucket_irods_path = '/tempZone/home/alice/alice-bucket'
    bucket_name = 'alice-bucket'
    key = 's3_key2'
    secret_key = 's3_secret_key2'
    s3_api_url = f'http://{s3_api_host_port}'

    def __init__(self, *args, **kwargs):
        super(ListObject_Test, self).__init__(*args, **kwargs)

    @classmethod 
    def setUpClass(cls):

        # create collections/data objects
        utility.make_local_file('f1', 100)
        utility.make_local_file('f2', 200)

        command.assert_command(f'imkdir {cls.bucket_irods_path}/dir1')
        command.assert_command(f'iput f1 {cls.bucket_irods_path}/f1')
        command.assert_command(f'iput f1 {cls.bucket_irods_path}/dir1/d1f1')
        command.assert_command(f'iput f2 {cls.bucket_irods_path}/dir1/d1f2')
        command.assert_command(f'imkdir {cls.bucket_irods_path}/dir1/dir1a')
        command.assert_command(f'iput f1 {cls.bucket_irods_path}/dir1/dir1a/d1af1')
        command.assert_command(f'iput f2 {cls.bucket_irods_path}/dir1/dir1a/d1af2')
        command.assert_command(f'imkdir {cls.bucket_irods_path}/dir1/dir1b')
        command.assert_command(f'iput f1 {cls.bucket_irods_path}/dir1/dir1b/d1bf1')
        command.assert_command(f'iput f2 {cls.bucket_irods_path}/dir1/dir1b/d1bf2')
        command.assert_command(f'imkdir {cls.bucket_irods_path}/dir2')

    @classmethod 
    def tearDownClass(cls):
        command.assert_command(f'irm -rf {cls.bucket_irods_path}/f1 {cls.bucket_irods_path}/f2 {cls.bucket_irods_path}/dir1 {cls.bucket_irods_path}/dir2')
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

        command.assert_command('ils -l %s' % self.bucket_irods_path, 'STDOUT') #debug
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
            command.assert_command(f'imkdir {self.bucket_irods_path}/commonkeyprefix_dir')
            command.assert_command(f'iput f1 {self.bucket_irods_path}/commonkeyprefix_f1')
            command.assert_command(f'iput f1 {self.bucket_irods_path}/commonkeyprefix_dir/f1')  # this one will not show up in this query

            listobjects_result = self.client.list_objects_v2(Bucket=self.bucket_name, Delimiter='/', Prefix='commonkeyprefix')
            print(listobjects_result)
            self.assertEqual(len(listobjects_result['Contents']), 1, 'Wrong number of results')
            self.assert_key_in_contents_list(listobjects_result, 'commonkeyprefix_f1')
            self.assertEqual(len(listobjects_result['CommonPrefixes']), 1, 'Wrong number of results')
            self.assert_prefix_in_common_prefixes_list(listobjects_result, 'commonkeyprefix_dir/')

        finally:
            # local cleanup
            command.assert_command(f'irm -rf {self.bucket_irods_path}/commonkeyprefix_dir {self.bucket_irods_path}/commonkeyprefix_f1')

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

    def test_botocore_list_object_with_reserved_characters_in_name(self):
        for character in ['+', ' ', '$', '@', ',', ':', ';', '=', '?', '&']:
            with self.subTest(f"character:[{character}]"):
                put_filename = f'{inspect.currentframe().f_code.co_name}__{character}.data'
                logical_path = f'{self.bucket_irods_path}/{put_filename}'

                try:
                    utility.make_arbitrary_file(put_filename, 100*1024)
                    command.assert_command(['iput', put_filename, logical_path])
                    listobjects_result = self.client.list_objects_v2(Bucket=self.bucket_name)
                    print(listobjects_result)
                    self.assertGreater(len(listobjects_result['Contents']), 6, 'Wrong number of results')
                    self.assert_key_in_contents_list(listobjects_result, put_filename)

                finally:
                    command.assert_command(['ils', '-l', self.bucket_irods_path], 'STDOUT') # debugging
                    if os.path.exists(put_filename):
                        os.remove(put_filename)
                    command.assert_command(['irm', '-f', logical_path])

    def test_aws_list_with_delimiter_no_prefix(self):
        command.assert_command(f'aws --profile s3_api_alice --endpoint-url {self.s3_api_url} s3 ls s3://{self.bucket_name}/',
                'STDOUT_MULTILINE', ['f1', 'dir1/', 'dir2/'])

    def test_aws_list_with_delimiter_prefix_ending_with_slash(self):

        # With a delimiter and ending in a slash, this works just like a directory listing
        # Example:   A search for prefix "dir1/" will only show collections and files directly
        # under dir1.
        command.assert_command(f'aws --profile s3_api_alice --endpoint-url {self.s3_api_url} s3 ls s3://{self.bucket_name}/dir1/',
                'STDOUT_MULTILINE', ['d1f1', 'd1f2', 'dir1a/', 'dir1b/'])

        command.assert_command(f'aws --profile s3_api_alice --endpoint-url {self.s3_api_url} s3 ls s3://{self.bucket_name}/dir1/dir1a/',
                'STDOUT_MULTILINE', ['d1af1', 'd1af2'])

    def test_aws_list_with_delimiter_prefix_no_slash(self):

        try:
            # With a delimiter and not ending in a slash, this will return all keys beginning with the common
            # prefix but will not descend into collections
            command.assert_command(f'imkdir {self.bucket_irods_path}/commonkeyprefix_dir')
            command.assert_command(f'iput f1 {self.bucket_irods_path}/commonkeyprefix_f1')
            command.assert_command(f'iput f1 {self.bucket_irods_path}/commonkeyprefix_dir/f1')  # this one will not show up in this query

            command.assert_command(f'aws --profile s3_api_alice --endpoint-url {self.s3_api_url} s3 ls s3://{self.bucket_name}/commonkeyprefix',
                    'STDOUT_MULTILINE', ['commonkeyprefix_f1', 'commonkeyprefix_dir'])

        finally:
            # local cleanup
            command.assert_command(f'irm -rf {self.bucket_irods_path}/commonkeyprefix_dir {self.bucket_irods_path}/commonkeyprefix_f1')

    def test_aws_list_no_delimiter(self):

        # With no delimiter, it is simply a key prefix search.  Since the delimiter does not exist, the search will 
        # descend into all objects.
        command.assert_command(f'aws --profile s3_api_alice --endpoint-url {self.s3_api_url} s3 ls --recursive s3://{self.bucket_name}/di',
                'STDOUT_MULTILINE', ['dir1/d1f1', 'dir1/d1f2', 'dir1/dir1a/d1af1', 'dir1/dir1a/d1af2', 'dir1/dir1b/d1bf1', 'dir1/dir1b/d1bf2'])

    def test_aws_list_nothing_found(self):
        _, out, _ = command.assert_command(f'aws --profile s3_api_alice --endpoint-url {self.s3_api_url} s3 ls --recursive s3://{self.bucket_name}/doesnotexist')
        self.assertEqual(len(out), 0)

    def test_aws_list_object_with_reserved_characters_in_name(self):
        for character in ['+', ' ', '$', '@', ',', ':', ';', '=', '?', '&']:
            with self.subTest(f"character:[{character}]"):
                put_filename = f'{inspect.currentframe().f_code.co_name}__{character}.data'
                logical_path = f'{self.bucket_irods_path}/{put_filename}'

                try:
                    utility.make_arbitrary_file(put_filename, 100*1024)
                    command.assert_command(['iput', put_filename, logical_path])
                    command.assert_command(
                        [
                            'aws',
                            '--profile',
                            's3_api_alice',
                            '--endpoint-url',
                            self.s3_api_url,
                            's3',
                            'ls',
                            f's3://{self.bucket_name}'
                        ],
                        'STDOUT',
                        put_filename)

                finally:
                    command.assert_command(['ils', '-l', self.bucket_irods_path], 'STDOUT') # debugging
                    if os.path.exists(put_filename):
                        os.remove(put_filename)
                    command.assert_command(['irm', '-f', logical_path])

    def test_mc_list_with_delimiter_no_prefix(self):
        command.assert_command(f'mc ls s3-api-alice/{self.bucket_name}/',
                'STDOUT_MULTILINE', ['f1', 'dir1/', 'dir2/'])

    def test_mc_list_with_delimiter_prefix_ending_with_slash(self):

        # With a delimiter and ending in a slash, this works just like a directory listing
        # Example:   A search for prefix "dir1/" will only show collections and files directly
        # under dir1.
        command.assert_command(f'mc ls s3-api-alice/{self.bucket_name}/dir1/',
                'STDOUT_MULTILINE', ['d1f1', 'd1f2', 'dir1a/', 'dir1b/'])

        command.assert_command(f'mc ls s3-api-alice/{self.bucket_name}/dir1/dir1a/',
                'STDOUT_MULTILINE', ['d1af1', 'd1af2'])

    def test_mc_list_with_delimiter_prefix_no_slash(self):

        try:
            # With a delimiter and not ending in a slash, this will return all keys beginning with the common
            # prefix but will not descend into collections
            command.assert_command(f'imkdir {self.bucket_irods_path}/commonkeyprefix_dir')
            command.assert_command(f'iput f1 {self.bucket_irods_path}/commonkeyprefix_f1')
            command.assert_command(f'iput f1 {self.bucket_irods_path}/commonkeyprefix_dir/f1')  # this one will not show up in this query

            command.assert_command(f'mc ls s3-api-alice/{self.bucket_name}/commonkeyprefix',
                    'STDOUT_MULTILINE', ['commonkeyprefix_f1', 'commonkeyprefix_dir'])

        finally:
            # local cleanup
            command.assert_command(f'irm -rf {self.bucket_irods_path}/commonkeyprefix_dir {self.bucket_irods_path}/commonkeyprefix_f1')

    @unittest.skip('mc client is setting a delimiter even with the --recursive flag set')
    def test_mc_list_no_delimiter(self):
        pass

    def test_mc_list_nothing_found(self):
        _, out, _ = command.assert_command(f'mc ls s3-api-alice/{self.bucket_name}/doesnotexist')
        self.assertEqual(len(out), 0)

    def test_mc_list_object_with_reserved_characters_in_name(self):
        for character in ['+', ' ', '$', '@', ',', ':', ';', '=', '?', '&']:
            with self.subTest(f"character:[{character}]"):
                put_filename = f'{inspect.currentframe().f_code.co_name}__{character}.data'
                logical_path = f'{self.bucket_irods_path}/{put_filename}'

                try:
                    utility.make_arbitrary_file(put_filename, 100*1024)
                    command.assert_command(['iput', put_filename, logical_path])
                    command.assert_command(['mc', 'ls', f's3-api-alice/{self.bucket_name}/'], 'STDOUT', put_filename)

                finally:
                    command.assert_command(['ils', '-l', self.bucket_irods_path], 'STDOUT') # debugging
                    if os.path.exists(put_filename):
                        os.remove(put_filename)
                    command.assert_command(['irm', '-f', logical_path])


class ListObject_with_Multiple_Replicas_Test(unittest.TestCase):
    bucket_irods_path = '/tempZone/home/alice/alice-bucket'
    bucket_name = 'alice-bucket'
    key = 's3_key2'
    secret_key = 's3_secret_key2'
    s3_api_url = f'http://{s3_api_host_port}'

    test_resources = [f's3_ufs{n}' for n in range(1, 3)]
    collection_name = 'issue_223_coll'
    put_filename = 'issue_223.data'
    collection_path = f'{bucket_irods_path}/{collection_name}'
    logical_path = f'{collection_path}/{put_filename}'
    repl0_size = 100
    repl1_size = 101
    repl2_size = 102

    def __init__(self, *args, **kwargs):
        super(ListObject_with_Multiple_Replicas_Test, self).__init__(*args, **kwargs)

    @classmethod
    def setUpClass(self):
        # Create a test collection.
        command.assert_command(['imkdir', self.collection_path])

        # Create a test data object.
        utility.make_arbitrary_file(self.put_filename, self.repl0_size)
        command.assert_command(['iput', self.put_filename, self.logical_path])

        # Switch to the rodsadmin user. To avoid switching back and forth, these tests will be run as the rodsadmin
        # user so that we can precisely manipulate replica information without moving data or sleeping.
        switch_client_user("rods", "rods")

        # Create some test resources to which the data object created above can be replicated.
        resc_host = 'irods-catalog-provider'
        for resc in self.test_resources:
            command.assert_command(
                ['iadmin', 'mkresc', resc, 'unixfilesystem', f'{resc_host}:/tmp/{resc}_vault'],
                "STDOUT", resc)

        # Replicate to the test resource so that there are multiple replicas.
        for resc in self.test_resources:
            command.assert_command(['irepl', '-M', '-R', resc, self.logical_path])

        # Change the replica sizes so that they are all unique. This helps to easily identify them in the S3 listings.
        command.assert_command(
            ["iadmin", "modrepl", "logical_path", self.logical_path, "replica_number", str(1), "DATA_SIZE", str(self.repl1_size)])
        command.assert_command(
            ["iadmin", "modrepl", "logical_path", self.logical_path, "replica_number", str(2), "DATA_SIZE", str(self.repl2_size)])

        # Create a client connection for botocore.
        session = botocore.session.get_session()
        self.client = session.create_client(
            's3', use_ssl=False, endpoint_url=self.s3_api_url, aws_access_key_id=self.key, aws_secret_access_key=self.secret_key)

    @classmethod
    def tearDownClass(self):
        # Switch to the rodsuser and remove the test data.
        switch_client_user("alice", "apass")
        command.assert_command(['rm', '-f', self.put_filename])
        command.assert_command(['irm', '-rf', self.collection_path])

        # Remove the test resources.
        switch_client_user("rods", "rods")
        for resc in self.test_resources:
            command.assert_command(['iadmin', 'rmresc', resc])

        # Switch back to the rodsuser because the other tests expect to be the rodsuser.
        switch_client_user("alice", "apass")

    def do_test(self, replica_info, index_of_expected_replica, case_name=None):
        """Assert that the replica information provided results in the expected listing from various S3 clients.

        Args:
            replica_info: A list of dicts containing desired state of the 3 test replicas in this format:
                {"number": 0, "status": 0, "mtime": 1000, "size": 1000}
            index_of_expected_replica: The index of the replica expected to be selected.
            case_name: Identifier for the test case. Default: e.g. "status:[0, 0, 0],mtime:[1000, 1000, 1000]"
        """
        try:
            # Set all the replica statuses and sizes as specified in the dict.
            for repl in replica_info:
                repl_num = str(repl["number"])
                status = str(repl["status"])
                mtime = str(repl["mtime"])
                command.assert_command(
                    ["iadmin", "modrepl", "logical_path", self.logical_path, "replica_number", repl_num, "DATA_REPL_STATUS", status])
                command.assert_command(
                    ["iadmin", "modrepl", "logical_path", self.logical_path, "replica_number", repl_num, "DATA_MODIFY_TIME", mtime])

            # If no case name is provided, generate one which shows the replica statuses and mtimes.
            if case_name is None:
                case_name = (
                    f'status:{[repl["status"] for repl in replica_info]},'
                    f'mtime:{[repl["mtime"] for repl in replica_info]}'
                )

            expected_repl = replica_info[index_of_expected_replica]

            # Confirm that the object is only listed once and uses info from the most-recently-updated replica.

            # Test with the Minio CLI.
            mc_targets = [
                f's3-api-alice/{self.bucket_name}/{self.collection_name}/{self.put_filename}',
                f's3-api-alice/{self.bucket_name}/{self.collection_name}/'
            ]
            for target in mc_targets:
                with self.subTest(f'mc ls {target}, case [{case_name}]'):
                    _, out, _ = command.assert_command(['mc', 'ls', target], 'STDOUT', self.put_filename)
                    for i, repl in enumerate(replica_info):
                        repl = replica_info[i]
                        if index_of_expected_replica == i:
                            self.assertIn(f'{repl["size"]}B STANDARD', out)
                        else:
                            self.assertNotIn(f'{repl["size"]}B STANDARD', out)

            # Test with the AWS CLI.
            # TODO(#99): For some reason, these commands are taking >1 second to complete.
            aws_targets = [
                f's3://{self.bucket_name}/{self.collection_name}/{self.put_filename}',
                f's3://{self.bucket_name}/{self.collection_name}/'
            ]
            for target in aws_targets:
                with self.subTest(f'aws s3 ls {target}, case [{case_name}]'):
                    # List the data object...
                    _, out, _ = command.assert_command(
                        [
                            'aws',
                            '--profile',
                            's3_api_alice',
                            '--endpoint-url',
                            self.s3_api_url,
                            's3',
                            'ls',
                            target
                        ],
                        'STDOUT',
                        self.put_filename)
                    for i, repl in enumerate(replica_info):
                        if index_of_expected_replica == i:
                            self.assertIn(f'{repl["size"]} {self.put_filename}', out)
                        else:
                            self.assertNotIn(f'{repl["size"]} {self.put_filename}', out)

            # Test with the botocore client. This one only lists the object (rather than the object and the collection)
            # because the list_objects_v2 interface does not allow for listing the objects in the collection.
            target = f'{self.collection_name}/{self.put_filename}'
            with self.subTest(f'botocore list_objects_v2 prefix={target}, case [{case_name}]'):
                listobjects_result = self.client.list_objects_v2(Bucket=self.bucket_name, Prefix=target)
                print(listobjects_result) # debugging
                self.assertEqual(len(listobjects_result['Contents']), 1)
                # Assert that the key and expected replica size are in the contents list.
                for entry in listobjects_result['Contents']:
                    if entry['Key'] == target:
                        self.assertIsNotNone(entry.get('Key'), f'Key not found [{target}]')
                        self.assertIsNotNone(entry.get('LastModified'), f'LastModified is not found for key {target}')
                        size = entry.get('Size')
                        self.assertIsNotNone(size, f'Size not found for key [{target}]')
                        self.assertEqual(
                            size,
                            replica_info[index_of_expected_replica]["size"],
                            f'Size does not match for key {target}')
                        break

        finally:
            command.assert_command(['ils', '-Lr'], 'STDOUT') # debugging

    def do_list_object_with_multiple_replicas_only_shows_one_s3_object_per_irods_object_test(
        self, status_tuple, expected_selected_replica_indexes
    ):
        """Run test for ListObjectsV2 to demonstrate that iRODS objects with multiple replicas only show 1 S3 object.

        Args:
            status_tuple: A triple with integers representing the 3 replica statuses.
            expected_selected_replica_indexes: A list of integers with the expected replica indexes.
        """
        # There are 27 cases for each of the 8 combinations of replica statuses, so make sure the expected indexes
        # list is the right length.
        self.assertEqual(27, len(expected_selected_replica_indexes))

        repl0_status, repl1_status, repl2_status = status_tuple
        replica_info = [
            {"number": 0, "status": repl0_status, "mtime": 1000, "size": self.repl0_size},
            {"number": 1, "status": repl1_status, "mtime": 1000, "size": self.repl1_size},
            {"number": 2, "status": repl2_status, "mtime": 1000, "size": self.repl2_size},
        ]

        expected_index = itertools.count()

        # Replica 0 has lowest mtime.

        replica_info[0]["mtime"] = str(1000)

        replica_info[1]["mtime"] = str(1000)
        replica_info[2]["mtime"] = str(1000)
        self.do_test(replica_info, expected_selected_replica_indexes[next(expected_index)])
        replica_info[2]["mtime"] = str(1001)
        self.do_test(replica_info, expected_selected_replica_indexes[next(expected_index)])
        replica_info[2]["mtime"] = str(1002)
        self.do_test(replica_info, expected_selected_replica_indexes[next(expected_index)])

        replica_info[1]["mtime"] = str(1001)
        replica_info[2]["mtime"] = str(1000)
        self.do_test(replica_info, expected_selected_replica_indexes[next(expected_index)])
        replica_info[2]["mtime"] = str(1001)
        self.do_test(replica_info, expected_selected_replica_indexes[next(expected_index)])
        replica_info[2]["mtime"] = str(1002)
        self.do_test(replica_info, expected_selected_replica_indexes[next(expected_index)])

        replica_info[1]["mtime"] = str(1002)
        replica_info[2]["mtime"] = str(1000)
        self.do_test(replica_info, expected_selected_replica_indexes[next(expected_index)])
        replica_info[2]["mtime"] = str(1001)
        self.do_test(replica_info, expected_selected_replica_indexes[next(expected_index)])
        replica_info[2]["mtime"] = str(1002)
        self.do_test(replica_info, expected_selected_replica_indexes[next(expected_index)])

        # Replica 0 has middle mtime.

        replica_info[0]["mtime"] = str(1001)

        replica_info[1]["mtime"] = str(1000)
        replica_info[2]["mtime"] = str(1000)
        self.do_test(replica_info, expected_selected_replica_indexes[next(expected_index)])
        replica_info[2]["mtime"] = str(1001)
        self.do_test(replica_info, expected_selected_replica_indexes[next(expected_index)])
        replica_info[2]["mtime"] = str(1002)
        self.do_test(replica_info, expected_selected_replica_indexes[next(expected_index)])

        replica_info[1]["mtime"] = str(1001)
        replica_info[2]["mtime"] = str(1000)
        self.do_test(replica_info, expected_selected_replica_indexes[next(expected_index)])
        replica_info[2]["mtime"] = str(1001)
        self.do_test(replica_info, expected_selected_replica_indexes[next(expected_index)])
        replica_info[2]["mtime"] = str(1002)
        self.do_test(replica_info, expected_selected_replica_indexes[next(expected_index)])

        replica_info[1]["mtime"] = str(1002)
        replica_info[2]["mtime"] = str(1000)
        self.do_test(replica_info, expected_selected_replica_indexes[next(expected_index)])
        replica_info[2]["mtime"] = str(1001)
        self.do_test(replica_info, expected_selected_replica_indexes[next(expected_index)])
        replica_info[2]["mtime"] = str(1002)
        self.do_test(replica_info, expected_selected_replica_indexes[next(expected_index)])

        # Replica 0 has largest mtime.

        replica_info[0]["mtime"] = str(1002)

        replica_info[1]["mtime"] = str(1000)
        replica_info[2]["mtime"] = str(1000)
        self.do_test(replica_info, expected_selected_replica_indexes[next(expected_index)])
        replica_info[2]["mtime"] = str(1001)
        self.do_test(replica_info, expected_selected_replica_indexes[next(expected_index)])
        replica_info[2]["mtime"] = str(1002)
        self.do_test(replica_info, expected_selected_replica_indexes[next(expected_index)])

        replica_info[1]["mtime"] = str(1001)
        replica_info[2]["mtime"] = str(1000)
        self.do_test(replica_info, expected_selected_replica_indexes[next(expected_index)])
        replica_info[2]["mtime"] = str(1001)
        self.do_test(replica_info, expected_selected_replica_indexes[next(expected_index)])
        replica_info[2]["mtime"] = str(1002)
        self.do_test(replica_info, expected_selected_replica_indexes[next(expected_index)])

        replica_info[1]["mtime"] = str(1002)
        replica_info[2]["mtime"] = str(1000)
        self.do_test(replica_info, expected_selected_replica_indexes[next(expected_index)])
        replica_info[2]["mtime"] = str(1001)
        self.do_test(replica_info, expected_selected_replica_indexes[next(expected_index)])
        replica_info[2]["mtime"] = str(1002)
        self.do_test(replica_info, expected_selected_replica_indexes[next(expected_index)])

    def test_repl0_good_repl1_good_repl2_good(self):
        # cases 1-27
        self.do_list_object_with_multiple_replicas_only_shows_one_s3_object_per_irods_object_test(
            (1, 1, 1),
            [0, 2, 2, 1, 1, 2, 1, 1, 1, 0, 0, 2, 0, 0, 2, 1, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0]
        )

    def test_repl0_good_repl1_good_repl2_stale(self):
        # cases 28-54
        self.do_list_object_with_multiple_replicas_only_shows_one_s3_object_per_irods_object_test(
            (1, 1, 0),
            [0, 0, 0, 1, 1, 1, 1, 1, 1, 0, 0, 0, 0, 0, 0, 1, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0]
        )

    def test_repl0_good_repl1_stale_repl2_good(self):
        # cases 55-81
        self.do_list_object_with_multiple_replicas_only_shows_one_s3_object_per_irods_object_test(
            (1, 0, 1),
            [0, 2, 2, 0, 2, 2, 0, 2, 2, 0, 0, 2, 0, 0, 2, 0, 0, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0]
        )

    def test_repl0_good_repl1_stale_repl2_stale(self):
        # cases 82-108
        self.do_list_object_with_multiple_replicas_only_shows_one_s3_object_per_irods_object_test(
            (1, 0, 0),
            [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
        )

    def test_repl0_stale_repl1_good_repl2_good(self):
        # cases 109-135
        self.do_list_object_with_multiple_replicas_only_shows_one_s3_object_per_irods_object_test(
            (0, 1, 1),
            [1, 2, 2, 1, 1, 2, 1, 1, 1, 1, 2, 2, 1, 1, 2, 1, 1, 1, 1, 2, 2, 1, 1, 2, 1, 1, 1]
        )

    def test_repl0_stale_repl1_good_repl2_stale(self):
        # cases 136-162
        self.do_list_object_with_multiple_replicas_only_shows_one_s3_object_per_irods_object_test(
            (0, 1, 0),
            [1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1]
        )

    def test_repl0_stale_repl1_stale_repl2_good(self):
        # cases 163-189
        self.do_list_object_with_multiple_replicas_only_shows_one_s3_object_per_irods_object_test(
            (0, 0, 1),
            [2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2]
        )

    def test_repl0_stale_repl1_stale_repl2_stale(self):
        # cases 190-216
        self.do_list_object_with_multiple_replicas_only_shows_one_s3_object_per_irods_object_test(
            (0, 0, 0),
            [0, 2, 2, 1, 1, 2, 1, 1, 1, 0, 0, 2, 0, 0, 2, 1, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0]
        )
