import unittest
import subprocess as sp
import botocore
import botocore.session
from tests.utility import *


class TestDeleteObject(unittest.TestCase):
    def setUp(self):
        session = botocore.session.get_session()
        self.client = session.create_client("s3",
                                            use_ssl=False,
                                            endpoint_url="http://127.0.0.1:8080",  # normal networking stuff :p
                                            aws_access_key_id="no",
                                            aws_secret_access_key="heck")
        set_access("", 'own', recursive=True)
        mkdir("", access_level="own")

    def test_permission(self):
        try:
            mkdir("unavailable", access_level="own")
            touch_file("unavailable/hello", access_level="read_metadata")
            self.assertRaises(Exception,
                              lambda: self.client.delete_object(Bucket="wow", Key="test/unavailable/hello"))
            set_access("unavailable/hello", "own")
            self.client.delete_object(Bucket="wow", Key="test/unavailable/hello")
            self.assertRaises(Exception, lambda: read_file(self.client, "unavailable/hello"))
        finally:
            set_access("unavailable", "own", recursive=True)
            remove_file(self.client, "unavailable", recursive=True)

    def tearDown(self) -> None:
        self.client.close()
