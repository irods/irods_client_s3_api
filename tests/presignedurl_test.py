from host_port import s3_api_host_port
from libs.command import *
from libs.execute import *
from libs.utility import *
from minio import Minio
from unittest import *
import datetime
import os
import requests

class PresignedURL_Test(TestCase):
    bucket_irods_path = '/tempZone/home/alice/alice-bucket'
    bucket_name = 'alice-bucket'
    key = 's3_key2'
    secret_key = 's3_secret_key2'

    def __init__(self, *args, **kwargs):
        super(PresignedURL_Test, self).__init__(*args, **kwargs)

    def setUp(self):
        self.minio_client = Minio(s3_api_host_port,
                                  access_key=self.key,
                                  secret_key=self.secret_key,
                                  secure=False)

    def tearDown(self):
        pass

    def test_minio_get_presigned_url_in_bucket_root_small_file(self):
        put_filename = "test_minio_get_presigned_url_in_bucket_root_small_file"
        get_filename = f"{put_filename}.get"

        try:
            # Put some data into iRODS.
            make_arbitrary_file(put_filename, 100*1024)
            assert_command(f"iput {put_filename} {self.bucket_irods_path}/{put_filename}")

            # Generate a presigned URL to download the data object.
            url_expiration_seconds = 5
            url_string = self.minio_client.presigned_get_object(
                self.bucket_name, put_filename, expires=datetime.timedelta(seconds=url_expiration_seconds)
            )

            # Then, use requests.get to get the file using the URL and write it to get_filename.
            response = requests.get(url_string)
            self.assertEqual(response.status_code, 200)
            with open(get_filename, "wb") as fd:
                fd.write(response.content)

            # Compare the put file and get file.
            assert_command(f'diff -q {put_filename} {get_filename}')

            # Sleep long enough to let the URL expire.
            time.sleep(url_expiration_seconds + 1)

            # Try to get the data object using the expired URL, and fail.
            response = requests.get(url_string)
            self.assertEqual(response.status_code, 403)

        finally:
            os.remove(put_filename)
            os.remove(get_filename)
            assert_command(f'irm -f {self.bucket_irods_path}/{put_filename}')

    def test_minio_put_presigned_url_in_bucket_root_small_file(self):
        put_filename = "test_minio_put_presigned_url_in_bucket_root_small_file"
        get_filename = f'{put_filename}.get'
        contents = b"data for overwrite"

        try:
            make_arbitrary_file(put_filename, 100*1024)

            # Generate a presigned URL to upload to the data object.
            url_expiration_seconds = 5
            url_string = self.minio_client.presigned_put_object(
                self.bucket_name, put_filename, expires=datetime.timedelta(seconds=url_expiration_seconds)
            )

            # Use requests.put to put the file into the bucket using the URL.
            with open(put_filename, "rb") as fd:
                response = requests.put(url_string, data=fd)
                self.assertEqual(response.status_code, 200)

            # Now, get the file out to a local file.
            assert_command(f'iget {self.bucket_irods_path}/{put_filename} {get_filename}')

            # Compare the put file and get file.
            assert_command(f'diff -q {put_filename} {get_filename}')

            # Now, use the same URL to overwrite the data object with something else.
            response = requests.put(url_string, data=contents)
            self.assertEqual(response.status_code, 200)

            # Now, get the file out to a local file, overwriting what is there.
            assert_command(f'iget -f {self.bucket_irods_path}/{put_filename} {get_filename}')

            # Verify the retrieved file contents.
            with open(get_filename, "rb") as fd:
                get_file_contents = fd.read()
                self.assertEqual(contents, get_file_contents)

            # Sleep long enough to let the URL expire.
            time.sleep(url_expiration_seconds + 1)

            # Try to put the data object again using the expired URL, and fail.
            with open(put_filename, "rb") as fd:
                response = requests.put(url_string, data=fd)
                self.assertEqual(response.status_code, 403)

        finally:
            os.remove(put_filename)
            os.remove(get_filename)
            assert_command(f'irm -f {self.bucket_irods_path}/{put_filename}')
