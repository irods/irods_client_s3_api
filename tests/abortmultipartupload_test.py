import inspect
import json
import os
import unittest

from host_port import s3_api_host_port, irods_host
from libs import command, utility

class AbortMultipartUpload_Test(unittest.TestCase):
    bucket_irods_path = '/tempZone/home/alice/alice-bucket'
    bucket_name = 'alice-bucket'
    s3_api_url = f'http://{s3_api_host_port}'

    def __init__(self, *args, **kwargs):
        super(AbortMultipartUpload_Test, self).__init__(*args, **kwargs)

    def setUp(self):
        pass
    def tearDown(self):
        pass

    def test_abort_multipart_closes_stream_to_data_object__issue_130(self):
        put_filename = inspect.currentframe().f_code.co_name
        part_filename = f'{put_filename}.part'
        try:
            utility.make_arbitrary_file(part_filename, 100*1024)

            # create the multipart upload and grab the upload ID from the json response
            _, out, _ = command.assert_command(f'aws --profile s3_api_alice --endpoint-url {self.s3_api_url} '
                    f's3api create-multipart-upload --bucket {self.bucket_name} --key {put_filename}',
                    'STDOUT_MULTILINE',
                    ['UploadId'])
            upload_id = json.loads(out)["UploadId"]

            # upload two parts
            command.assert_command(f'aws --profile s3_api_alice --endpoint-url {self.s3_api_url} '
                    f's3api upload-part --upload-id {upload_id} --bucket {self.bucket_name} --key {put_filename} --part-number 1 --body ./{part_filename}',
                    'STDOUT_SINGLELINE',
                    'ETag')
            command.assert_command(f'aws --profile s3_api_alice --endpoint-url {self.s3_api_url} '
                    f's3api upload-part --upload-id {upload_id} --bucket {self.bucket_name} --key {put_filename} --part-number 2 --body ./{part_filename}',
                    'STDOUT_SINGLELINE',
                    'ETag')

            # abort the multipart upload
            command.assert_command(f'aws --profile s3_api_alice --endpoint-url {self.s3_api_url} '
                    f's3api abort-multipart-upload --bucket {self.bucket_name} --key {put_filename} --upload-id {upload_id}')

            # Put the object. Without the fix for 130 this would fail as the stream remains open
            command.assert_command(f'aws --profile s3_api_alice --endpoint-url {self.s3_api_url} '
                    f's3 cp {part_filename} s3://{self.bucket_name}/{put_filename}',
                    'STDOUT_SINGLELINE',
                    f'upload: ./{part_filename} to s3://{self.bucket_name}/{put_filename}')

        finally:
            os.remove(part_filename)
            command.assert_command(f'irm -f {self.bucket_irods_path}/{put_filename}')
