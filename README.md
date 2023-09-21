# iRODS S3 API

A project that presents an iRODS 4.3.1+ Zone as S3 compatible storage.

![S3 API network diagram](s3_api_diagram.png)

Implements a subset of the Amazon S3 API:
  - https://docs.aws.amazon.com/AmazonS3/latest/API/API_Operations.html

Initial effort includes:
  - [x] CopyObject
  - CompleteMultipartUpload
  - CreateMultipartUpload
  - [x] DeleteObject
  - DeleteObjects
  - [x] GetBucketLocation
  - [x] GetObject
  - GetObjectAcl ?
  - [x] GetObjectLockConfiguration
  - GetObjectTagging ?
  - [x] HeadObject
  - [x] ListBuckets
  - ListObjects ?
  - [x] ListObjectsV2
  - [x] PutObject
  - PutObjectAcl ?
  - PutObjectTagging ?
  - UploadPart
  - UploadPartCopy ?

Goal is to support the equivalent of:
 - ils - `aws s3 ls s3://bucketname/a/b/c/`
 - iput - `aws s3 cp localfile s3://bucketname/a/b/c/filename`
 - iget - `aws s3 cp s3://bucketname/a/b/c/filename localfile`
 - irm - `aws s3 rm s3://bucketname/a/b/c/filename`
 - imv - `aws s3 mv s3://bucketname/a/b/c/filename1 s3://bucketname/a/b/c/filename2`

# Limitations / What's Missing

## Multipart Uploads

Multipart uploads are an important part of S3, however, they aren't simple to implement and have substantial performance
and storage implications for a naive approach. As of now, this API does not attempt to provide that functionality.

See [Disabling Multipart](#disabling-multipart) for details.

## Tagging

iRODS has its own metadata system, however it is not especially clear how it should map to S3 metadata, so it is not
included at the moment.

## Paging

Paging requires engineering work to provide paging through lists of objects efficiently, so right now this API does not
attempt to paginate its output for things such as listobjects.

## Checksum handling

Amazon S3 provides many ways to communicate checksums for the data as received by the server. iRODS provides MD5 checksums, 
however this API does not use that to verify data objects created through PutObject.

## ETags

ETags are not provided for or used consistently.

## Versioning

Versioning is not supported at this time.

# Setting it up

## Building

This project relies on git submodules and Docker for building the server.

Before the server can be built, you must download the appropriate git submodules. You can do that by running the following:

```bash
git submodule update --init --recursive
```

With the dependencies resolved, all that's left is to build the application. Run the following command from the root of the project directory.

```bash
docker build -t local/irods_s3_api .
```

If everything succeeds, you'll have a containerized iRODS S3 API server image.

If you run into issues, try checking if the git submodules exist on your machine and you're running an up-to-date version of Docker.

## Configuration

The S3 API expects a configuration file. You can create one using the template at the root of the project directory. The name of the template is **config.json.template**.

Create a copy and update it to fit your needs. For example:

```bash
cp config.json.template config.json

# Use your favorite editor to update config.json.
```

The following code block shows the structure of the configuration file and provides details explaining what they are. **THE COMMENTS MUST NOT BE INCLUDED. THEY EXIST FOR EXPLANATORY PURPOSES ONLY!**

```js
{
    // Defines options that affect how the client-facing component of the
    // server behaves.
    "s3_server": {
        // The port used to accept incoming client requests.
        "port": 8080,

        // Defines the set of plugins to load.
        "plugins": {
            //
            // Each key corresponds to a plugin's .so file name, minus the
            // "lib" prefix.
            //

            "static_bucket_resolver": {
                // The internal name assigned to the plugin.
                "name": "static_bucket_resolver",

                // Defines the mapping between bucket names and iRODS
                // collections.
                "mappings": {
                    "<bucket_name>": "/path/to/collection"
                }
            },

            "static_authentication_resolver": {
                // The internal name assigned to the plugin.
                "name": "static_authentication_resolver",

                // Defines information for resolving an S3 username to an
                // iRODS username.
                "users": {
                    // Maps <s3_username> to a specific iRODS user.
                    // Each iRODS user that intends to access the S3 API must
                    // have at least one entry.
                    "<s3_username>": {
                        // The iRODS username to resolve to.
                        "username": "<string>",

                        // The secret key used to authenticate with the S3
                        // API for this user.
                        "secret_key": "<string>"
                    }
                }
            }
        },

        // This may be relevant to your performance if you have many rules
        // in your iRODS installation
        "resource": "demoResc",

        // The number of threads dedicated to servicing client requests.
        "threads": 10,

        // The size of the buffer when calling PutObject.
        "put_object_buffer_size_in_bytes": 8192,

        // The size of the buffer when calling GetObject.
        "get_object_buffer_size_in_bytes": 8192,

        // The region returned in the GetBucketLocation API call.  The default is us-east-1.
        "s3_region": "us-east-1"
    },

    // Defines how the S3 API server connects to an iRODS server.
    "irods_client": {
        // The hostname or IP of the target iRODS server.
        "host": "<string>",

        // The port of the target iRODS server.
        "port": 1247,

        // The zone of the target iRODS server.
        "zone": "<string>",

        // The credentials for the rodsadmin user that will act as a proxy
        // for all authenticated users.
        "proxy_admin_account": {
            "username": "<string>",
            "password": "<string>"
        }
    }
}
```

## Running

Docker is required for running the S3 API server. To do so, run the following:

```bash
docker run -d --name irods_s3_api -v /path/to/your/config.json:/irods_client_s3_api_config.json:ro -p 8080:8080 local/irods_s3_api
```

You can follow the log file by running the following:

```bash
docker logs -f irods_s3_api
```

This application can also run against iRODS 4.2.11 and 4.2.12. No adjustments to your configuration file are required.

**IMPORTANT: This project requires the iRODS 4.3.1 runtime and therefore cannot be run on the same machine hosting an iRODS 4.2 server.**

## Connecting with Botocore

As a simple example, this is how you pass that in through botocore, a library from Amazon that provides S3 connectivity.

```python
import botocore.session

session = botocore.session.get_session()
client = session.create_client("s3",
                               use_ssl=False,
                               endpoint_url="http://127.0.0.1:8080",
                               aws_access_key_id="<username>",
                               aws_secret_access_key="<secret key>")
```

## Disabling Multipart

Multipart uploads are not supported at this time.  Therefore, multipart must be disabled in the client.

### Disabling Multipart for AWS CLI

For AWS CLI, multipart uploads can be disabled by setting an arbitrarily large multipart threshold.  Since 5 GB is the largest single part upload allowed by AWS, this is a good choice.

To disable multipart uploads, set the `multipart_threshold` in the ~/.aws/credentials file for the profile in question.  For example, you could create a profile called `irods_s3_no_multipart` with the following in the credentials file.

```
[irods_s3_no_multipart]
aws_access_key_id = key1 
aws_secret_access_key = secret_key1
s3 =
    multipart_threshold = 5GB
```

To use this with the AWS CLI commands, use the `--profile` flag.  Example: `aws --profile irods_s3_no_multipart`.

### Example for Boto3

To set the multipart threshold with a boto3 client, do the following: 

```python
config = TransferConfig(multipart_threshold=5*1024*1024*1024)
self.boto3_client.upload_file(put_filename, bucket_name, key, Config=config)
```

## Running Tests

Run the following commands to run the test suite.

```bash
cd tests/docker
docker-compose build
docker-compose run client
```

The test output will appear in the terminal.  Once the tests complete run the following to cleanup:

```bash
docker-compose down
```
