# irods_client_s3_cpp

iRODS S3 API

We will implement a subset of the S3 API:
  - https://docs.aws.amazon.com/AmazonS3/latest/API/API_Operations.html

Initial effort to include:
  - [x] CopyObject
  - CompleteMultipartUpload
  - CreateMultipartUpload
  - [x] DeleteObject
  - DeleteObjects
  - [x] GetObject
  - GetObjectAcl ? (Mapping the needs of S3 access control versus the iRODS access control is complicated)
  - GetObjectTagging (The way this translates into AVUs is also not entirely clear)
  - [x] HeadObject
  - ListObjects ?
  - [x] ListObjectsV2
  - [x] PutObject
  - PutObjectAcl ?
  - PutObjectTagging
  - UploadPart
  - UploadPartCopy ?

Goal is to support the equivalent of:
 - ils - aws s3 ls s3://bucketname/a/b/c/
 - iput - aws s3 cp localfile s3://bucketname/a/b/c/filename
 - iget - aws s3 cp s3://bucketname/a/b/c/filename localfile
 - irm - aws s3 rm s3://bucketname/a/b/c/filename
 - imv - aws s3 mv s3://bucketname/a/b/c/filename1 s3://bucketname/a/b/c/filename2

# Limitations (What's Missing?)

## Multipart Uploads

Multipart uploads are an important part of S3, however, they aren't simple to implement and have substantial performance
and storage implications for a naive approach. As of now, this bridge does not attempt to provide that functionality

## Tagging

iRODS does have its own metadata system, however it is not especially clear how it should map to S3 metadata, so it is not
included at the moment.

## Paging

Paging requires engineering work to provide paging through lists of objects efficient, so right now the bridge does not
attempt to paginate its output for things such as listobjects.

## Checksum handling

Amazon S3 provides many places to place checksums for the data as received by the server. iRODS provides MD5 checksums, 
however the bridge does not use that to verify data objects created through PutObject.

## ETags

ETags are not provided for or used consistently.

## Versioning

Versioning is not supported at this time.

# Setting it up <a id="Interesting_Part"/>

## Building

This project relies on iRODS features that have not been released yet.

You'll need to build the iRODS packages using [irods/irods@6b14b65](https://github.com/irods/irods/tree/6b14b65301fc119ffc5cfaae4b0f5e68872100b9) or a later commit.

Building requires the following:
- Docker
- irods-dev
- irods-runtime

You'll need to copy the packages into the root of the project directory.

To build, run the following in the root of the project directory:

```bash
docker build -t local/irods_s3_api .
```

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
        "rodsadmin": {
            "username": "<string>",
            "password": "<string>"
        }
    }
}
```

## Running

Docker is required for running the S3 API server. To do so, run the following:

```bash
docker run -d --name irods_s3_api -v /path/to/your/config.json:/root/config.json:ro -p 8080:8080 local/irods_s3_api
```

You can follow the log file by running the following:

```bash
docker logs -f irods_s3_api
```

## Connecting with Botocore

As a simple example, this is how you pass that in through botocore, one of the various libraries from Amazon which happen
to provide S3 connectivity.

```python
import botocore.session

session = botocore.session.get_session()
client = session.create_client("s3",
                               use_ssl=False,
                               endpoint_url="http://127.0.0.1:8080",
                               aws_access_key_id="<username>",
                               aws_secret_access_key="<secret key>")
```
