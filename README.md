### Running

You must use Python 3 and PyCrypto 2.6.1

### Overview

In this project a client must be able to upload and download files securely from an insecure storage server where an attacker can attack the server and corrupt these files. A client must also be able to share and revoke file access with other clients. 

This is done by using encryption and signatures to verify whether or not the file has been corrupted.

To optimize uploading and downloading large files, I implement a merkle tree so that if a file is reuploaded or updated, only the parts that have been changed get uploaded to the server thus minimizing the overall data sent across the internet.
