# Simple Open & Light - Web Server Engine

This repo contains only the web server ENGINE part. It provides tools in order
to build an image that containing:

- apache2 web service
- stunnel4 ssl proxy

## Setup
First setup solhsm-engine Docker container and generate curve keys .

    chmod +x init.sh
    ./init.sh


Next, generate a TLS certificate (see [solhsm-mgmt readme](https://github.com/jjungo/solhsm-mgmt)).

Place your HSM public certificate into the `data/keys` and the TLS certificate
into the `data/cert` directory. Don't forget to share the curve certificate
(`data/keys/client.cert`) with your HSM!

Configure stunnel (`apache.conf`) and feed theses options:

    engineCtrl=ZMQ_SERVER_PUB_CERT_PATH:<full path of the pub hsm curve cert>
    engineCtrl=ZMQ_CLIENT_PRIV_CERT_PATH:<full path of the priv curve cert>
    engineCtrl=ZMQ_SERVER_IP:<HSM ip>
    cert = /data/cert/<TLS certificate file>

## Build

    docker build -t solhsm-engine .

At this point your may have in your data folder in your current directory:

    data
    ├── cert
    │   └── yourcert.cert
    ├── keys
    │   ├── client.cert
    │   ├── hsm.cert
    │   └── priv
    │       └── client.cert_secret
    └── log

## Run
Finally we run the Docker container and mount our data volume.

    docker run -p 80:80 -p 443:443 -it -v $(pwd)/data:/data solhsm-engine
