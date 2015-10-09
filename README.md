Simple Open & Light on Android - Web Server Engine
===================================

This repo contains only the web server ENGINE part. It provides tools in order to build an image that containing:

- apache2 web service
- stunnel4 ssl proxy

Requirements
----------------
Edit the *apache.conf* to modify the HSM host's IP.

    sed -r -i 's/engineCtrl=ZMQ_SERVER_IP:*[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+/engineCtrl=ZMQ_SERVER_IP:<HSM_IPv4>/g' apache.conf


Build
------

    docker build -t <your_optional_repo>solhsmengine .

Run
-----

    docker run -p 80:80 -p 443:443 -it <your_optional_repo>/solhsmengine


Warning
-------

This Docker container contains a public certificate and czmq certificates in order
to work this my demo. If you want our own (see *engineCtrl=ZMQ_SERVER_PUB_CERT_PATH*, *engineCtrl=ZMQ_CLIENT_PRIV_CERT_PATH* and *cert* variables in *apache.conf* file), your have to create them your self:

- czmq certificates generator:
- In order to make your x509 certificate, you need extract the *Certificate Signing Request* (CSR) and sign it your self or by your CA.
