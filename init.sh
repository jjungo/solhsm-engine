#!/bin/bash

set -e

mkdir -p data/{keys/priv,cert,log}
cd tools
make
./generate_cert client

cp client.cert_secret ../data/keys/priv/
cp client.cert ../data/keys/

make cleanall
cd ..

echo -e "\n------------------------------------------------------------"
echo "ECC certificates are created into the ./data/keys dir"
echo "Please, place your TLS certificate into the ./data/cert/ dir"
