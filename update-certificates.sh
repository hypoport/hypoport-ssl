#!/bin/sh

BASE_DIR=`pwd`
CERT_GEN_DIR="$BASE_DIR/cert-gen"
TEST_RESOURCES_DIR="$BASE_DIR/src/test/resources"

cd $CERT_GEN_DIR
docker build -t cert-gen .
docker rm certs
docker run --name certs cert-gen true

docker cp certs:/certs/serverCA.bks $TEST_RESOURCES_DIR
docker cp certs:/certs/serverCA.crt $TEST_RESOURCES_DIR
docker cp certs:/certs/server.crt $TEST_RESOURCES_DIR

cd $TEST_RESOURCES_DIR
mv serverCA.crt serverCA.pem
mv server.crt serverCert.pem
