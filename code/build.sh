#!/bin/bash

rm -rf build
mkdir -p build
cd build
cmake ..
make

DEPLOY_FOLER=build-pcap-someip-deploy
BIN_FILE=pcap-someip2db

rm -rf $DEPLOY_FOLER
mkdir -p $DEPLOY_FOLER

cp -p $BIN_FILE $DEPLOY_FOLER
cp -R ../../img $DEPLOY_FOLER
cp -R ../../*.md $DEPLOY_FOLER

rm -rf "$DEPLOY_FOLER.zip"
echo "Compress deploy package $DEPLOY_FOLER.zip"
zip -r "$DEPLOY_FOLER.zip" $DEPLOY_FOLER