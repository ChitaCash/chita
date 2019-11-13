#!/usr/bin/env bash

DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
cd $DIR/..

DOCKER_IMAGE=${DOCKER_IMAGE:-chitapay/chitad-develop}
DOCKER_TAG=${DOCKER_TAG:-latest}

BUILD_DIR=${BUILD_DIR:-.}

rm docker/bin/*
mkdir docker/bin
cp $BUILD_DIR/src/chitad docker/bin/
cp $BUILD_DIR/src/chita-cli docker/bin/
cp $BUILD_DIR/src/chita-tx docker/bin/
strip docker/bin/chitad
strip docker/bin/chita-cli
strip docker/bin/chita-tx

docker build --pull -t $DOCKER_IMAGE:$DOCKER_TAG -f docker/Dockerfile docker
