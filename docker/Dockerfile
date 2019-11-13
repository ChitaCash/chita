FROM debian:stretch
LABEL maintainer="Chita Developers <dev@chita.org>"
LABEL description="Dockerised ChitaCore, built from Travis"

RUN apt-get update && apt-get -y upgrade && apt-get clean && rm -fr /var/cache/apt/*

COPY bin/* /usr/bin/
