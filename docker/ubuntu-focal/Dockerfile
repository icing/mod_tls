FROM ubuntu:focal

ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update; apt-get upgrade -y
RUN apt-get install -y apt-listchanges \
      make openssl libssl-dev libcurl4 libcurl4-openssl-dev \
      gcc subversion git cargo cbindgen python3 iputils-ping \
      libapr1-dev libaprutil1-dev libnghttp2-dev \
      autoconf libtool libtool-bin libpcre3-dev libjansson-dev curl rsync nghttp2-client

RUN apt-get install -y python3-pytest python3-tqdm python3-pycurl python3-cryptography

RUN apt-get install -y apache2 apache2-dev libapache2-mod-md

COPY docker/ubuntu-focal/bin/* /abetterinternet/bin/
COPY configure.ac Makefile.am NEWS README* AUTHORS ChangeLog COPYING LICENSE /abetterinternet/mod_tls/
COPY src /abetterinternet/mod_tls/src
COPY test/Makefile.am test/conftest.py /abetterinternet/mod_tls/test/
COPY test/modules /abetterinternet/mod_tls/test/modules
COPY test/pyhttpd /abetterinternet/mod_tls/test/pyhttpd
COPY m4 /abetterinternet/mod_tls/m4

CMD ["/bin/bash", "-c", "/abetterinternet/bin/update.sh"]
