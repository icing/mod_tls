FROM debian:sid

RUN apt-get update; apt-get upgrade -y
RUN apt-get install -y apt-listchanges \
      make openssl libssl-dev libcurl4 libcurl4-openssl-dev \
      gcc subversion git cargo python3 iputils-ping \
      libapr1-dev libaprutil1-dev libnghttp2-dev pip \
      autoconf libtool libtool-bin libpcre3-dev libjansson-dev curl rsync nghttp2-client

RUN pip install pytest tqdm pycurl cryptography

RUN apt-get install -y apache2 apache2-dev libapache2-mod-md

COPY docker/debian-test/bin/* /abetterinternet/bin/
COPY configure.ac Makefile.am NEWS README* AUTHORS ChangeLog COPYING LICENSE /abetterinternet/mod_tls/
COPY src /abetterinternet/mod_tls/src
COPY test test/Makefile.am test/test.ini.in /abetterinternet/mod_tls/test
COPY m4 /abetterinternet/mod_tls/m4

CMD ["/bin/bash", "-c", "/abetterinternet/bin/update.sh"]