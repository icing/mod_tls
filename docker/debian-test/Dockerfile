FROM debian:sid

RUN apt-get update; apt-get upgrade -y
RUN apt-get install -y apt-listchanges \
      make openssl libssl-dev libcurl4 libcurl4-openssl-dev \
      gcc subversion git cargo python3 \
      libapr1-dev libaprutil1-dev libnghttp2-dev pip

RUN pip install pytest tqdm pycurl

RUN apt-get install -y autoconf libtool libtool-bin
RUN apt-get install -y libpcre3-dev libjansson-dev
RUN apt-get install -y curl rsync

RUN pip install cryptography

COPY docker/debian-test/bin/* /abetterinternet/bin/
COPY configure.ac Makefile.am NEWS README* AUTHORS ChangeLog COPYING LICENSE /abetterinternet/mod_tls/
COPY src /abetterinternet/mod_tls/src
COPY test test/Makefile.am test/test.ini.in /abetterinternet/mod_tls/test
COPY m4 /abetterinternet/mod_tls/m4

CMD ["/bin/bash", "-c", "/abetterinternet/bin/update.sh"]