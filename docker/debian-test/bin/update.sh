#!/bin/bash

TOP=/abetterinternet
DATADIR=$TOP/data

fail() {
  echo "$@"
  exit 1
}

needs_update() {
  local ref_file="$1"
  local check_dir="$2"
  if test ! -f "$ref_file"; then
    return 0
  fi
  find "$check_dir" -type f -a -newer "$ref_file" -o -type d -name .git -prune -a -false |
  while read fname; do
    return 0
  done
  return 1
}

# remove some stuff that accumulates
rm -f $DATADIR/apache2/logs/*

cd $DATADIR
if test ! -f rustup.sh.run; then
  curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs -o rustup.sh ||rm -f rustup.sh
  /bin/bash rustup.sh -y ||fail
  touch rustup.sh.run
fi

if test ! -d httpd; then
  git clone https://github.com/icing/httpd.git httpd ||fail
fi
cd httpd
if test ! -d srclib/apr; then
  svn co http://svn.apache.org/repos/asf/apr/apr/trunk srclib/apr
fi
git fetch origin 2.4.x ||fail
git checkout 2.4.x ||fail
if needs_update $DATADIR/apache2/.installed .; then
  rm -f $DATADIR/apache2/.installed
  ./buildconf ||fail
  ./configure --prefix=$DATADIR/apache2 --with-included-apr \
    --enable-mpms-shared=event --enable-ssl --enable-http2 \
    --enable-cgi --enable-md  ||fail
  make install ||fail
  touch $DATADIR/apache2/.installed
fi

cd $DATADIR
rm -f $DATADIR/apache2/.crustls-installed
rm -rf crustls
if test ! -d crustls; then
  git clone https://github.com/abetterinternet/crustls.git crustls
fi
cd crustls
git fetch origin main
git checkout main
if needs_update $DATADIR/apache2/.crustls-installed .; then
  rm -f $DATADIR/apache2/.crustls-installed
  touch src/crustls.h ||fail "missing src/crustls.h"
  make install DESTDIR=$DATADIR/apache2 ||fail
  touch $DATADIR/apache2/.crustls-installed
fi

cd "$TOP/mod_tls" ||fail
if needs_update .installed .; then
  rm -f .installed
  if test ! -f configure -o configure.ac -nt configure; then
    autoreconf -i ||fail
  fi
  if test ! -d Makefile -o ./configure -nt Makefile; then
    ./configure --with-apxs=$DATADIR/apache2/bin/apxs ||fail
    touch ./configure
  fi
  make clean||fail
  make ||fail
  find .
  make install ||fail
  touch .installed
fi
make test
python3 test/load_test.py 1k-files