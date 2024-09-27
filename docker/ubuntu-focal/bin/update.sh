#!/bin/bash

TOP=/abetterinternet
DATADIR=$TOP/data
RUSTLS_VERSION=0.14.0

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

PREFIX=$(apxs -q exec_prefix)
if test ! -d $PREFIX; then
    fail "apache install prefix not found: $PREFIX"
fi

# remove some stuff that accumulates
LOG_DIR=$(apxs -q logfiledir)
rm -f $LOG_DIR/*

#cd $DATADIR
#if test ! -f rustup.sh.run; then
#  curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs -o rustup.sh ||rm -f rustup.sh
#  /bin/bash rustup.sh -y ||fail
#  touch rustup.sh.run
#fi

cd $DATADIR
rm -rf rustls-ffi
git clone https://github.com/rustls/rustls-ffi.git rustls-ffi
cd rustls-ffi
git fetch origin
git checkout "tags/v$RUSTLS_VERSION"
make install DESTDIR=$PREFIX CRYPTO_PROVIDER=ring || fail

cd "$TOP/mod_tls" ||fail
if needs_update .installed .; then
  rm -f .installed
  if test ! -f configure -o configure.ac -nt configure; then
    autoreconf -i ||fail
  fi
  if test ! -d Makefile -o ./configure -nt Makefile; then
    ./configure || fail
    touch ./configure
  fi
  make clean||fail
  make ||fail
  find .
  make install ||fail
  touch .installed
fi
pytest
