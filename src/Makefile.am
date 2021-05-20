# Copyright 2021, ISRG (https://www.abetterinternet.org)
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#

ACLOCAL_AMFLAGS = -I m4
AUTOMAKE_OPTIONS = foreign

lib_LTLIBRARIES    = mod_tls.la

#---------------------------------------------------------------------------------------------------
# mod_md for httpd
#---------------------------------------------------------------------------------------------------

mod_tls_la_CPPFLAGS = -g -I../src -std=c99 -D_GNU_SOURCE -Werror @WERROR_CFLAGS@
mod_tls_la_LDFLAGS  = -lcrustls -module -export-symbols-regex tls_module


OBJECTS = \
    mod_tls.c \
    tls_cache.c \
    tls_cert.c \
    tls_conf.c \
    tls_core.c \
    tls_filter.c \
    tls_ocsp.c \
    tls_proto.c \
    tls_util.c \
    tls_var.c

HFILES = \
    mod_tls.h \
    tls_cache.h \
    tls_cert.h \
    tls_conf.h \
    tls_core.h \
    tls_filter.h \
    tls_ocsp.h \
    tls_proto.h \
    tls_util.h \
    tls_var.h \
    tls_version.h

mod_tls_la_SOURCES = $(HFILES) $(OBJECTS)

all: mod_tls.la

#---------------------------------------------------------------------------------------------------
# installations
#---------------------------------------------------------------------------------------------------

install-exec-local: mod_tls.la
	$(MKDIR_P) $(DESTDIR)/@LIBEXEC_DIR@
	$(APXS) -i -S LIBEXECDIR=$(DESTDIR)/@LIBEXEC_DIR@ -n tls mod_tls.la
