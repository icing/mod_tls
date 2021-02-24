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

GEN            = gen
SERVER_DIR     = gen/apache

.phony: unit_tests

EXTRA_DIST     = conf data htdocs
 	
dist-hook:
	rm -rf $(distdir)/conf/httpd.conf
	rm -rf $(distdir)/conf/modules.conf


unit_tests: $(TESTS)
	@echo "no unit tests so far"
        
test: $(SERVER_DIR)/.test-setup unit_tests
	@pytest

$(SERVER_DIR)/.test-setup: \
	$(wildcard conf/*) \
	$(wildcard htdocs/*) \
	$(wildcard htdocs/*/*)
	@mkdir -p $(SERVER_DIR)/htdocs
	@rsync -a htdocs/* $(SERVER_DIR)/htdocs
	@mkdir -p $(SERVER_DIR)/conf/ssl
	@mkdir -p $(SERVER_DIR)/logs
	rsync -a --exclude="*.in" conf/* $(SERVER_DIR)/conf
	@touch $@


clean-local:
	rm -rf *.pyc __pycache__
	rm -rf $(SERVER_DIR)
