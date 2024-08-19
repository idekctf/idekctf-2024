#!/bin/bash
# Copyright 2020 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     https://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
set -Eeuo pipefail

TIMEOUT=30
PERIOD=10

export TERM=linux
export TERMINFO=/etc/terminfo
export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin

while true; do
  echo -n "[$(date)] "
  if timeout "${TIMEOUT}" sage --nodotsage /home/user/healthcheck.sage.py; then
    echo 'ok' | tee /tmp/healthz
  else
    echo -n "$? "
    echo 'err' | tee /tmp/healthz
  fi
  sleep "${PERIOD}"
done