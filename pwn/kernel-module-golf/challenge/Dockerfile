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
FROM gcr.io/kctf-docker/challenge@sha256:0f7d757bcda470c3bbc063606335b915e03795d72ba1d8fdb6f0f9ff3757364f

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y qemu-system-x86 && rm -rf /var/lib/apt/lists/*

COPY run.sh /home/user/
COPY upload.py /home/user/
COPY bzImage /home/user/
COPY initramfs.cpio.gz /home/user/


CMD mount -t tmpfs none /tmp && \
    kctf_setup && \
    kctf_drop_privs \
    socat \
      TCP-LISTEN:1337,reuseaddr,fork \
      EXEC:"kctf_pow /home/user/upload.py"
