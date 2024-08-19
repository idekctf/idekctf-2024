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
FROM gcr.io/kctf-docker/healthcheck@sha256:6709709a8cfd6e2d743c86d58398c00ca4eb26befd3b1a0a629ab35f91e98ef0 AS dummy

FROM sagemath/sagemath:10.4 AS healthcheck

COPY --from=dummy /usr/bin/kctf_drop_privs /usr/bin/kctf_drop_privs
COPY --from=dummy  /usr/bin/kctf_bypass_pow /usr/bin/kctf_bypass_pow

USER root

ENV DEBIAN_FRONTEND=noninteractive

ENV BUILD_PACKAGES="python3-pip build-essential python3-dev"
RUN apt-get update \
    && apt-get -yq --no-install-recommends install $BUILD_PACKAGES \
    && rm -rf /var/lib/apt/lists/* \
    && sage -pip install pwntools pycryptodome

RUN apt-get update && apt-get -yq --no-install-recommends install cpio openssl python3 && rm -rf /var/lib/apt/lists/*

RUN /usr/sbin/userdel sage
RUN rm /etc/sudoers.d/01-sage

RUN /usr/sbin/useradd --no-create-home -u 1000 user

RUN mkdir -p /home/user/.pwntools-cache && echo never > /home/user/.pwntools-cache/update

WORKDIR /home/user
COPY ./vector-bundles-sagemath .
RUN make install

COPY healthcheck_loop.sh healthcheck.sage function_field_elliptic.py healthz_webserver.py /home/user/

RUN sage --nodotsage --preparse /home/user/healthcheck.sage

CMD "kctf_drop_privs /home/user/healthcheck_loop.sh & /home/user/healthz_webserver.py"