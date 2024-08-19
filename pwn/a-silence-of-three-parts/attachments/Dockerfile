FROM pwn.red/jail

COPY --from=ubuntu:24.04@sha256:c920ba4cfca05503764b785c16b76d43c83a6df8d1ab107e7e6610000d94315c / /srv
COPY chal /srv/app/run
COPY flag.txt /srv/app/

ENV JAIL_TIME=300