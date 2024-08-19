FROM sagemath/sagemath:10.4  AS chroot

USER root

RUN apt-get update && apt-get install -y socat python3 python3-pip make && rm -rf /var/lib/apt/lists/*
RUN sage -pip install pycryptodome

RUN mkdir -m 777 /app

USER sage

COPY chall.sage /app/
COPY flag.txt /app/

WORKDIR /app

RUN sage --preparse chall.sage

FROM gcr.io/kctf-docker/challenge@sha256:eb0f8c3b97460335f9820732a42702c2fa368f7d121a671c618b45bbeeadab28

COPY --from=chroot / /chroot

COPY nsjail.cfg /home/user/

CMD ["bash", "-c", "kctf_setup && kctf_drop_privs socat -T600 TCP-LISTEN:1337,reuseaddr,fork EXEC:\"kctf_pow nsjail --config /home/user/nsjail.cfg --cwd /app -- /usr/bin/sage --nodotsage chall.sage.py\""]
