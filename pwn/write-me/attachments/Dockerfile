FROM ubuntu:20.04@sha256:ed4a42283d9943135ed87d4ee34e542f7f5ad9ecf2f244870e23122f703f91c2

RUN apt update && apt install -y socat

RUN /usr/sbin/useradd --no-create-home -u 1000 user

COPY flag.txt /
COPY write_me /home/user/chal

CMD ["socat", "TCP-LISTEN:1337,reuseaddr,fork", "EXEC:\"/home/user/chal\""]
