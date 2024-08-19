FROM python:3.10-slim

RUN apt update && apt install -y socat
RUN /usr/sbin/useradd --no-create-home -u 1000 user
WORKDIR /home/user
COPY main.py main.py
RUN chmod +x main.py

USER user

ENV FLAG="idek{sh311_r3wr1t3_sh3n4n1g4ns}"

CMD socat \
	TCP-LISTEN:1337,reuseaddr,fork \
	EXEC:"./main.py"
