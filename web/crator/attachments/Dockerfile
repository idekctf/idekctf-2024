FROM python@sha256:a90e299af8a9cd6b59c4aaed2b024c78561476978244a1ab89742a4a5ac8c974
# python:3.11-slim

RUN apt update && apt install sudo

RUN useradd -G sudo judge
RUN echo 'judge ALL = (ALL) NOPASSWD: APP' >> /etc/sudoers

RUN pip3 install --no-cache-dir flask sqlalchemy gunicorn
COPY app /home/judge/app

WORKDIR /home/judge/app
RUN chmod 600 db.sqlite

ENTRYPOINT ["gunicorn", "--bind", "0.0.0.0:1337", "-m", "007", "-w", "3", "--timeout", "15", "--capture-output", "app:app"]
