FROM node:22-alpine

ENV PORT=1337
ENV ADMIN_COOKIE="REDACTED"

WORKDIR /app

ADD src/static /app/static/
ADD src/views /app/views/

COPY src /app/

RUN npm i

ENTRYPOINT ["node", "server.js"]
