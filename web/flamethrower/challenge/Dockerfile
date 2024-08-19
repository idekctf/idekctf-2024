FROM node:22-alpine

ENV PORT=1337
ENV ADMIN_COOKIE="0b8316282ad3dcd7a200e27229084e6c75a644e8c95bf725fe00054702070c81"

WORKDIR /app

ADD src/static /app/static/
ADD src/views /app/views/

COPY src /app/

RUN npm i

ENTRYPOINT ["node", "server.js"]
