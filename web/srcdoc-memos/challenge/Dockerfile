FROM node:22-slim@sha256:ec92a9eaa01e8e098dc7da1c884a3d2a0f10c66b6dac6b1ca054cc5908442ab3

WORKDIR /app

COPY src .
RUN npm i

EXPOSE 1337

USER node

CMD [ "node", "index.js" ]
