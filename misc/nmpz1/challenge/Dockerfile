FROM node:22

WORKDIR /usr/src/app

RUN npm install body-parser cookie-parser express jsdom node-fetch@2

COPY . .

RUN tar xf public/img.tar.gz -C public

EXPOSE 1337

CMD [ "node", "server.js" ]
