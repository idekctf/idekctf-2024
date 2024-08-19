FROM pwn.red/admin-bot

COPY config.js .

ENTRYPOINT ["./node_modules/.bin/concurrently", "PORT=8080 ./node_modules/.bin/nodemon ./submit.js", "PORT=8081 ./node_modules/.bin/nodemon ./visit.js"]
