# latest node 18 at the time of writing this
FROM node:18-slim@sha256:03777927a98e306d478fdbdeed07351ad910179b714a2934f0f4d64810ac58aa

RUN apt update && apt install -y gcc socat

WORKDIR /app

# latest mathjs at the time of writing this
RUN npm i -g mathjs@13.0.3

COPY patched-cli.js /usr/local/lib/node_modules/mathjs/bin/cli.js

RUN chmod +x /usr/local/bin/mathjs

COPY readflag.c .
RUN gcc readflag.c -static -o /readflag
RUN chmod u+s /readflag

COPY flag.txt /flag.txt
RUN chmod 400 /flag.txt

RUN rm readflag.c

EXPOSE 1337

USER node

# unfortunately echo=0 doesn't work on the server (likely due to readline?), so there'll appear to be some
# lag on keypresses depending your ping to the server (negligible if localhost)
# socat -,raw,echo=0 tcp:localhost:1337
CMD socat tcp-l:1337,reuseaddr,fork system:"NODE_OPTIONS='--disallow-code-generation-from-strings' mathjs",stderr,pty
