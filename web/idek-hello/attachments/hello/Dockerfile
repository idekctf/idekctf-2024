FROM nginx:latest

RUN apt-get update && \
    apt-get install -y php8.2-fpm nano

COPY nginx.conf /etc/nginx/nginx.conf
COPY src /usr/share/nginx/html/
COPY init.sh /
RUN chmod +x /init.sh

EXPOSE 80

CMD /init.sh

