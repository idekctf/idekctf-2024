FROM php:8.2.12-cli-alpine

COPY --from=composer:latest /usr/bin/composer /usr/local/bin/composer

WORKDIR /app

COPY ./index.php ./
ADD pages ./pages/
COPY ./flag.txt /flag.txt
RUN mv /flag.txt /flag-$(head -c 6 /dev/urandom | xxd -p).txt

RUN composer require smarty/smarty symfony/symfony

COPY ./openbdir.ini /usr/local/etc/php/conf.d/openbdir.ini

ENTRYPOINT ["php", "-S", "0.0.0.0:1337", "index.php"]
