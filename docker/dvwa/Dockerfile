# Образ DVWA для РГР. Збирається з вендореного коду ./dvwa (контекст збирання — корінь репозиторію).
# Мережа потрібна лише під час збирання (apt, composer); під час роботи контейнер
# знаходиться тільки у внутрішній мережі без маршруту назовні (див. docker-compose.yml).
FROM docker.io/library/php:8.4-apache

WORKDIR /var/www/html

RUN apt-get update \
 && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
      zlib1g-dev libpng-dev libjpeg-dev libfreetype6-dev iputils-ping unzip \
 && DEBIAN_FRONTEND=noninteractive apt-get upgrade -y \
 && rm -rf /var/lib/apt/lists/* \
 && docker-php-ext-configure gd --with-jpeg --with-freetype \
 && docker-php-ext-install gd mysqli pdo pdo_mysql \
 && a2enmod rewrite headers

COPY --from=docker.io/library/composer:2 /usr/bin/composer /usr/local/bin/composer

# Код належить root і недоступний для запису процесу www-data (T16); на запис — лише uploads.
COPY dvwa/ ./
COPY dvwa/config/config.inc.php.dist config/config.inc.php
COPY docker/dvwa/apache-dvwa.conf /etc/apache2/conf-enabled/zz-dvwa.conf

RUN cd vulnerabilities/api && composer install --no-dev --no-interaction --no-progress \
 && chown -R root:root /var/www/html \
 && chmod 755 /var/www/html \
 && chown -R www-data:www-data /var/www/html/hackable/uploads \
 && chmod 755 /var/www/html/hackable/uploads

# php.ini копіюється після composer: open_basedir діє і на CLI.
COPY docker/dvwa/php-dvwa.ini /usr/local/etc/php/conf.d/zz-dvwa.ini

HEALTHCHECK --interval=10s --timeout=3s --retries=10 \
  CMD php -r 'exit(@file_get_contents("http://127.0.0.1/login.php") === false ? 1 : 0);'
