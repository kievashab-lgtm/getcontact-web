# syntax=docker/dockerfile:1.7
# Private deployment of naufalist/getcontact-web on Railway.
# All passwords and application secrets come from Railway environment variables.
FROM php:8.2-apache

RUN apt-get update \
 && apt-get install -y --no-install-recommends libcurl4-openssl-dev libonig-dev libsqlite3-dev apache2-utils \
 && docker-php-ext-install curl mbstring pdo_sqlite \
 && a2enmod rewrite headers setenvif \
 && rm -rf /var/lib/apt/lists/*

WORKDIR /var/www/html
COPY . /var/www/html/

RUN <<'SETUP' bash
set -euo pipefail

# Original app assumes /getcontact-web prefix and a public hard-coded crypto key.
sed -i 's|define("URL_PREFIX", "/getcontact-web");|define("URL_PREFIX", "");|' src/configurations/site.php
sed -i 's|define("FORM_SECRET_KEY", "Y29udGFjdC5uYXVmYWxpc3RAZ21haWwuY29t");|define("FORM_SECRET_KEY", getenv("FORM_SECRET_KEY"));|' src/configurations/site.php
sed -i 's|define("CSRF_EXPIRY_DURATION", 60);|define("CSRF_EXPIRY_DURATION", 300);|' src/configurations/site.php

# Use SQLite on a Railway persistent volume instead of an external MySQL server.
cat > src/libraries/database.php <<'PHP'
<?php
if (empty(getenv('ADMIN_PASSWORD')) || empty(getenv('FORM_SECRET_KEY'))) {
    http_response_code(503);
    exit('Missing private server configuration.');
}
try {
    $pdo = new PDO('sqlite:/data/getcontact.sqlite');
    $pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
    $pdo->setAttribute(PDO::ATTR_DEFAULT_FETCH_MODE, PDO::FETCH_ASSOC);
    $pdo->exec('PRAGMA busy_timeout=5000');
    $pdo->exec('CREATE TABLE IF NOT EXISTS administrators (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT NOT NULL UNIQUE,
        password TEXT NOT NULL
    )');
    $pdo->exec('CREATE TABLE IF NOT EXISTS credentials (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        description TEXT NOT NULL,
        final_key TEXT NOT NULL UNIQUE,
        token TEXT NOT NULL,
        client_device_id TEXT,
        created_by TEXT,
        created_at TEXT DEFAULT CURRENT_TIMESTAMP,
        updated_by TEXT,
        updated_at TEXT DEFAULT CURRENT_TIMESTAMP,
        deleted_by TEXT,
        deleted_at TEXT
    )');
    $stmt = $pdo->prepare('SELECT password FROM administrators WHERE username=?');
    $stmt->execute(['admin']);
    $savedHash = $stmt->fetchColumn();
    if (!$savedHash || !password_verify(getenv('ADMIN_PASSWORD'), $savedHash)) {
        $hash = password_hash(getenv('ADMIN_PASSWORD'), PASSWORD_DEFAULT);
        $stmt = $pdo->prepare('INSERT INTO administrators (username,password) VALUES (?,?)
            ON CONFLICT(username) DO UPDATE SET password=excluded.password');
        $stmt->execute(['admin', $hash]);
    }
} catch (Throwable $e) {
    error_log('SQLite initialization failed: ' . $e->getMessage());
    http_response_code(503);
    exit('Database unavailable.');
}
PHP

# Apache Basic authentication protects EVERY endpoint, not just /dashboard.
# The original database admin/admin login is also overwritten on first request.
cat > /etc/apache2/sites-available/000-default.conf <<'APACHE'
<VirtualHost *:80>
    ServerName localhost
    DocumentRoot /var/www/html
    SetEnvIf X-Forwarded-Proto "^https$" HTTPS=on
    <Directory /var/www/html>
        Options -Indexes
        AllowOverride None
        DirectoryIndex index.php
        AuthType Basic
        AuthName "Private Getcontact Web"
        AuthUserFile /etc/apache2/getcontact.htpasswd
        Require valid-user
    </Directory>
    <Directory /var/www/html/src>
        Require all denied
    </Directory>
    <Directory /var/www/html/sql>
        Require all denied
    </Directory>
    <FilesMatch "^(\.htaccess|\.git.*|Dockerfile|errors\.log|readme\.md)$">
        Require all denied
    </FilesMatch>
    RewriteEngine On
    RewriteCond %{REQUEST_FILENAME} !-f
    RewriteCond %{REQUEST_FILENAME} !-d
    RewriteRule ^/(.*)$ /index.php [L,QSA]
    ErrorLog /proc/self/fd/2
    CustomLog /proc/self/fd/1 combined
</VirtualHost>
APACHE

cat > /usr/local/bin/start-getcontact <<'START'
#!/bin/sh
set -eu
if [ -z "${ADMIN_PASSWORD:-}" ] || [ "${#ADMIN_PASSWORD}" -lt 16 ] || [ -z "${FORM_SECRET_KEY:-}" ]; then
    echo 'Configure ADMIN_PASSWORD (at least 16 chars) and FORM_SECRET_KEY in Railway.' >&2
    exit 1
fi
mkdir -p /data
chown www-data:www-data /data
chmod 700 /data
printf '%s\n' "$ADMIN_PASSWORD" | htpasswd -iBc /etc/apache2/getcontact.htpasswd admin >/dev/null
chmod 640 /etc/apache2/getcontact.htpasswd
chown root:www-data /etc/apache2/getcontact.htpasswd
exec apache2-foreground
START
chmod +x /usr/local/bin/start-getcontact
chown -R www-data:www-data /var/www/html
SETUP

EXPOSE 80
CMD ["/usr/local/bin/start-getcontact"]
