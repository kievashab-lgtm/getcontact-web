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

# Debian dependency installation can enable mpm_event alongside PHP's
# mpm_prefork. Apache refuses to start if both are loaded.
RUN rm -f /etc/apache2/mods-enabled/mpm_event.load \
           /etc/apache2/mods-enabled/mpm_event.conf \
           /etc/apache2/mods-enabled/mpm_worker.load \
           /etc/apache2/mods-enabled/mpm_worker.conf \
 && a2enmod mpm_prefork \
 && apache2ctl -t

# Use a private PHP router instead of Apache to avoid platform-specific MPM conflicts.
RUN <<'ROUTER' bash
set -e
cat > /usr/local/bin/getcontact-router.php <<'PHP_ROUTER'
<?php
// Private, single-user PHP router for Railway. No Apache MPM is needed.
$expectedPassword = getenv('ADMIN_PASSWORD') ?: '';
$providedUser = $_SERVER['PHP_AUTH_USER'] ?? '';
$providedPassword = $_SERVER['PHP_AUTH_PW'] ?? '';
if ($expectedPassword === '' || !hash_equals('admin', $providedUser) || !hash_equals($expectedPassword, $providedPassword)) {
    header('WWW-Authenticate: Basic realm="Private Getcontact Web"');
    http_response_code(401);
    header('Content-Type: text/plain; charset=utf-8');
    echo "Authorization required.\n";
    return true;
}
if (($_SERVER['HTTP_X_FORWARDED_PROTO'] ?? '') === 'https') {
    $_SERVER['HTTPS'] = 'on';
}
$path = rawurldecode(parse_url($_SERVER['REQUEST_URI'] ?? '/', PHP_URL_PATH) ?: '/');
// Only assets inside /public/ are served as files. Never expose PHP, SQL, source or configs.
if (preg_match('~^/public/(?:css|js|images)/[a-zA-Z0-9._/-]+$~', $path)
    && !str_contains($path, '..')
    && preg_match('~\.(?:css|js|webp|png|jpg|jpeg|gif|svg|ico|woff|woff2|ttf)$~i', $path)) {
    $file = '/var/www/html' . $path;
    if (is_file($file)) {
        $ext = strtolower(pathinfo($file, PATHINFO_EXTENSION));
        $mime = [
            'css' => 'text/css', 'js' => 'text/javascript', 'webp' => 'image/webp',
            'png' => 'image/png', 'jpg' => 'image/jpeg', 'jpeg' => 'image/jpeg',
            'gif' => 'image/gif', 'svg' => 'image/svg+xml', 'ico' => 'image/x-icon',
            'woff' => 'font/woff', 'woff2' => 'font/woff2', 'ttf' => 'font/ttf',
        ];
        header('Content-Type: ' . ($mime[$ext] ?? 'application/octet-stream'));
        readfile($file);
        return true;
    }
}
$_SERVER['SCRIPT_NAME'] = '/index.php';
$_SERVER['PHP_SELF'] = '/index.php';
require '/var/www/html/index.php';
return true;
PHP_ROUTER
php -l /usr/local/bin/getcontact-router.php
ROUTER

# Add Russian number input support. Getcontact/VerifyKit API support is NOT guaranteed.
RUN <<'RUSSIAN_PHONE_PATCH' bash
set -euo pipefail
cat >/tmp/patch-phone.php <<'PATCH_PHP'
<?php
function patch_exact(string $path, string $old, string $new): void {
  $body = file_get_contents($path);
  if ($body === false || !str_contains($body, $old)) {
    fwrite(STDERR, "Missing expected input in $path\n");
    exit(1);
  }
  file_put_contents($path, str_replace($old, $new, $body));
}

$serverOld = <<<'OLD'
      if (strpos($phone_number, "0") === 0) {
        $phone_number = "+62" . substr($phone_number, 1);
      } else if (
        strpos($phone_number, "62") === 0
      ) {
        $phone_number = "+" . $phone_number;
      } else if (strpos($phone_number, "-") !== false || strpos($phone_number, " ") !== false) {
        $phone_number = str_replace(["-", " "], "", $phone_number);
      } else {
OLD;
$serverNew = <<<'NEW'
      $digits = preg_replace('/\D/', '', $phone_number);
      if (preg_match('/^7\d{10}$/', $digits)) {
        $phone_number = "+" . $digits;
      } else if (preg_match('/^8\d{10}$/', $digits)) {
        $phone_number = "+7" . substr($digits, 1);
      } else {
NEW;
patch_exact('src/apis/generate_credentials.php', $serverOld, $serverNew);
patch_exact('src/apis/generate_credentials.php',
  "if (strpos(\$phone_number, '+62') === 0) {\n        \$outside_phone_number = substr(\$phone_number, 3); // cut first 3 char (+62)\n      }",
  "if (strpos(\$phone_number, '+7') === 0) {\n        \$outside_phone_number = substr(\$phone_number, 2); // strip +7 for RU VerifyKit\n      }");

$searchOld = <<<'OLD'
      if (strpos($phone_number, "0") === 0) {
        $phone_number = "+62" . substr($phone_number, 1);
      } else if (strpos($phone_number, "62") === 0) {
        $phone_number = "+" . $phone_number;
      } else if (strpos($phone_number, "-") !== false || strpos($phone_number, " ") !== false) {
        $phone_number = str_replace(["-", " "], "", $phone_number);
      } else {
OLD;
$searchNew = <<<'NEW'
      $digits = preg_replace('/\D/', '', $phone_number);
      if (preg_match('/^7\d{10}$/', $digits)) {
        $phone_number = "+" . $digits;
      } else if (preg_match('/^8\d{10}$/', $digits)) {
        $phone_number = "+7" . substr($digits, 1);
      } else {
NEW;
patch_exact('src/pages/index.php', $searchOld, $searchNew);

$genUiOld = <<<'OLD'
        } else if (!(phoneNumber.startsWith("0") || phoneNumber.startsWith("62"))) {
          $phoneInput.addClass("is-invalid");
          $phoneFeedback.text("Phone number prefix is invalid");
          isPhoneNumberValid = false;
OLD;
$genUiNew = <<<'NEW'
        } else if (!/^[78]\d{10}$/.test(phoneNumber)) {
          $phoneInput.addClass("is-invalid");
          $phoneFeedback.text("Enter a Russian number: 7XXXXXXXXXX or 8XXXXXXXXXX");
          isPhoneNumberValid = false;
NEW;
patch_exact('src/pages/dashboard/generate_credentials.php', $genUiOld, $genUiNew);

$searchUiOld = <<<'OLD'
      if (!(phoneNumber.startsWith("0") || phoneNumber.startsWith("62")))
        return setValidationState($phoneInput, false, "Phone number prefix is invalid"), false;
OLD;
$searchUiNew = <<<'NEW'
      if (!/^[78]\d{10}$/.test(phoneNumber))
        return setValidationState($phoneInput, false, "Enter Russian number: 7XXXXXXXXXX or 8XXXXXXXXXX"), false;
NEW;
patch_exact('src/pages/index.php', $searchUiOld, $searchUiNew);

foreach (['src/pages/index.php', 'src/pages/dashboard/generate_credentials.php'] as $path) {
  patch_exact($path, 'Phone Number &#127470;&#127465;', 'Phone Number &#127479;&#127482;');
  patch_exact($path, 'placeholder="62xxx / 0xxx"', 'placeholder="7XXXXXXXXXX / 8XXXXXXXXXX"');
}

$configPath = 'src/configurations/getcontact.php';
foreach ([
  'define("GTC_COUNTRY_CODE", "id");' => 'define("GTC_COUNTRY_CODE", "ru");',
  'define("GTC_CARRIER_COUNTRY_CODE", "510");' => 'define("GTC_CARRIER_COUNTRY_CODE", "250");',
  'define("GTC_CARRIER_NAME", "Indosat Ooredoo");' => 'define("GTC_CARRIER_NAME", "MTS");',
  'define("GTC_TIME_ZONE", "Asia/Bangkok");' => 'define("GTC_TIME_ZONE", "Europe/Moscow");',
  'define("GTC_OUTSIDE_COUNTRY_CODE", "ID");' => 'define("GTC_OUTSIDE_COUNTRY_CODE", "RU");',
  'define("VFK_LANG", "in_ID");' => 'define("VFK_LANG", "ru_RU");',
] as $before => $after) patch_exact($configPath, $before, $after);

PATCH_PHP
php /tmp/patch-phone.php
php -l src/apis/generate_credentials.php
php -l src/pages/index.php
php -l src/pages/dashboard/generate_credentials.php
php -l src/configurations/getcontact.php
RUSSIAN_PHONE_PATCH

# Use the real, provider-returned WhatsApp verification link. Never reconstruct
# its recipient from a hard-coded phone number in the original sample code.
RUN <<'VERIFYKIT_LINK_PATCH' bash
set -euo pipefail
cat >/tmp/patch-verifykit.php <<'PATCH_PHP'
<?php
function replace_exact(string $path, string $old, string $new): void {
  $source = file_get_contents($path);
  if ($source === false || !str_contains($source, $old)) {
    fwrite(STDERR, "Expected verification link code not found in $path\n");
    exit(1);
  }
  file_put_contents($path, str_replace($old, $new, $source));
}
$backend = 'src/apis/generate_credentials.php';
$checkOld = <<<'OLD'
      #endregion

      #region Parse and validate verification code from deeplink url
OLD;
$checkNew = <<<'NEW'
      // Only accept a WhatsApp deep link returned directly by VerifyKit.
      $linkParts = parse_url($deeplink);
      if (!is_array($linkParts)
          || strtolower($linkParts['scheme'] ?? '') !== 'https'
          || !in_array(strtolower($linkParts['host'] ?? ''),
              ['wa.me', 'api.whatsapp.com', 'web.whatsapp.com'], true)) {
        http_response_code(502);
        echo json_encode(['message' => 'VerifyKit returned an unexpected verification link']);
        exit();
      }

      #endregion

      #region Parse and validate verification code from deeplink url
NEW;
replace_exact($backend, $checkOld, $checkNew);
replace_exact($backend,
  '"verificationCode" => $verification_code, // for public view',
  '"verificationCode" => $verification_code, // for public view' . "\n        \"verifyLink\" => \$deeplink,");

$frontend = 'src/pages/dashboard/generate_credentials.php';
replace_exact($frontend,
  'const deeplinkWhatsappDesktopMobile = `https://api.whatsapp.com/send/?phone=905397766590&type=phone_number&app_absent=0&text=${response.verificationCode}`;',
  "const deeplinkWhatsappDesktopMobile = response.verifyLink;\n        if (!deeplinkWhatsappDesktopMobile || !/^https:\\/\\/(?:wa\\.me|api\\.whatsapp\\.com|web\\.whatsapp\\.com)\\//i.test(deeplinkWhatsappDesktopMobile)) {\n          throw new Error('VerifyKit returned an invalid WhatsApp verification link');\n        }");
replace_exact($frontend,
  'const deeplinkWhatsappWeb = `https://web.whatsapp.com/send?phone=905397766590&text=${response.verificationCode}`;',
  'const deeplinkWhatsappWeb = response.verifyLink;');
replace_exact($frontend, '>WhatsApp Web</div>', '>VerifyKit WhatsApp link</div>');
PATCH_PHP
php -l /tmp/patch-verifykit.php
php /tmp/patch-verifykit.php
php -l src/apis/generate_credentials.php
php -l src/pages/dashboard/generate_credentials.php
VERIFYKIT_LINK_PATCH


# Correct hard-coded Indonesian country headers in Getcontact requests.
# Keep authentication secrets and API payloads out of Railway logs.
RUN <<'PATCH_RU_HEADERS' bash
set -euo pipefail
cat > /tmp/patch-ru-headers.php <<'PHP_PATCH'
<?php
$path='src/libraries/getcontact.php';
$source=file_get_contents($path);
$old='"x-country-code: id"';
$count=substr_count($source,$old);
if($count < 1){fwrite(STDERR,"Country header not found; inspect upstream code.\n");exit(1);}
$source=str_replace($old,'"x-country-code: " . GTC_COUNTRY_CODE',$source);
file_put_contents($path,$source);
echo "Updated $count hard-coded country headers.\n";

$path='src/libraries/helper.php';
$source=file_get_contents($path);
$pattern='/  function log_api_transaction\(\$request, \$response, \$label = "API"\)\s*\{.*?\n  \}/s';
$replacement=<<<'SAFE'
  function log_api_transaction($request, $response, $label = "API")
  {
    $code = isset($response->httpCode) ? (int)$response->httpCode : 0;
    error_log("GetContact [$label] HTTP $code (API bodies redacted)");
  }
SAFE;
$source=preg_replace($pattern,$replacement,$source,1,$count);
if($count!==1){fwrite(STDERR,"Credential logging replacement failed.\n");exit(1);}
$source=preg_replace('/^\s*error_log\("(?:Header|Body): " \. .*?\);\r?\n/m','',$source);
file_put_contents($path,$source);

foreach (['src/apis/generate_credentials.php','src/pages/index.php','src/apis/subscription.php'] as $path) {
  $source=file_get_contents($path);
  foreach (['$api_response->body','$decrypted_data_raw','$raw_json','$api_response_body->data'] as $variable) {
    $source=str_replace('error_log('.$variable.');','/* API body logging disabled. */',$source);
  }
  if ($path==='src/apis/generate_credentials.php') {
    $privateLog=<<<'PRIVATELOG'
      error_log(json_encode([
        "phoneNumber" => $phone_number,
        "clientDeviceId" => $client_device_id,
        "token" => $token,
        "finalKey" => $final_key,
        "validationDate" => $validation_date,
      ], JSON_PRETTY_PRINT));
PRIVATELOG;
    if(!str_contains($source,$privateLog)){fwrite(STDERR,"Success credential log was not found.\n");exit(1);}
    $source=str_replace($privateLog,'// Successful validation. Do not log credentials.',$source);
  }
  file_put_contents($path,$source);
}
PHP_PATCH
php -l /tmp/patch-ru-headers.php
php /tmp/patch-ru-headers.php
for f in src/libraries/getcontact.php src/libraries/helper.php src/apis/generate_credentials.php src/pages/index.php src/apis/subscription.php; do php -l "$f"; done
PATCH_RU_HEADERS

EXPOSE 80
CMD ["php", "-S", "0.0.0.0:80", "-t", "/var/www/html", "/usr/local/bin/getcontact-router.php"]
