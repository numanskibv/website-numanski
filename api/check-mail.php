<?php
/**
 * Numanski — SMTP diagnose tool.
 *
 * Draai vanuit de container:
 *   docker compose exec php php /var/www/api/check-mail.php
 *
 * Doet NIETS daadwerkelijk versturen — handshaket alleen tot AUTH OK
 * en quit dan. Veilig om herhaaldelijk te draaien.
 */
declare(strict_types=1);

function pr(string $sym, string $msg, string $color): void {
    fwrite(STDOUT, "\033[{$color}m{$sym}  {$msg}\033[0m\n");
}
function ok(string $m):    void { pr('✓', $m, '32'); }
function bad(string $m):   void { pr('✗', $m, '31'); fwrite(STDOUT, "\n"); exit(1); }
function info(string $m):  void { pr('·', $m, '90'); }
function step(string $m):  void { fwrite(STDOUT, "\n\033[1;36m── $m ──\033[0m\n"); }

// ─── 1. Config inlezen (zelfde manier als send-mail.php) ──────────
step('1. Configuratie');
$host = getenv('SMTP_HOST') ?: 'smtp.gmail.com';
$port = (int) (getenv('SMTP_PORT') ?: 587);
$user = getenv('SMTP_USER') ?: '';
$mailTo  = getenv('MAIL_TO') ?: '';
$allowed = getenv('ALLOWED_ORIGIN') ?: '';

$passFile = getenv('SMTP_PASS_FILE') ?: '';
$pass = '';
if ($passFile !== '' && is_readable($passFile)) {
    $pass = rtrim((string) file_get_contents($passFile), "\r\n");
} elseif (getenv('SMTP_PASS')) {
    $pass = (string) getenv('SMTP_PASS');
}

$user    === '' && bad('SMTP_USER is leeg — vul .env in en herstart');
ok("SMTP_USER     = $user");
$passFile !== '' ? ok("SMTP_PASS_FILE = $passFile") : info('SMTP_PASS_FILE niet gezet — val terug op env-var');
$pass    === '' && bad('Password niet ingelezen — secrets/smtp_pass leeg of mount mist');
ok('Password lengte: ' . strlen($pass) . ' chars (Google App Password is 16 chars zonder spaties)');
$mailTo  === '' && bad('MAIL_TO is leeg');
ok("MAIL_TO       = $mailTo");
$allowed === '' && bad('ALLOWED_ORIGIN is leeg');
ok("ALLOWED_ORIGIN = $allowed");

// ─── 2. DNS ───────────────────────────────────────────────────────
step('2. DNS-resolve');
$ip = gethostbyname($host);
$ip === $host && bad("DNS-lookup voor $host faalt — geen outbound DNS?");
ok("$host → $ip");

// ─── 3. TCP connect ───────────────────────────────────────────────
step('3. TCP open ' . $host . ':' . $port);
$sock = @stream_socket_client("tcp://$host:$port", $errno, $errstr, 10);
if ($sock === false) {
    bad("Connect mislukt: $errstr ($errno) — host blokt mogelijk uitgaand 587?");
}
stream_set_timeout($sock, 10);
ok('TCP open');

// ─── 4. SMTP banner ───────────────────────────────────────────────
step('4. SMTP banner');
$banner = fgets($sock, 1024);
str_starts_with((string) $banner, '220') || bad("Geen 220-banner: " . trim((string) $banner));
ok('Banner: ' . trim((string) $banner));

// helper voor multi-line replies
$readReply = function () use ($sock): string {
    $buf = '';
    while (($l = fgets($sock, 1024)) !== false) {
        $buf .= $l;
        if (preg_match('/^\d{3} /', $l)) {
            break;
        }
    }
    return $buf;
};

// ─── 5. EHLO ──────────────────────────────────────────────────────
step('5. EHLO (plain)');
fwrite($sock, "EHLO numanski.nl\r\n");
$r = $readReply();
str_starts_with($r, '250') || bad('EHLO afgewezen: ' . trim($r));
ok('EHLO OK');

// ─── 6. STARTTLS ──────────────────────────────────────────────────
step('6. STARTTLS');
fwrite($sock, "STARTTLS\r\n");
$r = fgets($sock, 1024);
str_starts_with((string) $r, '220') || bad('STARTTLS afgewezen: ' . trim((string) $r));
ok('Server: ready voor TLS');

$ok = stream_socket_enable_crypto(
    $sock, true,
    STREAM_CRYPTO_METHOD_TLSv1_2_CLIENT | STREAM_CRYPTO_METHOD_TLSv1_3_CLIENT
);
$ok || bad('TLS-handshake faalde — CA bundle ontbreekt? Cert-verify niet gelukt?');
ok('TLS-handshake OK (cert-verify aan)');

// ─── 7. EHLO na TLS ───────────────────────────────────────────────
step('7. EHLO (na TLS)');
fwrite($sock, "EHLO numanski.nl\r\n");
$r = $readReply();
str_starts_with($r, '250') || bad('EHLO faalde na TLS: ' . trim($r));
ok('EHLO OK');

// ─── 8. AUTH LOGIN ────────────────────────────────────────────────
step('8. AUTH LOGIN');
fwrite($sock, "AUTH LOGIN\r\n");
$r = fgets($sock, 1024);
str_starts_with((string) $r, '334') || bad('AUTH LOGIN afgewezen: ' . trim((string) $r));

fwrite($sock, base64_encode($user) . "\r\n");
$r = fgets($sock, 1024);
str_starts_with((string) $r, '334') || bad('Username afgewezen: ' . trim((string) $r));
ok('Username geaccepteerd');

fwrite($sock, base64_encode($pass) . "\r\n");
$r = fgets($sock, 1024);
if (!str_starts_with((string) $r, '235')) {
    bad('AUTH FAILED: ' . trim((string) $r)
        . "\n\n   Meest waarschijnlijk:"
        . "\n   • Geen App Password gebruikt (regulier account-wachtwoord werkt NIET met SMTP)"
        . "\n   • App Password ingetrokken of niet meer geldig"
        . "\n   • 2-Step Verification staat uit op het Workspace-account"
        . "\n   • Spaties NIET strippen — Google geeft de code als 'aaaa bbbb cccc dddd', plak met spaties");
}
ok('AUTH OK — credentials werken!');

// ─── 9. Quit beleefd ──────────────────────────────────────────────
fwrite($sock, "QUIT\r\n");
@fgets($sock, 1024);
@fclose($sock);

fwrite(STDOUT, "\n");
pr('✓', 'ALLE SMTP-CHECKS GESLAAGD.', '1;32');
fwrite(STDOUT, "\n");
info('Test het endpoint nu end-to-end met curl:');
fwrite(STDOUT, "\n");
fwrite(STDOUT, "  curl -i -X POST '$allowed/api/send-mail' \\\n");
fwrite(STDOUT, "    -H 'Origin: $allowed' \\\n");
fwrite(STDOUT, "    -H 'Content-Type: application/json' \\\n");
fwrite(STDOUT, "    -d '{\"type\":\"contact\",\"name\":\"Diag\",\"email\":\"test@example.com\",\"message\":\"diag\"}'\n\n");
