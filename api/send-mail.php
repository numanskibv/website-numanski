<?php
/**
 * Numanski.nl — mail endpoint.
 * Zero-dependency: raw STARTTLS SMTP-client via stream_socket_client().
 * Doel: contact- en Quickscan-submissies doorsturen naar marco@numanski.nl.
 *
 * Beveiliging: origin-check, honeypot, rate-limit per IP, header-injection
 * stripping, dot-stuffing per RFC 5321, generieke 200-response (geen oracle).
 */
declare(strict_types=1);

// ─── Helper: secret uit file óf env (Docker-secret-friendly) ────────
function read_secret(string $name): string {
    $file = getenv($name . '_FILE');
    if ($file !== false && $file !== '' && is_readable($file)) {
        return rtrim((string) file_get_contents($file), "\r\n");
    }
    $val = getenv($name);
    return $val === false ? '' : $val;
}

// ─── Config (uit env / secrets) ─────────────────────────────────────
$cfg = [
    'smtp_host'      => getenv('SMTP_HOST') ?: 'smtp.gmail.com',
    'smtp_port'      => (int) (getenv('SMTP_PORT') ?: 587),
    'smtp_user'      => read_secret('SMTP_USER'),
    'smtp_pass'      => read_secret('SMTP_PASS'),
    'mail_to'        => getenv('MAIL_TO')   ?: '',
    'allowed_origin' => getenv('ALLOWED_ORIGIN') ?: '',
    'rate_limit'     => 5,        // requests per IP per window
    'rate_window'    => 3600,     // 1 uur
    'rate_dir'       => '/tmp/numanski-rl',
    'max_body'       => 8192,     // bytes
];

// ─── Hard fail als config niet compleet is (in plaats van stil falen) ─
if ($cfg['smtp_user'] === '' || $cfg['smtp_pass'] === ''
    || $cfg['mail_to'] === '' || $cfg['allowed_origin'] === '') {
    error_log('[numanski-mail] FATAL: config incomplete');
    http_response_code(500);
    exit;
}

// ─── Generieke responses (geen verschil tussen fail-modes → geen oracle) ──
function ok(): never  { http_response_code(200); header('Content-Type: application/json'); echo '{"ok":true}';  exit; }
function bad(int $c): never { http_response_code($c); header('Content-Type: application/json'); echo '{"ok":false}'; exit; }

// ─── Method-gate ────────────────────────────────────────────────────
if (($_SERVER['REQUEST_METHOD'] ?? '') !== 'POST') { bad(405); }

// ─── Origin-gate (strikt: exacte match) ─────────────────────────────
$origin = $_SERVER['HTTP_ORIGIN'] ?? '';
if ($origin !== $cfg['allowed_origin']) { bad(403); }

// ─── Content-Type moet JSON zijn (geen multipart/url-encoded) ───────
$ct = $_SERVER['CONTENT_TYPE'] ?? '';
if (stripos($ct, 'application/json') !== 0) { bad(415); }

// ─── Body-grootte + JSON-parse (strict) ─────────────────────────────
$raw = file_get_contents('php://input') ?: '';
if (strlen($raw) === 0 || strlen($raw) > $cfg['max_body']) { bad(413); }

try {
    $data = json_decode($raw, true, 4, JSON_THROW_ON_ERROR);
} catch (JsonException) {
    bad(400);
}
if (!is_array($data)) { bad(400); }

// ─── Honeypot (bots vullen vaak een veld 'website' in) ──────────────
if (!empty($data['website'])) { ok(); }   // stil 200 — bot weet niets

// ─── Rate-limit per IP (flat-file, geen Redis) ──────────────────────
$ip      = $_SERVER['REMOTE_ADDR'] ?? '0.0.0.0';
$ipHash  = hash('sha256', $ip);
@mkdir($cfg['rate_dir'], 0700, true);
$rlFile = $cfg['rate_dir'] . '/' . $ipHash;
$now    = time();
$hits   = [];
if (is_file($rlFile)) {
    $hits = array_filter(
        array_map('intval', file($rlFile, FILE_IGNORE_NEW_LINES)),
        fn($t) => $t > $now - $cfg['rate_window']
    );
}
if (count($hits) >= $cfg['rate_limit']) { ok(); }   // stil 200
$hits[] = $now;
@file_put_contents($rlFile, implode("\n", $hits));

// ─── Build mail per type ────────────────────────────────────────────
$type = (string) ($data['type'] ?? '');
[$subject, $body, $replyTo] = match ($type) {
    'contact'   => build_contact($data),
    'quickscan' => build_quickscan($data),
    default     => [null, null, null],
};
if ($subject === null) { bad(400); }

// ─── Verstuur ───────────────────────────────────────────────────────
$ok = smtp_send(
    $cfg['smtp_host'], $cfg['smtp_port'],
    $cfg['smtp_user'], $cfg['smtp_pass'],
    $cfg['smtp_user'], $cfg['mail_to'],
    $replyTo, $subject, $body
);
error_log(sprintf('[numanski-mail] type=%s ip=%s ok=%s',
    $type, substr($ipHash, 0, 12), $ok ? '1' : '0'));

// Altijd 200 — visitor mag niet weten of de mail wel/niet aankwam (geen oracle).
ok();


/* ─── Builders ──────────────────────────────────────────────────────── */

function build_contact(array $d): array {
    $name    = clean_line((string) ($d['name']    ?? ''), 100);
    $email   = clean_email((string) ($d['email']  ?? ''));
    $message = clean_text((string) ($d['message'] ?? ''), 4000);
    if ($name === '' || $email === '' || $message === '') {
        return [null, null, null];
    }
    $body = "Naam:    $name\n"
          . "E-mail:  $email\n"
          . "\n"
          . "Bericht:\n"
          . "--------\n"
          . "$message\n";
    return ['Numanski.nl — contactformulier', $body, $email];
}

function build_quickscan(array $d): array {
    $email = clean_email((string) ($d['email'] ?? ''));
    if ($email === '') { return [null, null, null]; }
    $p     = clean_line((string) ($d['p']     ?? ''), 20);
    $s     = clean_line((string) ($d['s']     ?? ''), 20);
    $o     = clean_line((string) ($d['o']     ?? ''), 20);
    $score = is_numeric($d['score'] ?? null) ? (int) $d['score'] : -1;
    $level = clean_line((string) ($d['level'] ?? ''), 20);
    $body  = "E-mail:      $email\n"
           . "Niveau:      $level (score $score van 6)\n"
           . "\n"
           . "Antwoorden\n"
           . "----------\n"
           . "Processen:   $p\n"
           . "Systemen:    $s\n"
           . "Organisatie: $o\n";
    $subject = sprintf('Numanski.nl — PSO Quickscan (%s)', $level !== '' ? $level : 'onbekend');
    return [$subject, $body, $email];
}


/* ─── Sanitizers ───────────────────────────────────────────────────── */

/** Single-line, strip CR/LF (header-injection guard), byte-cap. */
function clean_line(string $s, int $max): string {
    $s = trim($s);
    $s = str_replace(["\r", "\n", "\0"], '', $s);
    return substr($s, 0, $max);
}

function clean_email(string $s): string {
    $s = clean_line($s, 254);
    return filter_var($s, FILTER_VALIDATE_EMAIL) ? $s : '';
}

/** Multi-line tekst: CRLF→LF normaliseren, NUL strippen, cap. */
function clean_text(string $s, int $max): string {
    $s = str_replace(["\r\n", "\r", "\0"], ["\n", "\n", ''], $s);
    return substr(trim($s), 0, $max);
}


/* ─── Raw SMTP client (STARTTLS + AUTH LOGIN) ──────────────────────── */

function smtp_send(
    string $host, int $port,
    string $user, string $pass,
    string $from, string $to, string $replyTo,
    string $subject, string $body
): bool {
    $ctx = stream_context_create([
        'ssl' => [
            'verify_peer'      => true,
            'verify_peer_name' => true,
            'SNI_enabled'      => true,
        ],
    ]);
    $sock = @stream_socket_client(
        "tcp://$host:$port",
        $errno, $errstr, 10,
        STREAM_CLIENT_CONNECT, $ctx
    );
    if (!$sock) {
        error_log("[smtp] connect failed: $errstr ($errno)");
        return false;
    }
    stream_set_timeout($sock, 15);

    $expect = function (int $code) use ($sock): bool {
        $line = '';
        while (($l = fgets($sock, 1024)) !== false) {
            $line .= $l;
            if (preg_match('/^\d{3} /', $l)) { break; }
        }
        if (!str_starts_with($line, (string) $code)) {
            error_log('[smtp] unexpected reply: ' . trim($line));
            return false;
        }
        return true;
    };
    $send = static fn(string $cmd) => fwrite($sock, $cmd . "\r\n");

    try {
        if (!$expect(220)) { return false; }

        $send('EHLO numanski.nl');
        if (!$expect(250)) { return false; }

        $send('STARTTLS');
        if (!$expect(220)) { return false; }
        if (!stream_socket_enable_crypto(
                $sock, true,
                STREAM_CRYPTO_METHOD_TLSv1_2_CLIENT | STREAM_CRYPTO_METHOD_TLSv1_3_CLIENT
        )) {
            error_log('[smtp] TLS handshake failed');
            return false;
        }

        $send('EHLO numanski.nl');
        if (!$expect(250)) { return false; }

        $send('AUTH LOGIN');
        if (!$expect(334)) { return false; }
        $send(base64_encode($user));
        if (!$expect(334)) { return false; }
        $send(base64_encode($pass));
        if (!$expect(235)) { return false; }

        $send("MAIL FROM:<$from>");
        if (!$expect(250)) { return false; }
        $send("RCPT TO:<$to>");
        if (!$expect(250)) { return false; }

        $send('DATA');
        if (!$expect(354)) { return false; }

        $headers = [
            "From: Numanski Website <$from>",
            "To: <$to>",
            "Reply-To: <$replyTo>",
            'Subject: =?UTF-8?B?' . base64_encode($subject) . '?=',
            'MIME-Version: 1.0',
            'Content-Type: text/plain; charset=UTF-8',
            'Content-Transfer-Encoding: 8bit',
            'Date: ' . date('r'),
            'Message-ID: <' . bin2hex(random_bytes(8)) . '@numanski.nl>',
            'X-Mailer: Numanski-site (vanilla PHP)',
        ];
        // Dot-stuffing per RFC 5321 §4.5.2: lijnen die met '.' beginnen → '..'
        $safeBody = preg_replace('/^\./m', '..', $body);
        fwrite($sock, implode("\r\n", $headers) . "\r\n\r\n" . $safeBody . "\r\n.\r\n");
        if (!$expect(250)) { return false; }

        $send('QUIT');
        $expect(221);
        return true;
    } finally {
        @fclose($sock);
    }
}
