<?php
// upload.php
// Run: php -S 127.0.0.1:8080 upload.php
// POST to: http://127.0.0.1:8080/upload

declare(strict_types=1);

function reply(int $code, string $body, string $ctype = 'text/plain; charset=utf-8'): void {
    http_response_code($code);
    header('Content-Type: ' . $ctype);
    echo $body;
    exit;
}

$uri = parse_url($_SERVER['REQUEST_URI'] ?? '/', PHP_URL_PATH);
if ($uri !== '/upload') {
    reply(404, "Not Found\n");
}

if (($_SERVER['REQUEST_METHOD'] ?? 'GET') !== 'POST') {
    reply(405, "Method Not Allowed\n");
}

$raw = file_get_contents('php://input');
if ($raw === false || trim($raw) === '') {
    reply(400, "Empty body\n");
}

$ct = strtolower($_SERVER['CONTENT_TYPE'] ?? '');
if ($ct !== '' && strpos($ct, 'application/json') === false) {
    error_log("WARN: Content-Type is not application/json: " . $ct);
}

$data = json_decode($raw, true);
if ($data === null && json_last_error() !== JSON_ERROR_NONE) {
    reply(400, "Bad JSON: " . json_last_error_msg() . "\n");
}

error_log("=== UPLOAD JSON START ===");
error_log($raw);
error_log("=== UPLOAD JSON END ===");

$pretty = json_encode($data, JSON_UNESCAPED_UNICODE | JSON_PRETTY_PRINT);
reply(200, $pretty . "\n", 'application/json; charset=utf-8');
