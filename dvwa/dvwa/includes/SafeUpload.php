<?php
/**
 * SafeUpload — безпечне приймання зображень, завантажених користувачем (РГР, варіант 8).
 *
 * Усуває V1–V3, V7 і T7/T9. Заходи, кожен з яких окремо блокує принаймні одну атаку:
 *   1. allowlist розширень (jpg, jpeg, png): .php, .phtml, .htaccess, .rgrXXXX відхиляються;
 *   2. тип визначається за вмістом на сервері (finfo), заголовок Content-Type від клієнта ігнорується;
 *   3. розширення має відповідати фактичному типу вмісту;
 *   4. зображення декодується й перекодовується через GD, тож дописаний PHP-код (поліглот) знищується;
 *   5. ім'я файлу генерується сервером (random_bytes), тож перезапис і передбачуване ім'я неможливі;
 *   6. обмеження розміру файлу та розмірів зображення (захист від «бомб» декомпресії);
 *   7. у відповідь потрапляє лише публічне ім'я, без внутрішнього шляху (T9); кожне рішення журналюється (T13).
 */
final class SafeUpload
{
    public const MAX_BYTES = 100000;
    public const MAX_PIXELS = 4096 * 4096;

    /** розширення => MIME-тип, визначений за вмістом */
    private const ALLOWED = [
        'jpg'  => 'image/jpeg',
        'jpeg' => 'image/jpeg',
        'png'  => 'image/png',
    ];

    /**
     * Перевіряє файл без запису на диск. Повертає [ok, reason, ext].
     *
     * @return array{0: bool, 1: string, 2: string}
     */
    public static function inspect(string $tmpPath, string $clientName, int $size): array
    {
        if ($size <= 0 || $size > self::MAX_BYTES || !is_file($tmpPath) || filesize($tmpPath) > self::MAX_BYTES) {
            return [false, 'size', ''];
        }
        $ext = strtolower(pathinfo($clientName, PATHINFO_EXTENSION));
        if (!array_key_exists($ext, self::ALLOWED) || str_starts_with(basename($clientName), '.')) {
            return [false, 'extension', $ext];
        }
        $mime = (new finfo(FILEINFO_MIME_TYPE))->file($tmpPath);
        if ($mime !== self::ALLOWED[$ext]) {
            return [false, 'content-type mismatch: ' . $mime, $ext];
        }
        $info = @getimagesize($tmpPath);
        if ($info === false || $info['mime'] !== $mime) {
            return [false, 'not an image', $ext];
        }
        if ($info[0] < 1 || $info[1] < 1 || $info[0] * $info[1] > self::MAX_PIXELS) {
            return [false, 'dimensions', $ext];
        }
        return [true, 'ok', $ext];
    }

    /**
     * Приймає файл із $_FILES і зберігає перекодовану копію у $destDir.
     * Повертає [ok, повідомлення для користувача, публічне ім'я або null].
     *
     * @param array<string, mixed> $file елемент масиву $_FILES
     * @return array{0: bool, 1: string, 2: ?string}
     */
    public static function store(array $file, string $destDir, bool $requireUploaded = true): array
    {
        $tmp = (string) ($file['tmp_name'] ?? '');
        $name = (string) ($file['name'] ?? '');
        if (($file['error'] ?? UPLOAD_ERR_NO_FILE) !== UPLOAD_ERR_OK
            || ($requireUploaded && !is_uploaded_file($tmp))) {
            return self::reject($name, 'upload error');
        }
        [$ok, $reason, $ext] = self::inspect($tmp, $name, (int) ($file['size'] ?? 0));
        if (!$ok) {
            return self::reject($name, $reason);
        }
        $dir = realpath($destDir);
        if ($dir === false || !is_dir($dir) || !is_writable($dir)) {
            return self::reject($name, 'destination not writable');
        }
        $publicName = bin2hex(random_bytes(16)) . '.' . ($ext === 'jpeg' ? 'jpg' : $ext);
        if (!self::reencode($tmp, self::ALLOWED[$ext], $dir . DIRECTORY_SEPARATOR . $publicName)) {
            return self::reject($name, 're-encode failed');
        }
        self::log($name, 'accepted as ' . $publicName);
        return [true, 'Зображення завантажено: ' . $publicName, $publicName];
    }

    private static function reencode(string $src, string $mime, string $dest): bool
    {
        $img = $mime === 'image/png' ? @imagecreatefrompng($src) : @imagecreatefromjpeg($src);
        if ($img === false) {
            return false;
        }
        $written = $mime === 'image/png' ? imagepng($img, $dest, 9) : imagejpeg($img, $dest, 90);
        unset($img);
        if ($written) {
            @chmod($dest, 0644);
        }
        return $written;
    }

    /** @return array{0: bool, 1: string, 2: null} */
    private static function reject(string $name, string $reason): array
    {
        self::log($name, 'rejected: ' . $reason);
        return [false, 'Зображення не завантажено. Дозволено лише JPEG або PNG до 100 КБ.', null];
    }

    private static function log(string $name, string $decision): void
    {
        $user = function_exists('dvwaCurrentUser') ? (string) @dvwaCurrentUser() : '-';
        error_log(sprintf('[rgr-security] op=upload user=%s name=%s %s',
            $user, json_encode(substr($name, 0, 200), JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_INVALID_UTF8_SUBSTITUTE), $decision));
    }
}
