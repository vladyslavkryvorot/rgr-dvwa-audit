<?php
/**
 * SafePath — безпечне перетворення даних користувача на шлях до файлу (РГР, варіант 8).
 *
 * Усуває V4–V6 (fi/), V8 (view_source.php), V9 (view_help.php).
 * Принцип: спочатку allowlist (порівняння з точним переліком дозволених значень), потім канонізація
 * realpath() і перевірка, що результат лежить усередині базового каталогу (глибокий захист).
 * Будь-яка неоднозначність трактується як відмова (fail closed).
 */
final class SafePath
{
    /** Ідентифікатор сегмента шляху: модуль, рівень безпеки, локаль. */
    private const SEGMENT_RE = '/^[a-z0-9_]{1,32}$/';

    /**
     * Повертає абсолютний шлях до дозволеного файлу або null.
     *
     * @param string   $requested значення з запиту (наприклад, $_GET['page'])
     * @param string   $baseDir   каталог, у межах якого дозволено файли
     * @param string[] $allowlist точні імена дозволених файлів відносно $baseDir
     */
    public static function resolveInclude(string $requested, string $baseDir, array $allowlist): ?string
    {
        if (!self::looksLikePlainRelativeName($requested)) {
            self::log('include', $requested, 'rejected: scheme/absolute/traversal/control chars');
            return null;
        }
        if (!in_array($requested, $allowlist, true)) {
            self::log('include', $requested, 'rejected: not in allowlist');
            return null;
        }
        return self::within($baseDir, $requested);
    }

    /** Рівень безпеки DVWA з точного переліку. */
    public static function isSecurityLevel(string $value): bool
    {
        return in_array($value, ['low', 'medium', 'high', 'impossible'], true);
    }

    /** Ідентифікатор модуля: безпечний сегмент, для якого існує каталог $vulnRoot/<id>/<subdir>. */
    public static function isModuleId(string $id, string $vulnRoot, string $subdir): bool
    {
        return self::isSafeSegment($id) && is_dir($vulnRoot . DIRECTORY_SEPARATOR . $id . DIRECTORY_SEPARATOR . $subdir);
    }

    /** Чи є значення безпечним ідентифікатором сегмента (лише [a-z0-9_]). */
    public static function isSafeSegment(string $value): bool
    {
        return preg_match(self::SEGMENT_RE, $value) === 1;
    }

    /**
     * Канонізує $baseDir/$relative і повертає шлях, лише якщо він існує, є файлом
     * і знаходиться всередині $baseDir.
     */
    public static function within(string $baseDir, string $relative): ?string
    {
        $base = realpath($baseDir);
        if ($base === false || !self::looksLikePlainRelativeName($relative)) {
            return null;
        }
        $candidate = realpath($base . DIRECTORY_SEPARATOR . $relative);
        if ($candidate === false || !is_file($candidate)) {
            return null;
        }
        if (strncmp($candidate, $base . DIRECTORY_SEPARATOR, strlen($base) + 1) !== 0) {
            self::log('path', $relative, 'rejected: outside base directory');
            return null;
        }
        return $candidate;
    }

    /**
     * Відкидає обгортки потоків (file://, php://, data:, zip:// …), абсолютні шляхи,
     * сегменти «..», зворотні косі риски, NUL та керівні символи, а також URL-кодування.
     */
    private static function looksLikePlainRelativeName(string $value): bool
    {
        if ($value === '' || strlen($value) > 255) {
            return false;
        }
        if (preg_match('/[\x00-\x1f\x7f\\\\%]/', $value)) {
            return false;
        }
        if (preg_match('#^[a-z][a-z0-9+.\-]*:#i', $value)) {   // будь-яка схема/обгортка
            return false;
        }
        if ($value[0] === '/' || $value[0] === '~') {
            return false;
        }
        foreach (explode('/', $value) as $segment) {
            if ($segment === '..' || $segment === '.' || $segment === '') {
                return false;
            }
        }
        return true;
    }

    private static function log(string $op, string $value, string $decision): void
    {
        $user = function_exists('dvwaCurrentUser') ? (string) @dvwaCurrentUser() : '-';
        error_log(sprintf('[rgr-security] op=%s user=%s value=%s %s',
            $op, $user, json_encode(substr($value, 0, 200), JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_INVALID_UTF8_SUBSTITUTE), $decision));
    }
}
