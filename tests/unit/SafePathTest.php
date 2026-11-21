<?php
declare(strict_types=1);

use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/**
 * SafePath: включення файлів (V4–V6) і службові сторінки (V8, V9).
 * Вектори атак узято з етапу 3 та з типових варіантів обходу фільтрів (OWASP WSTG-ATHZ-01).
 */
final class SafePathTest extends TestCase
{
    private const ALLOW = ['include.php', 'file1.php', 'file2.php', 'file3.php'];
    private static string $base;

    public static function setUpBeforeClass(): void
    {
        self::$base = dirname(__DIR__, 2) . '/dvwa/vulnerabilities/fi';
    }

    public function testAllowedPagesResolveToFilesInsideModule(): void
    {
        foreach (self::ALLOW as $page) {
            $path = SafePath::resolveInclude($page, self::$base, self::ALLOW);
            self::assertSame(realpath(self::$base . '/' . $page), $path);
        }
    }

    /** @return iterable<string, array{string}> */
    public static function attackVectors(): iterable
    {
        yield 'V4 relative traversal'        => ['../../../../../../etc/passwd'];
        yield 'V5 nested ....//'             => ['....//....//....//etc/passwd'];
        yield 'V5 absolute path'             => ['/etc/passwd'];
        yield 'V6 file:// wrapper'           => ['file:///etc/passwd'];
        yield 'V3 file:// to upload'         => ['file:///var/www/html/hackable/uploads/x.jpg'];
        yield 'php://filter source leak'     => ['php://filter/convert.base64-encode/resource=include.php'];
        yield 'data: wrapper'                => ['data://text/plain;base64,PD9waHAgcGhwaW5mbygpOyA/Pg=='];
        yield 'remote http'                  => ['http://127.0.0.1/evil.txt'];
        yield 'zip/phar wrapper'             => ['phar://../../hackable/uploads/x.jpg/a'];
        yield 'url-encoded traversal'        => ['%2e%2e%2f%2e%2e%2fetc%2fpasswd'];
        yield 'NUL byte'                     => ["file1.php\0.jpg"];
        yield 'backslash traversal'          => ['..\\..\\etc\\passwd'];
        yield 'allowlisted name after ../'   => ['../fi/file1.php'];
        yield 'dot segment'                  => ['./file1.php'];
        yield 'hidden bonus file4'           => ['file4.php'];
        yield 'case variation'               => ['FILE1.php'];
        yield 'trailing slash'               => ['file1.php/'];
        yield 'empty'                        => [''];
        yield 'home dir'                     => ['~/.bashrc'];
    }

    #[DataProvider('attackVectors')]
    public function testAttackVectorsAreRejected(string $vector): void
    {
        self::assertNull(SafePath::resolveInclude($vector, self::$base, self::ALLOW));
    }

    public function testAllowlistEntryThatEscapesBaseIsStillRejected(): void
    {
        // Навіть помилковий запис у allowlist не дає вийти за межі каталогу (глибокий захист).
        self::assertNull(SafePath::resolveInclude('../../../etc/passwd', self::$base, ['../../../etc/passwd']));
        self::assertNull(SafePath::within(self::$base, '../include.php'));
    }

    public function testWithinRejectsSymlinkEscapingBase(): void
    {
        $dir = sys_get_temp_dir() . '/rgr-safepath-' . bin2hex(random_bytes(4));
        mkdir($dir);
        symlink('/etc/passwd', $dir . '/link.php');
        try {
            self::assertNull(SafePath::within($dir, 'link.php'), 'symlink поза базовим каталогом');
        } finally {
            unlink($dir . '/link.php');
            rmdir($dir);
        }
    }

    /** @return iterable<string, array{string, bool}> */
    public static function moduleIds(): iterable
    {
        yield 'existing module'     => ['upload', true];
        yield 'V8 traversal'        => ['../../config', false];
        yield 'V9 locale traversal' => ['x/../../../../phpinfo', false];
        yield 'missing module'      => ['nosuchmodule', false];
        yield 'uppercase'           => ['Upload', false];
        yield 'xss'                 => ['"><script>', false];
    }

    #[DataProvider('moduleIds')]
    public function testModuleIdValidation(string $id, bool $expected): void
    {
        $root = dirname(__DIR__, 2) . '/dvwa/vulnerabilities';
        self::assertSame($expected, SafePath::isModuleId($id, $root, 'source'));
    }

    public function testSecurityLevelIsExactAllowlist(): void
    {
        foreach (['low', 'medium', 'high', 'impossible'] as $level) {
            self::assertTrue(SafePath::isSecurityLevel($level));
        }
        foreach (['../../../config/config.inc', 'LOW', 'low ', '', 'impossible.php'] as $bad) {
            self::assertFalse(SafePath::isSecurityLevel($bad), $bad);
        }
    }
}
