<?php
declare(strict_types=1);

use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/**
 * SafeUpload: завантаження файлів (V1–V3, V7, T7, T9).
 * Фікстури генеруються в тимчасовому каталозі під час тесту (синтетичні дані).
 */
final class SafeUploadTest extends TestCase
{
    private const PHP = '<?php echo "RGR-V8-" . (7*191); ?>';
    private string $tmp;
    private string $dest;

    protected function setUp(): void
    {
        $this->tmp = sys_get_temp_dir() . '/rgr-upload-' . bin2hex(random_bytes(4));
        $this->dest = $this->tmp . '/uploads';
        mkdir($this->dest, 0755, true);
    }

    protected function tearDown(): void
    {
        foreach (glob($this->tmp . '/{,uploads/}{,.}*', GLOB_BRACE) ?: [] as $f) {
            if (is_file($f)) {
                unlink($f);
            }
        }
        @rmdir($this->dest);
        @rmdir($this->tmp);
    }

    private function fixture(string $name, string $bytes): array
    {
        $path = $this->tmp . '/' . bin2hex(random_bytes(6));
        file_put_contents($path, $bytes);
        return ['name' => $name, 'type' => 'image/jpeg', 'tmp_name' => $path, 'error' => UPLOAD_ERR_OK, 'size' => strlen($bytes)];
    }

    private static function image(string $type, int $w = 8, int $h = 8): string
    {
        $img = imagecreatetruecolor($w, $h);
        imagefilledrectangle($img, 0, 0, $w - 1, $h - 1, imagecolorallocate($img, 10, 120, 200));
        ob_start();
        $type === 'png' ? imagepng($img) : imagejpeg($img, null, 90);
        return (string) ob_get_clean();
    }

    private static function pngWithDimensions(int $w, int $h): string
    {
        $chunk = static fn (string $type, string $data): string =>
            pack('N', strlen($data)) . $type . $data . pack('N', crc32($type . $data));
        return "\x89PNG\r\n\x1a\n"
            . $chunk('IHDR', pack('NNCCCCC', $w, $h, 8, 2, 0, 0, 0))
            . $chunk('IDAT', (string) gzcompress("\0\0\0\0"))
            . $chunk('IEND', '');
    }

    private static function gif(): string
    {
        return base64_decode('R0lGODlhAQABAIAAAAAAAP///yH5BAEAAAAALAAAAAABAAEAAAICRAEAOw==');
    }

    private function store(array $file): array
    {
        return SafeUpload::store($file, $this->dest, requireUploaded: false);
    }

    public function testValidPngIsStoredUnderRandomNameWithoutInternalPath(): void
    {
        [$ok, $message, $name] = $this->store($this->fixture('holiday.png', self::image('png')));
        self::assertTrue($ok);
        self::assertMatchesRegularExpression('/^[0-9a-f]{32}\.png$/', (string) $name);
        self::assertFileExists($this->dest . '/' . $name);
        self::assertStringNotContainsString($this->dest, $message, 'T9: шлях не розкривається');
        self::assertStringNotContainsString('uploads', $message);
    }

    public function testValidJpegIsStoredAsJpg(): void
    {
        [$ok, , $name] = $this->store($this->fixture('photo.JPEG', self::image('jpeg')));
        self::assertTrue($ok);
        self::assertStringEndsWith('.jpg', (string) $name);
    }

    public function testSameClientNameNeverOverwrites(): void
    {
        [, , $a] = $this->store($this->fixture('same.png', self::image('png')));
        [, , $b] = $this->store($this->fixture('same.png', self::image('png')));
        self::assertNotSame($a, $b, 'T7: файли з однаковим іменем не перезаписуються');
    }

    /** @return iterable<string, array{string, callable(): string}> */
    public static function maliciousFiles(): iterable
    {
        yield 'V1 plain .php'                       => ['shell.php', fn () => self::PHP];
        yield 'V2 .php with image Content-Type'     => ['shell.php', fn () => self::image('png') . self::PHP];
        yield 'V3 GIF polyglot named .jpg'          => ['x.jpg', fn () => self::gif() . self::PHP];
        yield 'V7 .htaccess'                        => ['.htaccess', fn () => "SetHandler application/x-httpd-php\n"];
        yield 'V7 custom extension'                 => ['x.rgr1234', fn () => self::PHP];
        yield 'double extension .php.png (text)'    => ['x.php.png', fn () => self::PHP];
        yield 'alternative PHP extension .phtml'    => ['x.phtml', fn () => self::image('png')];
        yield '.phar'                               => ['x.phar', fn () => self::image('png')];
        yield 'PNG content named .jpg (mismatch)'   => ['x.jpg', fn () => self::image('png')];
        yield 'JPEG content named .png (mismatch)'  => ['x.png', fn () => self::image('jpeg')];
        yield 'GIF named .png'                      => ['x.png', fn () => self::gif()];
        yield 'SVG with script'                     => ['x.png', fn () => '<svg xmlns="http://www.w3.org/2000/svg"><script>alert(1)</script></svg>'];
        yield 'truncated PNG header'                => ['x.png', fn () => "\x89PNG\r\n\x1a\n"];
        yield 'empty file'                          => ['x.png', fn () => ''];
        yield 'no extension'                        => ['image', fn () => self::image('png')];
    }

    #[DataProvider('maliciousFiles')]
    public function testMaliciousFilesAreRejectedAndNothingIsWritten(string $name, callable $bytes): void
    {
        [$ok, $message, $stored] = $this->store($this->fixture($name, $bytes()));
        self::assertFalse($ok, $name);
        self::assertNull($stored);
        self::assertStringNotContainsString($name === '' ? "\0" : $this->dest, $message);
        self::assertSame([], glob($this->dest . '/{,.}[!.]*', GLOB_BRACE) ?: [], 'у каталог нічого не записано');
    }

    public function testPhpAppendedToRealJpegIsDestroyedByReencoding(): void
    {
        // Справжній JPEG + PHP у кінці проходить усі перевірки типу, але перекодування знищує корисне навантаження.
        [$ok, , $name] = $this->store($this->fixture('poly.jpg', self::image('jpeg') . self::PHP));
        self::assertTrue($ok);
        $stored = (string) file_get_contents($this->dest . '/' . $name);
        self::assertStringNotContainsString('<?php', $stored);
        self::assertStringNotContainsString('RGR-V8', $stored);
    }

    public function testOversizedFileIsRejected(): void
    {
        $file = $this->fixture('big.png', self::image('png') . str_repeat("\0", SafeUpload::MAX_BYTES));
        [$ok] = $this->store($file);
        self::assertFalse($ok);
    }

    public function testDecompressionBombDimensionsAreRejected(): void
    {
        // «Бомба»: валідний PNG-заголовок оголошує 5000x5000 (25 Мпікс > MAX_PIXELS), а файл займає ~70 байт.
        // Розміри мають бути відхилені ДО декодування, інакше imagecreatefrompng() вичерпає пам'ять.
        $file = $this->fixture('bomb.png', self::pngWithDimensions(5000, 5000));
        self::assertLessThan(SafeUpload::MAX_BYTES, $file['size']);
        [$ok] = $this->store($file);
        self::assertFalse($ok);
    }

    public function testUploadErrorAndNonUploadedFileAreRejected(): void
    {
        $file = $this->fixture('x.png', self::image('png'));
        [$ok] = SafeUpload::store(['error' => UPLOAD_ERR_PARTIAL] + $file, $this->dest, requireUploaded: false);
        self::assertFalse($ok);
        [$ok] = SafeUpload::store($file, $this->dest); // не через HTTP-завантаження → is_uploaded_file() = false
        self::assertFalse($ok);
    }
}
