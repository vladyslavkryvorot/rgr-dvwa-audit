<?php
declare(strict_types=1);

require __DIR__ . '/../../vendor/autoload.php';
require __DIR__ . '/../../dvwa/dvwa/includes/SafePath.php';
require __DIR__ . '/../../dvwa/dvwa/includes/SafeUpload.php';

// Журнал подій безпеки під час тестів не потрібен у виводі.
ini_set('error_log', sys_get_temp_dir() . '/rgr-unit-security.log'); // журнал [rgr-security] — у файл
