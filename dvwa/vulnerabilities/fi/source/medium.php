<?php

// РГР, варіант 8 — виправлення V4 (low, ../), V5 (medium, ....//), V6 (high, file://), T6.
// Параметр page має збігатися з allowlist, а канонізований шлях — лежати в каталозі модуля.
require_once DVWA_WEB_PAGE_TO_ROOT . 'dvwa/includes/SafePath.php';

if( isset( $_GET[ 'page' ] ) ) {
	$file = SafePath::resolveInclude(
		is_string( $_GET[ 'page' ] ) ? $_GET[ 'page' ] : '',
		__DIR__ . '/..',
		array( 'include.php', 'file1.php', 'file2.php', 'file3.php' )
	);
	if( $file === null ) {
		// This isn't the page we want!
		echo "ERROR: File not found!";
		exit;
	}
}

?>
