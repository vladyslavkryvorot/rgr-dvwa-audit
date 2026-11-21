<?php

// РГР, варіант 8 — виправлення V1 (low), V2 (medium), V3 (high), V7 (.htaccess), T7, T9.
// Рівень безпеки задає клієнтська cookie «security» (загроза T12), тому всі рівні
// використовують одну безпечну реалізацію SafeUpload (dvwa/includes/SafeUpload.php).
require_once DVWA_WEB_PAGE_TO_ROOT . 'dvwa/includes/SafeUpload.php';

if( isset( $_POST[ 'Upload' ] ) && isset( $_FILES[ 'uploaded' ] ) && is_array( $_FILES[ 'uploaded' ] ) ) {
	[ $uploadOk, $uploadMessage ] = SafeUpload::store( $_FILES[ 'uploaded' ], DVWA_WEB_PAGE_TO_ROOT . 'hackable/uploads' );
	$html .= '<pre>' . htmlspecialchars( $uploadMessage, ENT_QUOTES, 'UTF-8' ) . '</pre>';
}

?>
