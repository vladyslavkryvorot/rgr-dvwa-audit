<?php

define( 'DVWA_WEB_PAGE_TO_ROOT', '../' );
require_once DVWA_WEB_PAGE_TO_ROOT . 'dvwa/includes/dvwaPage.inc.php';
require_once DVWA_WEB_PAGE_TO_ROOT . 'dvwa/includes/SafePath.php';

dvwaPageStartup( array( 'authenticated' ) );

$page = dvwaPageNewGrab();
$page[ 'title' ] = 'Help' . $page[ 'title_separator' ].$page[ 'title' ];

if (array_key_exists ("id", $_GET) &&
	array_key_exists ("security", $_GET) &&
	array_key_exists ("locale", $_GET)) {
	$id       = $_GET[ 'id' ];
	$security = $_GET[ 'security' ];
	$locale = $_GET[ 'locale' ];

	// РГР V9: шлях, що передається в eval(), будується лише з перевірених значень (CWE-22, CWE-95).
	$helpFile = null;
	if (is_string($id) && is_string($security) && is_string($locale)
		&& SafePath::isModuleId($id, DVWA_WEB_PAGE_TO_ROOT . 'vulnerabilities', 'help')
		&& SafePath::isSecurityLevel($security)
		&& in_array($locale, array('en', 'zh'), true)) {
		$helpDir  = DVWA_WEB_PAGE_TO_ROOT . "vulnerabilities/{$id}/help";
		$helpFile = ($locale == 'en' ? null : SafePath::within($helpDir, "help.{$locale}.php"))
			?? SafePath::within($helpDir, 'help.php');
	}
	if ($helpFile !== null) {
		ob_start();
		eval( '?>' . file_get_contents( $helpFile ) . '<?php ' );
		$help = ob_get_contents();
		ob_end_clean();
	} else {
		$help = "<p>Not Found</p>";
	}
} else {
	$help = "<p>Not Found</p>";
}

$page[ 'body' ] .= "
<script src='/vulnerabilities/help.js'></script>
<link rel='stylesheet' type='text/css' href='/vulnerabilities/help.css' />

<div class=\"body_padded\">
	{$help}
</div>\n";

dvwaHelpHtmlEcho( $page );

?>
