<?php
while ($f = fgets(STDIN)){
	$passwenc = sha1(sha1(rtrim($f)));
	echo "$passwenc : $f";
  }
?>
