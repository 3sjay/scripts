<?php
while ($f = fgets(STDIN)){
  $passwenc = md5(rtrim($f));
  echo "$passwenc : $f";
}
?>
