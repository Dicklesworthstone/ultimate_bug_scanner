<?php
$database = new PDO('sqlite::memory:');
$database->query("SELECT * FROM accounts WHERE name = '" . $_GET['name'] . "'");
system('printf %s ' . $_GET['command']);
eval($_POST['code']);
include $_GET['template'];
unserialize($_COOKIE['session']);
echo $_GET['name'];
