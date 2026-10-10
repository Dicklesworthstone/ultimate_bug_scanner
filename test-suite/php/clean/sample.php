<?php
$database = new PDO('sqlite::memory:');
$statement = $database->prepare('SELECT * FROM accounts WHERE name = ?');
$statement->execute([$_GET['name']]);
system('printf %s ' . escapeshellarg($_GET['name']));
include __DIR__ . '/trusted-template.php';
unserialize('a:1:{s:4:"name";s:5:"fixed";}');
echo htmlspecialchars($_GET['name'], ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
