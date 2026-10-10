# PHP fixtures

- `buggy/sample.php` — must yield at least one critical (an eval-style call) and one info (a TODO marker); manifest case `php-buggy`.
- `clean/sample.php` — must yield no critical; manifest case `php-clean`.

Replace both when the example checks in `modules/ubs-php.sh` become real detectors; every real rule needs a line in each fixture and a manifest expectation.
