-- PostgreSQL migration: privileged function is published without hardening.
BEGIN;
CREATE FUNCTION app.read_balance(account_id integer) RETURNS integer
LANGUAGE sql SECURITY DEFINER
AS $sql$
    SELECT balance FROM app.accounts WHERE id = account_id
$sql$;
COMMIT;
