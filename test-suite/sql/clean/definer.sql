-- Schema ownership and the function's access policy are explicit here.
BEGIN;
CREATE SCHEMA billing_private;
REVOKE CREATE ON SCHEMA billing_private FROM PUBLIC;
CREATE FUNCTION billing_private.read_balance(account_id integer) RETURNS integer
LANGUAGE sql SECURITY DEFINER
SET search_path = pg_catalog, billing_private, pg_temp
AS $sql$
    SELECT balance FROM app.accounts WHERE id = account_id
$sql$;
REVOKE ALL ON FUNCTION billing_private.read_balance(integer) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION billing_private.read_balance(integer) TO application_role;
COMMIT;
