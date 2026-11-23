"""Independent PostgreSQL function-security oracle for mj1j.33/.34.

Labels precede the analyzer and follow PostgreSQL's CREATE FUNCTION,
search_path and GRANT/REVOKE contracts. These are source-analysis tests, not a
claim that migration execution or deployed privileges were verified. A custom
schema's name does not prove that it is trusted.

References:
https://www.postgresql.org/docs/current/sql-createfunction.html
https://www.postgresql.org/docs/current/runtime-config-client.html
https://www.postgresql.org/docs/current/ddl-priv.html
https://www.postgresql.org/docs/current/sql-alterdefaultprivileges.html
https://www.postgresql.org/docs/current/sql-alterfunction.html
https://www.postgresql.org/docs/current/sql-createprocedure.html
https://www.postgresql.org/docs/current/sql-dropprocedure.html
https://www.postgresql.org/docs/current/sql-grant.html
https://www.postgresql.org/docs/current/sql-do.html
https://www.postgresql.org/docs/current/functions-string.html#FUNCTIONS-STRING-FORMAT
https://www.postgresql.org/docs/current/sql-select.html
https://www.postgresql.org/docs/current/app-psql.html
https://coverage.postgresql.org/src/fe_utils/psqlscan.l.gcov.html
https://doxygen.postgresql.org/scansup_8c_source.html
https://doxygen.postgresql.org/alter_8c_source.html
"""
from __future__ import annotations

from dataclasses import dataclass
import hashlib
import importlib
import json
import os
from pathlib import Path
import subprocess
import sys
import textwrap
import time
import unittest
import uuid


ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "modules/helpers"))
RULES = {
    "path": "sql.security.definer-search-path",
    "public": "sql.security.definer-public-execute",
}


@dataclass(frozen=True)
class Case:
    name: str
    code: str
    column: int | None = None

    @property
    def source(self):
        return textwrap.dedent(self.code).strip("\n") + "\n"

    @property
    def filename(self):
        return self.name + ".sql"

    @property
    def expected(self):
        result = []
        for line, source in enumerate(self.source.split("\n"), 1):
            if "-- expect:" in source:
                names = source.split("-- expect:", 1)[1].strip().split(",")
                column = self.column if self.column is not None else len(source) - len(source.lstrip()) + 1
                result.extend((RULES[name], line, column) for name in names)
        return sorted(result)


# Fixed labels include cases where a later safe-looking statement must not
# erase the vulnerable overload or an already committed exposure window.
CASES = (
    Case("missing_function_hardening", """
        CREATE FUNCTION app.f() RETURNS integer -- expect:path,public
        LANGUAGE sql SECURITY DEFINER AS $$ SELECT 1 $$;
    """),
    Case("fixed_path_does_not_revoke_public", """
        CREATE FUNCTION app.f() RETURNS integer -- expect:public
        LANGUAGE sql SECURITY DEFINER SET search_path = pg_catalog, pg_temp
        AS $$ SELECT 1 $$;
    """),
    Case("one_transaction_revoke_and_role_grant", """
        BEGIN;
        CREATE FUNCTION app.f(input_id int) RETURNS integer
        LANGUAGE sql SECURITY DEFINER SET search_path = pg_catalog, pg_temp
        AS $$ SELECT 1 $$;
        REVOKE EXECUTE ON FUNCTION app.f(integer) FROM PUBLIC;
        GRANT EXECUTE ON FUNCTION app.f(integer) TO application_role;
        COMMIT;
    """),
    Case("out_parameter_not_part_of_identity", """
        BEGIN;
        CREATE FUNCTION app.f(IN input_id int, OUT allowed boolean)
        RETURNS boolean LANGUAGE sql SECURITY DEFINER
        SET search_path = pg_catalog, pg_temp AS $$ SELECT true $$;
        REVOKE ALL PRIVILEGES ON FUNCTION app.f(integer) FROM PUBLIC;
        COMMIT;
    """),
    Case("defaults_do_not_split_signature", """
        BEGIN;
        CREATE FUNCTION app.f(prefix text DEFAULT 'SECURITY DEFINER,public', input_id integer DEFAULT 1)
        RETURNS integer LANGUAGE sql SECURITY DEFINER
        SET search_path = pg_catalog, pg_temp AS $$ SELECT 1 $$;
        REVOKE ALL ON FUNCTION app.f(text, int4) FROM PUBLIC;
        COMMIT;
    """),
    Case("overload_revoke_does_not_cover_integer", """
        BEGIN;
        CREATE FUNCTION app.f(integer) RETURNS integer -- expect:public
        LANGUAGE sql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$ SELECT 1 $$;
        CREATE FUNCTION app.f(text) RETURNS integer
        LANGUAGE sql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$ SELECT 1 $$;
        REVOKE EXECUTE ON FUNCTION app.f(text) FROM PUBLIC;
        COMMIT;
    """),
    Case("quoted_identifier_is_distinct", """
        BEGIN;
        CREATE FUNCTION app."F"() RETURNS integer -- expect:public
        LANGUAGE sql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$ SELECT 1 $$;
        CREATE FUNCTION app.f() RETURNS integer
        LANGUAGE sql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$ SELECT 1 $$;
        REVOKE EXECUTE ON FUNCTION app.f() FROM PUBLIC;
        COMMIT;
    """),
    Case("revoke_after_commit_leaves_exposure_window", """
        BEGIN;
        CREATE FUNCTION app.f() RETURNS integer -- expect:public
        LANGUAGE sql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$ SELECT 1 $$;
        COMMIT;
        REVOKE EXECUTE ON FUNCTION app.f() FROM PUBLIC;
    """),
    Case("autocommit_revoke_leaves_exposure_window", """
        CREATE FUNCTION app.f() RETURNS integer -- expect:public
        LANGUAGE sql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$ SELECT 1 $$;
        REVOKE EXECUTE ON FUNCTION app.f() FROM PUBLIC;
    """),
    Case("later_public_grant_restores_exposure", """
        BEGIN;
        CREATE FUNCTION app.f() RETURNS integer -- expect:public
        LANGUAGE sql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$ SELECT 1 $$;
        REVOKE ALL ON FUNCTION app.f() FROM PUBLIC;
        GRANT EXECUTE ON FUNCTION app.f() TO application_role, PUBLIC;
        COMMIT;
    """),
    Case("another_role_revoke_does_not_remove_public", """
        BEGIN;
        CREATE FUNCTION app.f() RETURNS integer -- expect:public
        LANGUAGE sql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$ SELECT 1 $$;
        REVOKE EXECUTE ON FUNCTION app.f() FROM application_role;
        COMMIT;
    """),
    Case("missing_temp_schema_keeps_implicit_first_lookup", """
        BEGIN;
        CREATE FUNCTION app.f() RETURNS integer -- expect:path
        LANGUAGE sql SECURITY DEFINER SET search_path = pg_catalog AS $$ SELECT 1 $$;
        REVOKE ALL ON FUNCTION app.f() FROM PUBLIC;
        COMMIT;
    """),
    Case("temporary_schema_precedes_catalog", """
        BEGIN;
        CREATE FUNCTION app.f() RETURNS integer -- expect:path
        LANGUAGE sql SECURITY DEFINER SET search_path = pg_temp, pg_catalog AS $$ SELECT 1 $$;
        REVOKE ALL ON FUNCTION app.f() FROM PUBLIC;
        COMMIT;
    """),
    Case("user_dependent_schema_search", """
        BEGIN;
        CREATE FUNCTION app.f() RETURNS integer -- expect:path
        LANGUAGE sql SECURITY DEFINER SET search_path = "$user", pg_catalog, pg_temp AS $$ SELECT 1 $$;
        REVOKE ALL ON FUNCTION app.f() FROM PUBLIC;
        COMMIT;
    """),
    Case("known_public_writable_schema", """
        BEGIN;
        CREATE SCHEMA tenant;
        GRANT CREATE ON SCHEMA tenant TO PUBLIC;
        CREATE FUNCTION tenant.f() RETURNS integer -- expect:path
        LANGUAGE sql SECURITY DEFINER SET search_path = tenant, pg_temp AS $$ SELECT 1 $$;
        REVOKE ALL ON FUNCTION tenant.f() FROM PUBLIC;
        COMMIT;
    """),
    Case("quoted_setting_value_is_schema_list", """
        BEGIN;
        CREATE FUNCTION app.f() RETURNS integer
        LANGUAGE sql SECURITY DEFINER SET search_path TO 'pg_catalog, pg_temp' AS $$ SELECT 1 $$;
        REVOKE ALL ON FUNCTION app.f() FROM PUBLIC;
        COMMIT;
    """),
    Case("empty_path_with_fully_qualified_body", """
        BEGIN;
        CREATE FUNCTION app.f() RETURNS integer
        LANGUAGE sql SECURITY DEFINER SET search_path TO '' AS $$ SELECT pg_catalog.length('text') $$;
        REVOKE ALL ON FUNCTION app.f() FROM PUBLIC;
        COMMIT;
    """),
    Case("session_path_is_not_a_fixed_function_setting", """
        SET search_path TO pg_catalog, pg_temp;
        BEGIN;
        CREATE FUNCTION app.f() RETURNS integer -- expect:path
        LANGUAGE sql SECURITY DEFINER AS $$ SELECT 1 $$;
        REVOKE ALL ON FUNCTION app.f() FROM PUBLIC;
        COMMIT;
    """),
    Case("nested_comments_literals_and_identifiers_are_not_ddl", """
        /* CREATE FUNCTION app.fake() SECURITY DEFINER;
           /* Nested comment: REVOKE ALL ON FUNCTION app.fake() FROM PUBLIC; */
        */
        SELECT 'CREATE FUNCTION app.fake() SECURITY DEFINER;';
        SELECT $ddl$ CREATE FUNCTION app.fake() SECURITY DEFINER; $ddl$;
        CREATE FUNCTION app."SECURITY DEFINER"() RETURNS text LANGUAGE sql
        SECURITY INVOKER AS $body$ SELECT 'SECURITY DEFINER; SET search_path=public;' $body$;
    """),
    Case("body_revoke_is_not_migration_revoke", """
        CREATE FUNCTION app.f() RETURNS text -- expect:public
        LANGUAGE sql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $body$
        SELECT 'REVOKE ALL ON FUNCTION app.f() FROM PUBLIC;'
        $body$;
    """),
    Case("dollar_tags_are_case_sensitive", """
        CREATE FUNCTION app.f() RETURNS text LANGUAGE sql SECURITY INVOKER AS $body$
        SELECT '$BODY$; SECURITY DEFINER; CREATE FUNCTION app.fake();'
        $body$;
    """),
    Case("replacement_preserves_known_restricted_acl", """
        BEGIN;
        CREATE FUNCTION app.f(integer) RETURNS integer LANGUAGE sql AS $$ SELECT 1 $$;
        REVOKE ALL ON FUNCTION app.f(integer) FROM PUBLIC;
        CREATE OR REPLACE FUNCTION app.f(int4) RETURNS integer
        LANGUAGE sql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$ SELECT 2 $$;
        COMMIT;
    """),
    Case("rolled_back_creation_is_not_published", """
        BEGIN;
        CREATE FUNCTION app.f() RETURNS integer LANGUAGE sql SECURITY DEFINER AS $$ SELECT 1 $$;
        ROLLBACK;
    """),
    Case("ordinary_dml_is_not_blanket_destructive_warning", """
        BEGIN;
        UPDATE app.settings SET enabled = false;
        DELETE FROM app.expired_sessions;
        COMMIT;
    """),
    Case("alter_reset_removes_fixed_function_path", """
        BEGIN;
        CREATE FUNCTION app.f() RETURNS integer LANGUAGE sql SECURITY DEFINER
        SET search_path = pg_catalog, pg_temp AS $$ SELECT 1 $$;
        REVOKE ALL ON FUNCTION app.f() FROM PUBLIC;
        ALTER FUNCTION app.f() RESET search_path; -- expect:path
        COMMIT;
    """),
    Case("alter_invoker_before_commit_removes_definer_exposure", """
        BEGIN;
        CREATE FUNCTION app.f() RETURNS integer LANGUAGE sql SECURITY DEFINER AS $$ SELECT 1 $$;
        ALTER FUNCTION app.f() SECURITY INVOKER;
        COMMIT;
    """),
    Case("alter_definer_requires_its_own_fixed_path", """
        BEGIN;
        CREATE FUNCTION app.f() RETURNS integer LANGUAGE sql AS $$ SELECT 1 $$;
        REVOKE ALL ON FUNCTION app.f() FROM PUBLIC;
        ALTER FUNCTION app.f() SECURITY DEFINER; -- expect:path
        COMMIT;
    """),
    Case("savepoint_rollback_restores_public_execute", """
        BEGIN;
        CREATE FUNCTION app.f() RETURNS integer -- expect:public
        LANGUAGE sql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$ SELECT 1 $$;
        SAVEPOINT before_revoke;
        REVOKE ALL ON FUNCTION app.f() FROM PUBLIC;
        ROLLBACK TO SAVEPOINT before_revoke;
        COMMIT;
    """),
    Case("revoking_grant_option_does_not_revoke_execute", """
        BEGIN;
        CREATE FUNCTION app.f() RETURNS integer -- expect:public
        LANGUAGE sql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$ SELECT 1 $$;
        GRANT EXECUTE ON FUNCTION app.f() TO application_role WITH GRANT OPTION;
        REVOKE GRANT OPTION FOR EXECUTE ON FUNCTION app.f() FROM application_role;
        COMMIT;
    """),
    Case("schema_wide_grant_reexposes_known_function", """
        BEGIN;
        CREATE FUNCTION app.f() RETURNS integer -- expect:public
        LANGUAGE sql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$ SELECT 1 $$;
        REVOKE ALL ON FUNCTION app.f() FROM PUBLIC;
        GRANT EXECUTE ON ALL FUNCTIONS IN SCHEMA app TO PUBLIC;
        COMMIT;
    """),
    Case("public_grant_option_revoke_preserves_execute", """
        BEGIN;
        CREATE FUNCTION app.f() RETURNS integer -- expect:public
        LANGUAGE sql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$ SELECT 1 $$;
        REVOKE GRANT OPTION FOR EXECUTE ON FUNCTION app.f() FROM PUBLIC;
        COMMIT;
    """),
    Case("default_grant_option_revoke_preserves_execute", """
        ALTER DEFAULT PRIVILEGES REVOKE GRANT OPTION FOR EXECUTE ON FUNCTIONS FROM PUBLIC;
        CREATE FUNCTION app.f() RETURNS integer -- expect:public
        LANGUAGE sql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$ SELECT 1 $$;
    """),
    Case("rollback_work_to_savepoint_restores_acl", """
        BEGIN;
        CREATE FUNCTION app.f() RETURNS integer -- expect:public
        LANGUAGE sql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$ SELECT 1 $$;
        SAVEPOINT before_revoke;
        REVOKE ALL ON FUNCTION app.f() FROM PUBLIC;
        ROLLBACK WORK TO before_revoke;
        COMMIT;
    """),
    Case("empty_path_does_not_exclude_implicit_temp_relations", """
        BEGIN;
        CREATE FUNCTION app.f() RETURNS text -- expect:path
        LANGUAGE sql SECURITY DEFINER SET search_path = ''
        AS $$ SELECT secret FROM protected_table $$;
        REVOKE ALL ON FUNCTION app.f() FROM PUBLIC;
        COMMIT;
    """),
    Case("quoted_type_name_does_not_alias_builtin_keyword", """
        BEGIN;
        CREATE DOMAIN "integer" AS text;
        CREATE FUNCTION app.f(integer) RETURNS integer -- expect:public
        LANGUAGE sql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$ SELECT 1 $$;
        CREATE FUNCTION app.f("integer") RETURNS integer LANGUAGE sql SECURITY INVOKER AS $$ SELECT 1 $$;
        REVOKE ALL ON FUNCTION app.f("integer") FROM PUBLIC;
        COMMIT;
    """),
    Case("returns_table_type_names_are_not_security_attributes", """
        CREATE TYPE definer AS (value text);
        CREATE FUNCTION app.f() RETURNS TABLE (security definer)
        LANGUAGE sql AS $$ SELECT NULL::definer $$;
    """),
    Case("builtin_type_word_can_be_a_parameter_name", """
        BEGIN;
        CREATE FUNCTION app.f(name text, date date, time integer) RETURNS integer
        LANGUAGE sql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$ SELECT 1 $$;
        REVOKE ALL ON FUNCTION app.f(text, date, integer) FROM PUBLIC;
        COMMIT;
    """),
    Case("quoted_type_with_dot_is_not_qualified_domain", """
        BEGIN;
        CREATE SCHEMA app;
        CREATE DOMAIN app.money AS numeric;
        CREATE DOMAIN "app.money" AS text;
        CREATE FUNCTION app.f(app.money) RETURNS integer -- expect:public
        LANGUAGE sql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$ SELECT 1 $$;
        CREATE FUNCTION app.f("app.money") RETURNS integer LANGUAGE sql SECURITY INVOKER AS $$ SELECT 1 $$;
        REVOKE ALL ON FUNCTION app.f("app.money") FROM PUBLIC;
        COMMIT;
    """),
    Case("reported_owner_role_migration", """
        CREATE ROLE app_mutator NOLOGIN;
        CREATE FUNCTION public.f() RETURNS int LANGUAGE sql AS $$ SELECT 1 $$;
        DO $$ BEGIN
          EXECUTE format('GRANT app_mutator TO %I WITH INHERIT FALSE', current_user);
        END $$;
        ALTER FUNCTION public.f() OWNER TO app_mutator;
    """),
    Case("owner_transfer_preserves_function_hardening", """
        BEGIN;
        CREATE ROLE "app mutator" NOLOGIN;
        CREATE FUNCTION app.f() RETURNS integer LANGUAGE sql SECURITY DEFINER
        SET search_path = pg_catalog, pg_temp AS $$ SELECT 1 $$;
        REVOKE ALL ON FUNCTION app.f() FROM PUBLIC;
        ALTER FUNCTION app.f() OWNER TO "app mutator";
        COMMIT;
    """),
    Case("owner_transfer_does_not_revoke_public", """
        BEGIN;
        CREATE FUNCTION app.f() RETURNS integer -- expect:public
        LANGUAGE sql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$ SELECT 1 $$;
        ALTER FUNCTION app.f() OWNER TO app_mutator;
        COMMIT;
    """),
    Case("owner_transfer_does_not_fix_search_path", """
        BEGIN;
        CREATE FUNCTION app.f() RETURNS integer -- expect:path
        LANGUAGE sql SECURITY DEFINER AS $$ SELECT 1 $$;
        REVOKE ALL ON FUNCTION app.f() FROM PUBLIC;
        ALTER FUNCTION app.f() OWNER TO CURRENT_ROLE;
        COMMIT;
    """),
    Case("owner_transfer_preserves_acl_for_replacement", """
        BEGIN;
        CREATE FUNCTION app.f() RETURNS integer LANGUAGE sql AS $$ SELECT 1 $$;
        REVOKE ALL ON FUNCTION app.f() FROM PUBLIC;
        ALTER FUNCTION app.f() OWNER TO SESSION_USER;
        CREATE OR REPLACE FUNCTION app.f() RETURNS integer LANGUAGE sql SECURITY DEFINER
        SET search_path = pg_catalog, pg_temp AS $$ SELECT 2 $$;
        COMMIT;
    """),
    Case("owner_transfer_does_not_duplicate_published_hazards", """
        CREATE FUNCTION app.f() RETURNS integer -- expect:path,public
        LANGUAGE sql SECURITY DEFINER AS $$ SELECT 1 $$;
        ALTER FUNCTION app.f() OWNER TO CURRENT_USER;
    """),
    Case("owner_transfer_and_savepoint_preserve_restricted_acl", """
        BEGIN;
        CREATE FUNCTION app.f() RETURNS integer LANGUAGE sql SECURITY DEFINER
        SET search_path = pg_catalog, pg_temp AS $$ SELECT 1 $$;
        REVOKE ALL ON FUNCTION app.f() FROM PUBLIC;
        SAVEPOINT secured;
        GRANT EXECUTE ON FUNCTION app.f() TO PUBLIC;
        ALTER FUNCTION app.f() OWNER TO app_mutator;
        ROLLBACK TO secured;
        COMMIT;
    """),
    Case("do_literal_and_static_membership_grants", """
        DO LANGUAGE plpgsql $body$ BEGIN
          GRANT app_reader TO CURRENT_USER, SESSION_USER WITH SET TRUE, INHERIT FALSE;
          EXECUTE 'GRANT app_owner TO deployment_user WITH ADMIN OPTION';
        END; $body$;
        GRANT app_reader, app_writer TO application_user WITH INHERIT FALSE;
    """),
    Case("qualified_format_after_changed_search_path", """
        SET search_path = public, pg_catalog;
        DO $body$ BEGIN
          EXECUTE pg_catalog.format('GRANT %1$I TO %2$I WITH INHERIT FALSE', 'app owner', current_user);
        END $body$ LANGUAGE plpgsql;
    """),
    Case("format_identifier_arguments_cannot_inject_sql", """
        DO $body$ BEGIN
          EXECUTE pg_catalog.format('GRANT %I TO %I', 'role"; SELECT dangerous(); --', session_user);
          EXECUTE pg_catalog.format('GRANT "rate%%role" TO %I', current_role);
        END $body$;
    """),
    Case("role_membership_does_not_revoke_function_public_execute", """
        BEGIN;
        CREATE FUNCTION app.f() RETURNS integer -- expect:public
        LANGUAGE sql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$ SELECT 1 $$;
        DO $$ BEGIN
          EXECUTE format('GRANT app_mutator TO %I WITH INHERIT FALSE', current_user);
        END $$;
        ALTER FUNCTION app.f() OWNER TO app_mutator;
        COMMIT;
    """),
    Case("reported_constant_cte", """
        WITH sample AS (SELECT 1 AS value) SELECT value FROM sample;
    """),
    Case("multiple_ctes_with_columns_and_materialization", """
        WITH "sample rows" (value, label) AS MATERIALIZED (VALUES (1, 'one'), (2, 'two')),
             selected AS NOT MATERIALIZED (SELECT value FROM "sample rows" WHERE value > 1)
        SELECT * FROM selected;
    """),
    Case("recursive_cte", """
        WITH RECURSIVE counter(n) AS (
          SELECT 1 UNION ALL SELECT n + 1 FROM counter WHERE n < 3
        ) SELECT sum(n) FROM counter;
    """),
    Case("nested_cte_and_parenthesized_query", """
        WITH outer_rows AS (
          WITH inner_rows AS ((SELECT 1 AS value)) SELECT value FROM inner_rows
        ) SELECT (SELECT value FROM outer_rows);
    """),
    Case("data_modifying_cte_keeps_dml_policy", """
        WITH moved AS (DELETE FROM app.expired_sessions RETURNING id)
        INSERT INTO app.archived_sessions SELECT id FROM moved;
        WITH counts AS (SELECT 3 AS count)
        UPDATE app.settings SET value = counts.count FROM counts;
        WITH expired AS (TABLE app.expired_sessions)
        DELETE FROM app.archived_sessions USING expired WHERE archived_sessions.id = expired.id;
    """),
    Case("cte_values_and_table_primary_queries", """
        WITH sample AS (SELECT 1) VALUES (2), (3);
        WITH sample AS (SELECT 1) TABLE app.settings;
    """),
    Case("cte_does_not_interrupt_transaction_hardening", """
        BEGIN;
        CREATE FUNCTION app.f() RETURNS integer LANGUAGE sql SECURITY DEFINER
        SET search_path = pg_catalog, pg_temp AS $$ SELECT 1 $$;
        WITH sample AS (SELECT 1 AS value) SELECT value FROM sample;
        REVOKE ALL ON FUNCTION app.f() FROM PUBLIC;
        COMMIT;
    """),
    Case("cte_does_not_hide_later_function_exposure", """
        WITH sample AS (SELECT 1 AS value) SELECT value FROM sample;
        CREATE FUNCTION app.f() RETURNS integer -- expect:path,public
        LANGUAGE sql SECURITY DEFINER AS $$ SELECT 1 $$;
    """),
    Case("cte_literals_and_comments_do_not_change_migration", r"""
        WITH sample AS (
          SELECT 'CREATE FUNCTION fake(); :unknown' AS text,
                 $body$ \gexec; REVOKE ALL ON FUNCTION app.f() FROM PUBLIC; $body$ AS quoted
          /* AS (EXECUTE 'GRANT EXECUTE') */
        ) SELECT * FROM sample;
        CREATE FUNCTION app.f() RETURNS integer -- expect:path,public
        LANGUAGE sql SECURITY DEFINER AS $$ SELECT 1 $$;
    """),
    Case("reported_lock_table", """
        LOCK TABLE public.example IN SHARE ROW EXCLUSIVE MODE;
        select 1;
    """),
    Case("locks_and_maintenance_preserve_function_transaction", """
        BEGIN;
        LOCK TABLE app.settings IN ACCESS EXCLUSIVE MODE;
        CREATE FUNCTION app.f() RETURNS integer LANGUAGE sql SECURITY DEFINER
        SET search_path = pg_catalog, pg_temp AS $$ SELECT 1 $$;
        LOCK app.settings, app.archive IN SHARE MODE NOWAIT;
        NOTIFY app_changes, 'function created';
        REVOKE ALL ON FUNCTION app.f() FROM PUBLIC;
        COMMIT;
        REFRESH MATERIALIZED VIEW CONCURRENTLY app.summary WITH DATA;
        REINDEX INDEX CONCURRENTLY app.settings_pkey;
        CLUSTER app.settings USING settings_pkey;
        CHECKPOINT;
        LISTEN app_changes;
        UNLISTEN *;
    """),
    Case("locks_and_maintenance_do_not_hide_later_function_exposure", """
        LOCK TABLE app.settings IN SHARE MODE;
        REFRESH MATERIALIZED VIEW app.summary;
        REINDEX TABLE app.settings;
        CREATE FUNCTION app.f() RETURNS integer -- expect:path,public
        LANGUAGE sql SECURITY DEFINER AS $$ SELECT 1 $$;
    """),
    Case("reported_psql_error_stop", r"""
        \set ON_ERROR_STOP on
        SELECT 1;
    """),
    Case("psql_literal_error_stop_and_display_settings", r"""
        \set ON_ERROR_STOP
        \set ON_ERROR_STOP 'true'
        \set ECHO all
        \set VERBOSITY terse
        \echo 'Preparing function migration'
        \echo 'Literal :variable, `command`, and "quoted text" are messages'
        \warn 'This message changes no database state'
        SELECT 1::integer;
    """),
    Case("psql_directives_preserve_function_transaction", r"""
        \set ON_ERROR_STOP on
        BEGIN;
        CREATE FUNCTION app.f() RETURNS integer LANGUAGE sql SECURITY DEFINER
        SET search_path = pg_catalog, pg_temp AS $$ SELECT 1 $$;
        \echo 'Function created; revoke PUBLIC before publishing'
        REVOKE ALL ON FUNCTION app.f() FROM PUBLIC;
        COMMIT;
    """),
    Case("psql_echo_sql_text_cannot_create_function", r"""
        \echo 'CREATE FUNCTION app.fake() SECURITY DEFINER;'
        \echo CREATE FUNCTION app.also_fake() SECURITY DEFINER;
        SELECT 1;
    """),
    Case("psql_directive_does_not_consume_following_hazard", r"""
        \set ON_ERROR_STOP on
        \echo 'Beginning migration'
        CREATE FUNCTION app.f() RETURNS integer -- expect:path,public
        LANGUAGE sql SECURITY DEFINER AS $$ SELECT 1 $$;
    """),
    Case("psql_inert_directive_does_not_flush_query_buffer", r"""
        BEGIN;
        CREATE FUNCTION app.f() RETURNS integer
        \echo 'Continue the declaration'
        LANGUAGE sql SECURITY DEFINER
        SET search_path = pg_catalog, pg_temp AS $$ SELECT 1 $$;
        REVOKE ALL ON FUNCTION app.f() FROM PUBLIC;
        COMMIT;
    """),
    Case("psql_commands_share_line_without_losing_next_command", r"""
        \set ON_ERROR_STOP on \echo 'Starting migration'
        CREATE FUNCTION app.f() RETURNS integer -- expect:path,public
        LANGUAGE sql SECURITY DEFINER AS $$ SELECT 1 $$;
    """),
    Case("psql_quoted_literals_and_comments_are_not_commands", r"""
        -- \i other.sql
        /* \gexec */
        SELECT '\\set AUTOCOMMIT off', ':ON_ERROR_STOP', ':"schema"';
        CREATE FUNCTION app.f() RETURNS text LANGUAGE sql SECURITY INVOKER AS $body$
        SELECT '\i external.sql';
        $body$;
    """),
    Case("postgresql_casts_and_literal_array_slices_are_not_variables", """
        SELECT 1::integer, (ARRAY[1, 2, 3])[1: 2], (ARRAY[1, 2, 3])[: 2];
    """),
    Case("unicode_colons_in_literals_comments_and_casts_are_not_variables", """
        SELECT ':💥', ':\u0301', ':\u00a0', ":💥", $body$ :\u00a0 $body$;
        -- :💥
        /* :\u00a0 */
        SELECT 1::"💥", 1::é;
    """),
    Case("unicode_dollar_tag_shields_client_commands_before_hazard", """
        SELECT $é$\\echo ignored$é$; CREATE FUNCTION app.f() RETURNS integer -- expect:path,public
        LANGUAGE sql SECURITY DEFINER AS $$ SELECT 1 $$;
    """, column=29),
    Case("unicode_space_dollar_tag_shields_client_commands_before_hazard", """
        SELECT $\u00a0$\\echo ignored$\u00a0$; CREATE FUNCTION app.f() RETURNS integer -- expect:path,public
        LANGUAGE sql SECURITY DEFINER AS $$ SELECT 1 $$;
    """, column=29),
    Case("unicode_symbol_dollar_tags_are_opaque", """
        SELECT $💥$\\gexec; :💥$💥$, $\u0301$\\i secret.sql; :\u00a0$\u0301$;
    """),
    Case("unicode_unquoted_function_names_do_not_fold_together", """
        BEGIN;
        CREATE FUNCTION app.Ä() RETURNS integer -- expect:public
        LANGUAGE sql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$ SELECT 1 $$;
        CREATE FUNCTION app.ä() RETURNS integer
        LANGUAGE sql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$ SELECT 2 $$;
        REVOKE ALL ON FUNCTION app.ä() FROM PUBLIC;
        COMMIT;
    """),
    Case("unicode_quoted_revoke_matches_exact_unquoted_function", """
        BEGIN;
        CREATE FUNCTION app.Ä() RETURNS integer
        LANGUAGE sql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$ SELECT 1 $$;
        REVOKE ALL ON FUNCTION app."Ä"() FROM PUBLIC;
        COMMIT;
    """),
    Case("rename_then_revoke_uses_new_function_identity", """
        BEGIN;
        CREATE FUNCTION app.f() RETURNS integer
        LANGUAGE sql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$ SELECT 1 $$;
        ALTER FUNCTION app.f() RENAME TO renamed;
        REVOKE ALL ON FUNCTION app.renamed() FROM PUBLIC;
        COMMIT;
    """),
    Case("schema_transfer_then_revoke_uses_new_function_identity", """
        BEGIN;
        CREATE FUNCTION app.f() RETURNS integer
        LANGUAGE sql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$ SELECT 1 $$;
        ALTER FUNCTION app.f() SET SCHEMA api;
        REVOKE ALL ON FUNCTION api.f() FROM PUBLIC;
        COMMIT;
    """),
    Case("identity_changes_preserve_acl_for_replacement", """
        BEGIN;
        CREATE FUNCTION app.f(integer) RETURNS integer LANGUAGE sql AS $$ SELECT 1 $$;
        REVOKE ALL ON FUNCTION app.f(integer) FROM PUBLIC;
        ALTER FUNCTION app.f(int4) RENAME TO renamed;
        ALTER FUNCTION app.renamed(integer) SET SCHEMA api;
        CREATE OR REPLACE FUNCTION api.renamed(int) RETURNS integer
        LANGUAGE sql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$ SELECT 2 $$;
        COMMIT;
    """),
    Case("rename_does_not_revoke_public", """
        BEGIN;
        CREATE FUNCTION app.f() RETURNS integer -- expect:public
        LANGUAGE sql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$ SELECT 1 $$;
        ALTER FUNCTION app.f() RENAME TO renamed;
        COMMIT;
    """),
    Case("schema_transfer_does_not_fix_function_search_path", """
        BEGIN;
        CREATE FUNCTION app.f() RETURNS integer -- expect:path
        LANGUAGE sql SECURITY DEFINER AS $$ SELECT 1 $$;
        REVOKE ALL ON FUNCTION app.f() FROM PUBLIC;
        ALTER FUNCTION app.f() SET SCHEMA pg_catalog;
        COMMIT;
    """),
    Case("schema_wide_revoke_follows_moved_function", """
        BEGIN;
        CREATE FUNCTION app.f() RETURNS integer
        LANGUAGE sql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$ SELECT 1 $$;
        ALTER FUNCTION app.f() SET SCHEMA api;
        REVOKE ALL ON ALL FUNCTIONS IN SCHEMA api FROM PUBLIC;
        COMMIT;
    """),
    Case("old_schema_revoke_cannot_harden_moved_function", """
        BEGIN;
        CREATE FUNCTION app.f() RETURNS integer -- expect:public
        LANGUAGE sql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$ SELECT 1 $$;
        ALTER FUNCTION app.f() SET SCHEMA api;
        REVOKE ALL ON ALL FUNCTIONS IN SCHEMA app FROM PUBLIC;
        COMMIT;
    """),
    Case("rename_changes_only_selected_overload", """
        BEGIN;
        CREATE FUNCTION app.f(integer) RETURNS integer
        LANGUAGE sql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$ SELECT 1 $$;
        CREATE FUNCTION app.f(text) RETURNS integer -- expect:public
        LANGUAGE sql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$ SELECT 2 $$;
        ALTER FUNCTION app.f(int4) RENAME TO renamed;
        REVOKE ALL ON FUNCTION app.renamed(integer) FROM PUBLIC;
        COMMIT;
    """),
    Case("renamed_function_can_share_another_overloads_name", """
        BEGIN;
        CREATE FUNCTION app.f(integer) RETURNS integer
        LANGUAGE sql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$ SELECT 1 $$;
        CREATE FUNCTION app.renamed(text) RETURNS integer LANGUAGE sql AS $$ SELECT 2 $$;
        ALTER FUNCTION app.f(integer) RENAME TO renamed;
        REVOKE ALL ON FUNCTION app.renamed(int) FROM PUBLIC;
        COMMIT;
    """),
    Case("quoted_rename_and_schema_are_single_identifiers", """
        BEGIN;
        CREATE FUNCTION app."f.old"(integer) RETURNS integer
        LANGUAGE sql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$ SELECT 1 $$;
        ALTER FUNCTION app."f.old"(int) RENAME TO "f.new";
        ALTER FUNCTION app."f.new"(int4) SET SCHEMA "API.v2";
        REVOKE ALL ON FUNCTION "API.v2"."f.new"(integer) FROM PUBLIC;
        COMMIT;
    """),
    Case("quoted_renamed_identity_keeps_case", """
        BEGIN;
        CREATE FUNCTION app.f() RETURNS integer -- expect:public
        LANGUAGE sql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$ SELECT 1 $$;
        ALTER FUNCTION app.f() RENAME TO "F";
        CREATE FUNCTION app.f() RETURNS integer LANGUAGE sql AS $$ SELECT 2 $$;
        REVOKE ALL ON FUNCTION app.f() FROM PUBLIC;
        COMMIT;
    """),
    Case("rollback_to_savepoint_restores_renamed_identity", """
        BEGIN;
        CREATE FUNCTION app.f() RETURNS integer
        LANGUAGE sql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$ SELECT 1 $$;
        SAVEPOINT before_rename;
        ALTER FUNCTION app.f() RENAME TO renamed;
        REVOKE ALL ON FUNCTION app.renamed() FROM PUBLIC;
        ROLLBACK TO before_rename;
        REVOKE ALL ON FUNCTION app.f() FROM PUBLIC;
        COMMIT;
    """),
    Case("rollback_to_savepoint_restores_moved_acl", """
        BEGIN;
        CREATE FUNCTION app.f() RETURNS integer
        LANGUAGE sql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$ SELECT 1 $$;
        REVOKE ALL ON FUNCTION app.f() FROM PUBLIC;
        SAVEPOINT before_move;
        ALTER FUNCTION app.f() SET SCHEMA api;
        GRANT EXECUTE ON FUNCTION api.f() TO PUBLIC;
        ROLLBACK TO before_move;
        ALTER FUNCTION app.f() OWNER TO app_owner;
        COMMIT;
    """),
    Case("transaction_rollback_restores_function_identity", """
        BEGIN;
        CREATE FUNCTION app.f() RETURNS integer
        LANGUAGE sql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$ SELECT 1 $$;
        REVOKE ALL ON FUNCTION app.f() FROM PUBLIC;
        COMMIT;
        BEGIN;
        ALTER FUNCTION app.f() RENAME TO renamed;
        ALTER FUNCTION app.renamed() SET SCHEMA api;
        GRANT EXECUTE ON FUNCTION api.renamed() TO PUBLIC;
        ROLLBACK;
        ALTER FUNCTION app.f() OWNER TO app_owner;
    """),
    Case("identity_changes_do_not_duplicate_committed_exposure", """
        CREATE FUNCTION app.f() RETURNS integer -- expect:path,public
        LANGUAGE sql SECURITY DEFINER AS $$ SELECT 1 $$;
        ALTER FUNCTION app.f() RENAME TO renamed;
        ALTER FUNCTION app.renamed() SET SCHEMA api;
        REVOKE ALL ON FUNCTION api.renamed() FROM PUBLIC;
        DROP FUNCTION api.renamed();
    """),
    Case("reusing_old_name_creates_independent_acl", """
        BEGIN;
        CREATE FUNCTION app.f() RETURNS integer LANGUAGE sql AS $$ SELECT 1 $$;
        REVOKE ALL ON FUNCTION app.f() FROM PUBLIC;
        ALTER FUNCTION app.f() RENAME TO renamed;
        CREATE FUNCTION app.f() RETURNS integer -- expect:public
        LANGUAGE sql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$ SELECT 2 $$;
        CREATE OR REPLACE FUNCTION app.renamed() RETURNS integer
        LANGUAGE sql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$ SELECT 3 $$;
        COMMIT;
    """),
    Case("unqualified_selected_function_can_move_to_explicit_schema", """
        BEGIN;
        CREATE FUNCTION f() RETURNS integer
        LANGUAGE sql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$ SELECT 1 $$;
        ALTER FUNCTION f() RENAME TO renamed;
        ALTER FUNCTION renamed() SET SCHEMA api;
        REVOKE ALL ON FUNCTION api.renamed() FROM PUBLIC;
        COMMIT;
    """),
    Case("same_schema_transfer_is_a_no_op", """
        BEGIN;
        CREATE FUNCTION app.f() RETURNS integer
        LANGUAGE sql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$ SELECT 1 $$;
        REVOKE ALL ON FUNCTION app.f() FROM PUBLIC;
        ALTER FUNCTION app.f() SET SCHEMA app;
        COMMIT;
    """),
)

# Unknown deployment/dialect/control-flow inputs and malformed source cannot
# certify clean. Positive findings established before an unknown may survive.
INCOMPLETE_CASES = (
    Case("unclosed_block_comment", "/* unfinished migration\n"),
    Case("unclosed_string", "SELECT 'unfinished;\n"),
    Case("unclosed_dollar_body", "CREATE FUNCTION app.f() RETURNS integer LANGUAGE sql AS $body$ SELECT 1;\n"),
    Case("unknown_alter_target", "ALTER FUNCTION app.external(integer) SECURITY DEFINER;\n"),
    Case("unknown_revoke_target", "REVOKE EXECUTE ON FUNCTION app.external(integer) FROM PUBLIC;\n"),
    Case("replacement_with_unseen_acl", """
        CREATE OR REPLACE FUNCTION app.external() RETURNS integer
        LANGUAGE sql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$ SELECT 1 $$;
    """),
    Case("function_setting_from_unknown_current", """
        BEGIN;
        CREATE FUNCTION app.f() RETURNS integer LANGUAGE sql SECURITY DEFINER
        SET search_path FROM CURRENT AS $$ SELECT 1 $$;
        REVOKE ALL ON FUNCTION app.f() FROM PUBLIC;
        COMMIT;
    """),
    Case("role_specific_default_acl_is_unresolved", """
        ALTER DEFAULT PRIVILEGES FOR ROLE deployment_owner REVOKE EXECUTE ON FUNCTIONS FROM PUBLIC;
        CREATE FUNCTION app.f() RETURNS integer LANGUAGE sql SECURITY DEFINER
        SET search_path = pg_catalog, pg_temp AS $$ SELECT 1 $$;
    """),
    Case("mysql_delimiter_is_not_postgres", "DELIMITER //\nCREATE FUNCTION f() RETURNS INT RETURN 1//\n"),
    Case("psql_include_requires_external_context", "\\i privileges.sql\n"),
    Case("do_block_can_execute_hidden_ddl", """
        DO $body$ BEGIN
        EXECUTE 'CREATE FUNCTION app.hidden() RETURNS integer LANGUAGE sql SECURITY DEFINER AS ''SELECT 1''';
        END $body$;
    """),
    Case("set_local_role_invalidates_known_default_acl", """
        ALTER DEFAULT PRIVILEGES REVOKE EXECUTE ON FUNCTIONS FROM PUBLIC;
        BEGIN;
        SET LOCAL ROLE another_owner;
        CREATE FUNCTION app.f() RETURNS integer LANGUAGE sql SECURITY DEFINER
        SET search_path = pg_catalog, pg_temp AS $$ SELECT 1 $$;
        COMMIT;
    """),
    Case("unbalanced_statement_parenthesis", "SELECT (1;\n"),
    Case("as_requires_a_function_body", """
        BEGIN;
        CREATE FUNCTION app.f() RETURNS integer LANGUAGE sql SECURITY DEFINER
        SET search_path = pg_catalog, pg_temp AS ;
        REVOKE ALL ON FUNCTION app.f() FROM PUBLIC;
        COMMIT;
    """),
    Case("declaration_without_function_body", """
        BEGIN;
        CREATE FUNCTION app.f() RETURNS integer LANGUAGE sql SECURITY DEFINER
        SET search_path = pg_catalog, pg_temp;
        REVOKE ALL ON FUNCTION app.f() FROM PUBLIC;
        COMMIT;
    """),
    Case("savepoint_nesting_exceeds_documented_limit",
         "BEGIN;\n" + "".join(f"SAVEPOINT s{number};\n" for number in range(65)) + "ROLLBACK;\n"),
    Case("owner_target_requires_selected_signature", "ALTER FUNCTION app.f() OWNER TO app_mutator;\n"),
    Case("owner_clause_cannot_hide_other_changes", """
        CREATE FUNCTION app.f() RETURNS integer LANGUAGE sql AS $$ SELECT 1 $$;
        ALTER FUNCTION app.f() OWNER TO app_mutator SECURITY DEFINER;
    """),
    Case("owner_clause_requires_one_role", """
        CREATE FUNCTION app.f() RETURNS integer LANGUAGE sql AS $$ SELECT 1 $$;
        ALTER FUNCTION app.f() OWNER TO;
    """),
    Case("owner_transfer_does_not_resolve_replacement_acl", """
        BEGIN;
        CREATE OR REPLACE FUNCTION app.f() RETURNS integer LANGUAGE sql SECURITY DEFINER
        SET search_path = pg_catalog, pg_temp AS $$ SELECT 1 $$;
        ALTER FUNCTION app.f() OWNER TO app_mutator;
        COMMIT;
    """),
    Case("do_other_language_is_not_plpgsql", "DO LANGUAGE plpython3u $$ BEGIN GRANT app TO CURRENT_USER; END $$;\n"),
    Case("do_conditional_grant_requires_control_flow", """
        DO $$ BEGIN IF allowed THEN GRANT app TO CURRENT_USER; END IF; END $$;
    """),
    Case("do_grant_function_privileges_requires_modeling", """
        DO $$ BEGIN EXECUTE 'GRANT EXECUTE ON FUNCTION app.f() TO PUBLIC'; END $$;
    """),
    Case("do_dynamic_argument_can_execute_arbitrary_code", """
        DO $$ BEGIN EXECUTE format('GRANT app TO %I', arbitrary_function()); END $$;
    """),
    Case("do_unused_format_argument_still_has_effects", """
        DO $$ BEGIN EXECUTE format('GRANT app TO %1$I', current_user, arbitrary_function()); END $$;
    """),
    Case("do_raw_format_conversion_is_not_identifier_quoting", """
        DO $$ BEGIN EXECUTE format('GRANT app TO %s', current_user); END $$;
    """),
    Case("do_format_identifier_must_be_a_whole_token", """
        DO $$ BEGIN EXECUTE format('GRANT "%I" TO current_user', current_user); END $$;
    """),
    Case("do_format_cannot_execute_additional_statement", """
        DO $$ BEGIN
          EXECUTE format('GRANT app TO %I; GRANT EXECUTE ON FUNCTION app.f() TO PUBLIC', current_user);
        END $$;
    """),
    Case("do_format_argument_position_must_exist", """
        DO $$ BEGIN EXECUTE format('GRANT app TO %2$I', current_user); END $$;
    """),
    Case("do_unqualified_format_after_changed_search_path", """
        SET search_path = app, pg_catalog;
        DO $$ BEGIN EXECUTE format('GRANT app TO %I', current_user); END $$;
    """),
    Case("do_selected_format_definition_is_not_builtin", """
        CREATE FUNCTION public.format(text, name) RETURNS text
        LANGUAGE sql AS $$ SELECT 'SELECT dangerous()' $$;
        DO $$ BEGIN EXECUTE format('GRANT app TO %I', current_user); END $$;
    """),
    Case("do_qualified_format_definition_is_not_builtin", """
        CREATE OR REPLACE FUNCTION pg_catalog.format(text, name) RETURNS text
        LANGUAGE sql AS $$ SELECT 'SELECT dangerous()' $$;
        DO $$ BEGIN EXECUTE pg_catalog.format('GRANT app TO %I', current_user); END $$;
    """),
    Case("do_declarations_require_binding_analysis", """
        DO $$ DECLARE target text := arbitrary_function();
        BEGIN EXECUTE format('GRANT app TO %I', target); END $$;
    """),
    Case("do_exception_handler_can_hide_ddl", """
        DO $$ BEGIN GRANT app TO current_user;
        EXCEPTION WHEN others THEN EXECUTE 'SELECT dangerous()'; END $$;
    """),
    Case("cte_missing_as", "WITH sample (SELECT 1) SELECT * FROM sample;\n"),
    Case("cte_missing_body", "WITH sample AS () SELECT * FROM sample;\n"),
    Case("cte_missing_primary_query", "WITH sample AS (SELECT 1);\n"),
    Case("cte_column_list_requires_identifiers", "WITH sample(value integer) AS (SELECT 1) SELECT * FROM sample;\n"),
    Case("cte_materialization_requires_body", "WITH sample AS NOT (SELECT 1) SELECT * FROM sample;\n"),
    Case("cte_unmodeled_recursive_search", """
        WITH RECURSIVE sample(n) AS (SELECT 1)
        SEARCH DEPTH FIRST BY n SET order_column SELECT * FROM sample;
    """),
    Case("server_side_copy_remains_outside_statement_model", """
        COPY app.settings FROM PROGRAM 'generate-settings';
        SELECT 1;
    """),
    Case("library_load_remains_outside_statement_model", "LOAD 'auto_explain';\nSELECT 1;\n"),
    Case("cte_cannot_hide_dynamic_primary_statement", """
        WITH sample AS (SELECT 1) EXECUTE external_statement;
    """),
    Case("cte_cannot_hide_dynamic_substatement", """
        WITH sample AS (CALL mutate_privileges()) SELECT 1;
    """),
    Case("cte_cannot_hide_function_ddl", """
        WITH sample AS (CREATE FUNCTION app.hidden() RETURNS int LANGUAGE sql AS $$ SELECT 1 $$)
        SELECT 1;
    """),
    Case("cte_nesting_budget", "WITH sample AS (" * 65 + "SELECT 1" + ") SELECT 1" * 65 + ";\n"),
    Case("psql_relative_include_requires_external_context", "\\ir privileges.sql\nSELECT 1;\n"),
    Case("psql_execute_generated_sql_is_not_display", "SELECT 'GRANT EXECUTE ON FUNCTION app.f() TO PUBLIC' \\gexec\n"),
    Case("psql_connection_switch_invalidates_context", "\\connect other_database\nSELECT 1;\n"),
    Case("psql_autocommit_switch_changes_publication", "\\set AUTOCOMMIT off\nSELECT 1;\n"),
    Case("psql_conditional_requires_control_flow", "\\if false\nSELECT 1;\n\\endif\n"),
    Case("psql_backticks_require_execution", "\\echo `load_external_sql`\nSELECT 1;\n"),
    Case("psql_double_quoted_arguments_are_outside_literal_subset", '\\echo "message"\nSELECT 1;\n'),
    Case("psql_escaped_arguments_are_outside_literal_subset", r"""
        \echo 'message\n'
        SELECT 1;
    """),
    Case("psql_error_stop_requires_literal_value", "\\set ON_ERROR_STOP :enabled\nSELECT 1;\n"),
    Case("psql_invalid_error_stop_value", "\\set ON_ERROR_STOP maybe\nSELECT 1;\n"),
    Case("psql_setting_names_are_case_sensitive", "\\set on_error_stop on\nSELECT 1;\n"),
    Case("psql_sql_variable_interpolation_is_not_literal", "\\set ON_ERROR_STOP on\nSELECT :ON_ERROR_STOP;\n"),
    Case("psql_sql_quoted_variable_is_not_literal", "SELECT :'query_text';\n"),
    Case("psql_sql_identifier_variable_is_not_literal", 'SELECT 1 FROM :"schema".settings;\n'),
    Case("psql_variable_existence_requires_context", "SELECT :{?enabled};\n"),
    Case("psql_numeric_variable_requires_context", "SELECT :42;\n"),
    Case("psql_non_ascii_symbol_variable_requires_context", "SELECT :💥;\n"),
    Case("psql_non_ascii_combining_variable_requires_context", "SELECT :\u0301;\n"),
    Case("psql_non_ascii_space_variable_requires_context", "SELECT :\u00a0;\n"),
    Case("psql_non_ascii_variable_at_eof_requires_context", "SELECT :\u00a0"),
    Case("psql_non_ascii_variable_after_cast_requires_context", "SELECT 1:::💥;\n"),
    Case("psql_non_ascii_variable_does_not_hide_later_function", """
        SELECT :\u00a0;
        CREATE FUNCTION app.f() RETURNS integer -- expect:path,public
        LANGUAGE sql SECURITY DEFINER AS $$ SELECT 1 $$;
    """),
    Case("psql_numeric_slice_bound_can_interpolate_external_variable", "SELECT (ARRAY[1, 2, 3])[1:2];\n"),
    Case("psql_numeric_slice_without_lower_bound_can_interpolate", "SELECT (ARRAY[1, 2, 3])[:2];\n"),
    Case("psql_variable_after_cast_requires_context", "SELECT 1:::cast_type;\n"),
    Case("psql_variable_before_escape_string_requires_context", "SELECT :e'quoted';\n"),
    Case("psql_same_line_execution_is_not_echo_text", "\\echo ready \\gexec\nSELECT 1;\n"),
    Case("psql_include_does_not_swallow_next_function", r"""
        \i external.sql
        CREATE FUNCTION app.f() RETURNS integer -- expect:path,public
        LANGUAGE sql SECURITY DEFINER AS $$ SELECT 1 $$;
    """),
    Case("rename_requires_selected_function", "ALTER FUNCTION app.unseen() RENAME TO renamed;\n"),
    Case("schema_transfer_requires_selected_function", "ALTER FUNCTION app.unseen() SET SCHEMA api;\n"),
    Case("rename_requires_one_unqualified_identifier", """
        CREATE FUNCTION app.f() RETURNS integer LANGUAGE sql AS $$ SELECT 1 $$;
        ALTER FUNCTION app.f() RENAME TO api.renamed;
    """),
    Case("schema_transfer_requires_one_schema_identifier", """
        CREATE FUNCTION app.f() RETURNS integer LANGUAGE sql AS $$ SELECT 1 $$;
        ALTER FUNCTION app.f() SET SCHEMA 'api';
    """),
    Case("rename_cannot_hide_security_change", """
        CREATE FUNCTION app.f() RETURNS integer LANGUAGE sql AS $$ SELECT 1 $$;
        ALTER FUNCTION app.f() RENAME TO renamed SECURITY DEFINER;
    """),
    Case("schema_transfer_cannot_hide_security_change", """
        CREATE FUNCTION app.f() RETURNS integer LANGUAGE sql AS $$ SELECT 1 $$;
        ALTER FUNCTION app.f() SET SCHEMA api SECURITY DEFINER;
    """),
    Case("rename_cannot_overwrite_another_function", """
        BEGIN;
        CREATE FUNCTION app.f() RETURNS integer -- expect:public
        LANGUAGE sql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$ SELECT 1 $$;
        CREATE FUNCTION app.renamed() RETURNS integer -- expect:public
        LANGUAGE sql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$ SELECT 2 $$;
        ALTER FUNCTION app.f() RENAME TO renamed;
        COMMIT;
    """),
    Case("schema_transfer_cannot_overwrite_another_function", """
        BEGIN;
        CREATE FUNCTION app.f() RETURNS integer -- expect:public
        LANGUAGE sql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$ SELECT 1 $$;
        CREATE FUNCTION api.f() RETURNS integer -- expect:public
        LANGUAGE sql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$ SELECT 2 $$;
        ALTER FUNCTION app.f() SET SCHEMA api;
        COMMIT;
    """),
    Case("old_name_no_longer_resolves_after_rename", """
        BEGIN;
        CREATE FUNCTION app.f() RETURNS integer -- expect:public
        LANGUAGE sql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$ SELECT 1 $$;
        ALTER FUNCTION app.f() RENAME TO renamed;
        REVOKE ALL ON FUNCTION app.f() FROM PUBLIC;
        COMMIT;
    """),
    Case("old_schema_no_longer_resolves_after_transfer", """
        BEGIN;
        CREATE FUNCTION app.f() RETURNS integer -- expect:public
        LANGUAGE sql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$ SELECT 1 $$;
        ALTER FUNCTION app.f() SET SCHEMA api;
        REVOKE ALL ON FUNCTION app.f() FROM PUBLIC;
        COMMIT;
    """),
    Case("identity_change_keeps_unknown_replacement_acl", """
        BEGIN;
        CREATE OR REPLACE FUNCTION app.f() RETURNS integer
        LANGUAGE sql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$ SELECT 1 $$;
        ALTER FUNCTION app.f() RENAME TO renamed;
        ALTER FUNCTION app.renamed() SET SCHEMA api;
        COMMIT;
    """),
    Case("renamed_format_function_is_not_builtin", """
        CREATE FUNCTION app.custom_format(text, name) RETURNS text
        LANGUAGE sql AS $$ SELECT 'SELECT dangerous()' $$;
        ALTER FUNCTION app.custom_format(text, name) RENAME TO format;
        DO $$ BEGIN EXECUTE format('GRANT app TO %I', current_user); END $$;
    """),
    Case("moved_format_function_is_not_builtin", """
        CREATE FUNCTION app.format(text, name) RETURNS text
        LANGUAGE sql AS $$ SELECT 'SELECT dangerous()' $$;
        ALTER FUNCTION app.format(text, name) SET SCHEMA pg_catalog;
        DO $$ BEGIN EXECUTE pg_catalog.format('GRANT app TO %I', current_user); END $$;
    """),
    Case("unqualified_rename_after_search_path_change_is_unresolved", """
        CREATE FUNCTION f() RETURNS integer LANGUAGE sql AS $$ SELECT 1 $$;
        SET search_path = other_schema, pg_catalog;
        ALTER FUNCTION f() RENAME TO renamed;
    """),
    Case("same_name_rename_conflicts_with_existing_function", """
        CREATE FUNCTION app.f() RETURNS integer -- expect:public
        LANGUAGE sql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$ SELECT 1 $$;
        ALTER FUNCTION app.f() RENAME TO f;
    """),
)


# Procedure labels also distinguish PostgreSQL's two OUT-argument lookup
# conventions and the different ALL FUNCTIONS / ALL ROUTINES privilege sets.
# These cases were fixed before activating the procedure implementation.
PROCEDURE_CASES = (
    Case("procedure_default_exposure", """
        CREATE PROCEDURE app.run() -- expect:path,public
        LANGUAGE plpgsql SECURITY DEFINER AS $$ BEGIN NULL; END $$;
    """),
    Case("procedure_hardened_in_one_transaction", """
        BEGIN;
        CREATE PROCEDURE app.run(IN item integer)
        LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp
        AS $$ BEGIN NULL; END $$;
        REVOKE EXECUTE ON PROCEDURE app.run(IN int4) FROM PUBLIC;
        GRANT EXECUTE ON PROCEDURE app.run(integer) TO app_role;
        COMMIT;
    """),
    Case("procedure_default_invoker_is_clean", """
        CREATE PROCEDURE app.run() LANGUAGE plpgsql AS $$ BEGIN NULL; END $$;
    """),
    Case("procedure_revoke_does_not_fix_path", """
        BEGIN;
        CREATE PROCEDURE app.run() -- expect:path
        LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog
        AS $$ BEGIN NULL; END $$;
        REVOKE ALL ON PROCEDURE app.run() FROM PUBLIC;
        COMMIT;
    """),
    Case("procedure_replace_preserves_acl", """
        BEGIN;
        CREATE PROCEDURE app.run() LANGUAGE plpgsql AS $$ BEGIN NULL; END $$;
        REVOKE ALL ON PROCEDURE app.run() FROM PUBLIC;
        CREATE OR REPLACE PROCEDURE app.run() -- expect:path
        LANGUAGE plpgsql SECURITY DEFINER AS $$ BEGIN NULL; END $$;
        COMMIT;
    """),
    Case("procedure_and_function_share_name_with_different_inputs", """
        BEGIN;
        CREATE FUNCTION app.run(integer) RETURNS int -- expect:public
        LANGUAGE sql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$ SELECT 1 $$;
        CREATE PROCEDURE app.run(text) LANGUAGE plpgsql SECURITY DEFINER
        SET search_path = pg_catalog, pg_temp AS $$ BEGIN NULL; END $$;
        REVOKE ALL ON PROCEDURE app.run(text) FROM PUBLIC;
        COMMIT;
    """),
    Case("all_functions_does_not_revoke_procedures", """
        BEGIN;
        CREATE FUNCTION app.f() RETURNS int LANGUAGE sql SECURITY DEFINER
        SET search_path = pg_catalog, pg_temp AS $$ SELECT 1 $$;
        CREATE PROCEDURE app.p() -- expect:public
        LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp
        AS $$ BEGIN NULL; END $$;
        REVOKE ALL ON ALL FUNCTIONS IN SCHEMA app FROM PUBLIC;
        COMMIT;
    """),
    Case("all_procedures_does_not_revoke_functions", """
        BEGIN;
        CREATE FUNCTION app.f() RETURNS int -- expect:public
        LANGUAGE sql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$ SELECT 1 $$;
        CREATE PROCEDURE app.p() LANGUAGE plpgsql SECURITY DEFINER
        SET search_path = pg_catalog, pg_temp AS $$ BEGIN NULL; END $$;
        REVOKE ALL ON ALL PROCEDURES IN SCHEMA app FROM PUBLIC;
        COMMIT;
    """),
    Case("all_routines_covers_functions_and_procedures", """
        BEGIN;
        CREATE FUNCTION app.f() RETURNS int LANGUAGE sql SECURITY DEFINER
        SET search_path = pg_catalog, pg_temp AS $$ SELECT 1 $$;
        CREATE PROCEDURE app.p() LANGUAGE plpgsql SECURITY DEFINER
        SET search_path = pg_catalog, pg_temp AS $$ BEGIN NULL; END $$;
        REVOKE ALL ON ALL ROUTINES IN SCHEMA app FROM PUBLIC;
        COMMIT;
    """),
    Case("default_functions_privileges_include_procedures", """
        ALTER DEFAULT PRIVILEGES REVOKE EXECUTE ON FUNCTIONS FROM PUBLIC;
        CREATE PROCEDURE app.p() LANGUAGE plpgsql SECURITY DEFINER
        SET search_path = pg_catalog, pg_temp AS $$ BEGIN NULL; END $$;
    """),
    Case("default_routines_privileges_include_functions", """
        ALTER DEFAULT PRIVILEGES REVOKE EXECUTE ON ROUTINES FROM PUBLIC;
        CREATE PROCEDURE app.p() LANGUAGE plpgsql SECURITY DEFINER
        SET search_path = pg_catalog, pg_temp AS $$ BEGIN NULL; END $$;
        CREATE FUNCTION app.f() RETURNS int LANGUAGE sql SECURITY DEFINER
        SET search_path = pg_catalog, pg_temp AS $$ SELECT 1 $$;
    """),
    Case("procedure_rename_schema_and_owner_keep_acl", """
        BEGIN;
        CREATE PROCEDURE app.p(integer) LANGUAGE plpgsql SECURITY DEFINER
        SET search_path = pg_catalog, pg_temp AS $$ BEGIN NULL; END $$;
        ALTER PROCEDURE app.p(integer) RENAME TO renamed;
        ALTER PROCEDURE app.renamed(integer) SET SCHEMA api;
        ALTER PROCEDURE api.renamed(integer) OWNER TO app_owner;
        REVOKE ALL ON ROUTINE api.renamed(integer) FROM PUBLIC;
        COMMIT;
    """),
    Case("alter_routine_selects_procedure", """
        BEGIN;
        CREATE PROCEDURE app.p() LANGUAGE plpgsql
        SET search_path = pg_catalog, pg_temp AS $$ BEGIN NULL; END $$;
        ALTER ROUTINE app.p() SECURITY DEFINER; -- expect:public
        COMMIT;
    """),
    Case("procedure_savepoint_restores_security_and_identity", """
        BEGIN;
        CREATE PROCEDURE app.p() -- expect:public
        LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp
        AS $$ BEGIN NULL; END $$;
        SAVEPOINT before_change;
        ALTER PROCEDURE app.p() RENAME TO renamed;
        REVOKE ALL ON PROCEDURE app.renamed() FROM PUBLIC;
        ALTER PROCEDURE app.renamed() RESET search_path;
        ROLLBACK TO before_change;
        COMMIT;
    """),
    Case("procedure_drop_removes_unpublished_exposure", """
        BEGIN;
        CREATE PROCEDURE app.p() LANGUAGE plpgsql SECURITY DEFINER AS $$ BEGIN NULL; END $$;
        DROP PROCEDURE app.p() RESTRICT;
        COMMIT;
    """),
    Case("procedure_out_explicit_input_identity", """
        BEGIN;
        CREATE PROCEDURE app.p(IN item integer, OUT result text)
        LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp
        AS $$ BEGIN result := ''; END $$;
        REVOKE ALL ON PROCEDURE app.p(IN integer) FROM PUBLIC;
        COMMIT;
    """),
    Case("procedure_out_full_signature_identity", """
        BEGIN;
        CREATE PROCEDURE app.p(IN item integer, OUT result text)
        LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp
        AS $$ BEGIN result := ''; END $$;
        REVOKE ALL ON PROCEDURE app.p(integer, text) FROM PUBLIC;
        ALTER PROCEDURE app.p(integer, text) RENAME TO renamed;
        DROP PROCEDURE app.renamed(integer, text);
        COMMIT;
    """),
    Case("procedure_out_explicit_modes_disambiguate_overloads", """
        BEGIN;
        CREATE PROCEDURE app.p(IN item integer, OUT result text)
        LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp
        AS $$ BEGIN result := ''; END $$;
        CREATE PROCEDURE app.p(IN item integer, IN value text) -- expect:public
        LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp
        AS $$ BEGIN NULL; END $$;
        REVOKE ALL ON PROCEDURE app.p(IN integer, OUT text) FROM PUBLIC;
        COMMIT;
    """),
    Case("procedure_inout_variadic_and_defaults", """
        BEGIN;
        CREATE PROCEDURE app.p(INOUT item integer, VARIADIC values text[] DEFAULT ARRAY[]::text[])
        LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp
        AS $$ BEGIN NULL; END $$;
        REVOKE ALL ON PROCEDURE app.p(INOUT pg_catalog.int4, VARIADIC text[]) FROM PUBLIC;
        COMMIT;
    """),
    Case("procedure_identity_changes_do_not_duplicate_exposure", """
        CREATE PROCEDURE app.p() -- expect:path,public
        LANGUAGE plpgsql SECURITY DEFINER AS $$ BEGIN NULL; END $$;
        ALTER PROCEDURE app.p() RENAME TO renamed;
        ALTER ROUTINE app.renamed() SET SCHEMA api;
    """),
    Case("procedure_quoted_public_is_an_ordinary_role", """
        BEGIN;
        CREATE PROCEDURE app.p() -- expect:public
        LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp
        AS $$ BEGIN NULL; END $$;
        REVOKE EXECUTE ON PROCEDURE app.p() FROM "PUBLIC";
        COMMIT;
    """),
    Case("procedure_invoker_transition_before_commit", """
        BEGIN;
        CREATE PROCEDURE app.p() LANGUAGE plpgsql SECURITY DEFINER AS $$ BEGIN NULL; END $$;
        ALTER PROCEDURE app.p() SECURITY INVOKER;
        COMMIT;
    """),
    Case("procedure_defaults_only_affect_future_objects", """
        BEGIN;
        CREATE PROCEDURE app.p() -- expect:public
        LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp
        AS $$ BEGIN NULL; END $$;
        ALTER DEFAULT PRIVILEGES REVOKE ALL ON ROUTINES FROM PUBLIC;
        CREATE PROCEDURE app.later() LANGUAGE plpgsql SECURITY DEFINER
        SET search_path = pg_catalog, pg_temp AS $$ BEGIN NULL; END $$;
        COMMIT;
    """),
)

PROCEDURE_INCOMPLETE_CASES = (
    Case("procedure_wrong_grant_kind_preserves_exposure", """
        BEGIN;
        CREATE PROCEDURE app.p() -- expect:public
        LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp
        AS $$ BEGIN NULL; END $$;
        REVOKE ALL ON FUNCTION app.p() FROM PUBLIC;
        COMMIT;
    """),
    Case("procedure_wrong_alter_kind_preserves_exposure", """
        BEGIN;
        CREATE PROCEDURE app.p() -- expect:public
        LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp
        AS $$ BEGIN NULL; END $$;
        ALTER FUNCTION app.p() SECURITY INVOKER;
        COMMIT;
    """),
    Case("procedure_wrong_drop_kind_preserves_exposure", """
        BEGIN;
        CREATE PROCEDURE app.p() -- expect:public
        LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp
        AS $$ BEGIN NULL; END $$;
        DROP FUNCTION app.p();
        COMMIT;
    """),
    Case("procedure_cannot_replace_function_kind", """
        BEGIN;
        CREATE FUNCTION app.p() RETURNS int -- expect:public
        LANGUAGE sql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$ SELECT 1 $$;
        CREATE OR REPLACE PROCEDURE app.p() LANGUAGE plpgsql AS $$ BEGIN NULL; END $$;
        COMMIT;
    """),
    Case("procedure_rename_cannot_overwrite_function", """
        BEGIN;
        CREATE PROCEDURE app.p() -- expect:public
        LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp
        AS $$ BEGIN NULL; END $$;
        CREATE FUNCTION app.f() RETURNS int LANGUAGE sql AS $$ SELECT 1 $$;
        ALTER PROCEDURE app.p() RENAME TO f;
        COMMIT;
    """),
    Case("procedure_out_implicit_signature_ambiguity", """
        BEGIN;
        CREATE PROCEDURE app.p(IN item integer, OUT result text) -- expect:public
        LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp
        AS $$ BEGIN result := ''; END $$;
        CREATE PROCEDURE app.p(integer, text) -- expect:public
        LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp
        AS $$ BEGIN NULL; END $$;
        REVOKE ALL ON PROCEDURE app.p(integer, text) FROM PUBLIC;
        COMMIT;
    """),
    Case("procedure_unseen_replacement_acl_is_unknown", """
        CREATE OR REPLACE PROCEDURE app.p() LANGUAGE plpgsql SECURITY DEFINER
        SET search_path = pg_catalog, pg_temp AS $$ BEGIN NULL; END $$;
    """),
    Case("procedure_call_does_not_execute_body_in_scanner", """
        CREATE PROCEDURE app.p() -- expect:path,public
        LANGUAGE plpgsql SECURITY DEFINER AS $$ BEGIN NULL; END $$;
        CALL app.p();
    """),
    Case("procedure_from_current_does_not_borrow_path", """
        CREATE PROCEDURE app.p() -- expect:public
        LANGUAGE plpgsql SECURITY DEFINER SET search_path FROM CURRENT
        AS $$ BEGIN NULL; END $$;
    """),
    Case("procedure_unqualified_lookup_requires_catalog", """
        CREATE PROCEDURE app.p() LANGUAGE plpgsql AS $$ BEGIN NULL; END $$;
        ALTER PROCEDURE app.p SECURITY DEFINER;
    """),
)


# PostgreSQL's per-schema default ACL is added to the global default ACL.
# These labels are frozen before the schema-default implementation. In
# particular, the former incomplete single-schema REVOKE case now requires
# the positive PUBLIC finding instead of merely accepting an incomplete scan.
SCHEMA_DEFAULT_CASES = (
    Case("schema_default_revoke_does_not_override_global_grant", """
        ALTER DEFAULT PRIVILEGES IN SCHEMA app REVOKE EXECUTE ON FUNCTIONS FROM PUBLIC;
        CREATE FUNCTION app.f() RETURNS integer -- expect:public
        LANGUAGE sql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$ SELECT 1 $$;
    """),
    Case("schema_default_revoke_does_not_override_global_procedure_grant", """
        ALTER DEFAULT PRIVILEGES IN SCHEMA app REVOKE EXECUTE ON ROUTINES FROM PUBLIC;
        CREATE PROCEDURE app.p() -- expect:public
        LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$ BEGIN NULL; END $$;
    """),
    Case("schema_default_grants_both_routine_kinds_only_in_selected_schema", """
        ALTER DEFAULT PRIVILEGES REVOKE EXECUTE ON FUNCTIONS FROM PUBLIC;
        ALTER DEFAULT PRIVILEGES IN SCHEMA app GRANT EXECUTE ON ROUTINES TO PUBLIC;
        CREATE FUNCTION app.f() RETURNS integer -- expect:public
        LANGUAGE sql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$ SELECT 1 $$;
        CREATE PROCEDURE app.p() -- expect:public
        LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$ BEGIN NULL; END $$;
        CREATE PROCEDURE private.p()
        LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$ BEGIN NULL; END $$;
    """),
    Case("global_default_revoke_preserves_prior_schema_grant", """
        ALTER DEFAULT PRIVILEGES IN SCHEMA app GRANT EXECUTE ON FUNCTIONS TO PUBLIC;
        ALTER DEFAULT PRIVILEGES REVOKE ALL PRIVILEGES ON ROUTINES FROM PUBLIC;
        CREATE PROCEDURE app.p() -- expect:public
        LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$ BEGIN NULL; END $$;
    """),
    Case("schema_default_revoke_undoes_only_its_schema_grant", """
        ALTER DEFAULT PRIVILEGES REVOKE EXECUTE ON ROUTINES FROM PUBLIC;
        ALTER DEFAULT PRIVILEGES IN SCHEMA app, other GRANT EXECUTE ON FUNCTIONS TO PUBLIC;
        ALTER DEFAULT PRIVILEGES IN SCHEMA app REVOKE ALL ON ROUTINES FROM PUBLIC;
        CREATE PROCEDURE app.p()
        LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$ BEGIN NULL; END $$;
        CREATE FUNCTION other.f() RETURNS integer -- expect:public
        LANGUAGE sql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$ SELECT 1 $$;
    """),
    Case("schema_default_names_preserve_quoting_and_identifier_folding", """
        ALTER DEFAULT PRIVILEGES REVOKE EXECUTE ON FUNCTIONS FROM PUBLIC;
        ALTER DEFAULT PRIVILEGES IN SCHEMA "App Space", APP GRANT ALL PRIVILEGES ON ROUTINES TO PUBLIC;
        CREATE PROCEDURE "App Space".p() -- expect:public
        LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$ BEGIN NULL; END $$;
        CREATE FUNCTION app.f() RETURNS integer -- expect:public
        LANGUAGE sql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$ SELECT 1 $$;
        CREATE PROCEDURE "APP".p()
        LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$ BEGIN NULL; END $$;
    """),
    Case("schema_default_grant_affects_future_objects_only", """
        ALTER DEFAULT PRIVILEGES REVOKE EXECUTE ON ROUTINES FROM PUBLIC;
        CREATE FUNCTION app.before() RETURNS integer
        LANGUAGE sql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$ SELECT 1 $$;
        ALTER DEFAULT PRIVILEGES IN SCHEMA app GRANT EXECUTE ON ROUTINES TO PUBLIC;
        CREATE PROCEDURE app.after() -- expect:public
        LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$ BEGIN NULL; END $$;
    """),
    Case("schema_default_revoke_does_not_revoke_existing_object", """
        ALTER DEFAULT PRIVILEGES REVOKE EXECUTE ON ROUTINES FROM PUBLIC;
        BEGIN;
        ALTER DEFAULT PRIVILEGES IN SCHEMA app GRANT EXECUTE ON FUNCTIONS TO PUBLIC;
        CREATE PROCEDURE app.before() -- expect:public
        LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$ BEGIN NULL; END $$;
        ALTER DEFAULT PRIVILEGES IN SCHEMA app REVOKE EXECUTE ON FUNCTIONS FROM PUBLIC;
        CREATE PROCEDURE app.after()
        LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$ BEGIN NULL; END $$;
        COMMIT;
    """),
    Case("schema_default_grant_does_not_reset_replaced_routine_acl", """
        ALTER DEFAULT PRIVILEGES REVOKE EXECUTE ON ROUTINES FROM PUBLIC;
        CREATE PROCEDURE app.p() LANGUAGE plpgsql AS $$ BEGIN NULL; END $$;
        ALTER DEFAULT PRIVILEGES IN SCHEMA app GRANT EXECUTE ON FUNCTIONS TO PUBLIC;
        CREATE OR REPLACE PROCEDURE app.p()
        LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$ BEGIN NULL; END $$;
    """),
    Case("schema_transfer_does_not_apply_target_default_privileges", """
        ALTER DEFAULT PRIVILEGES REVOKE EXECUTE ON ROUTINES FROM PUBLIC;
        ALTER DEFAULT PRIVILEGES IN SCHEMA app GRANT EXECUTE ON FUNCTIONS TO PUBLIC;
        BEGIN;
        CREATE PROCEDURE private.p()
        LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$ BEGIN NULL; END $$;
        ALTER PROCEDURE private.p() SET SCHEMA app;
        COMMIT;
    """),
    Case("schema_default_rollback_removes_uncommitted_grant", """
        ALTER DEFAULT PRIVILEGES REVOKE EXECUTE ON ROUTINES FROM PUBLIC;
        BEGIN;
        ALTER DEFAULT PRIVILEGES IN SCHEMA app GRANT EXECUTE ON FUNCTIONS TO PUBLIC;
        ROLLBACK;
        CREATE PROCEDURE app.p()
        LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$ BEGIN NULL; END $$;
    """),
    Case("schema_default_savepoint_restores_reverted_grant", """
        ALTER DEFAULT PRIVILEGES REVOKE EXECUTE ON ROUTINES FROM PUBLIC;
        BEGIN;
        ALTER DEFAULT PRIVILEGES IN SCHEMA app GRANT EXECUTE ON FUNCTIONS TO PUBLIC;
        SAVEPOINT keep_grant;
        ALTER DEFAULT PRIVILEGES IN SCHEMA app REVOKE ALL ON ROUTINES FROM PUBLIC;
        ROLLBACK TO keep_grant;
        CREATE PROCEDURE app.p() -- expect:public
        LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$ BEGIN NULL; END $$;
        COMMIT;
    """),
    Case("schema_default_named_roles_do_not_mean_public", """
        ALTER DEFAULT PRIVILEGES REVOKE ALL ON ROUTINES FROM PUBLIC;
        ALTER DEFAULT PRIVILEGES IN SCHEMA app GRANT EXECUTE ON ROUTINES TO "public", GROUP app_reader;
        CREATE PROCEDURE app.p()
        LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$ BEGIN NULL; END $$;
    """),
    Case("schema_default_public_among_named_roles_is_public", """
        ALTER DEFAULT PRIVILEGES REVOKE ALL ON ROUTINES FROM PUBLIC;
        ALTER DEFAULT PRIVILEGES IN SCHEMA app GRANT EXECUTE ON ROUTINES TO app_reader, PUBLIC;
        CREATE PROCEDURE app.p() -- expect:public
        LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$ BEGIN NULL; END $$;
    """),
    Case("schema_default_grant_option_revoke_preserves_execute", """
        ALTER DEFAULT PRIVILEGES REVOKE ALL ON ROUTINES FROM PUBLIC;
        ALTER DEFAULT PRIVILEGES IN SCHEMA app GRANT EXECUTE ON ROUTINES TO PUBLIC;
        ALTER DEFAULT PRIVILEGES IN SCHEMA app REVOKE GRANT OPTION FOR EXECUTE ON FUNCTIONS FROM PUBLIC;
        CREATE PROCEDURE app.p() -- expect:public
        LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$ BEGIN NULL; END $$;
    """),
    Case("schema_default_revoke_restrict_and_cascade_preserve_other_schema", """
        ALTER DEFAULT PRIVILEGES REVOKE ALL ON ROUTINES FROM PUBLIC;
        ALTER DEFAULT PRIVILEGES IN SCHEMA app, other GRANT EXECUTE ON ROUTINES TO PUBLIC;
        ALTER DEFAULT PRIVILEGES IN SCHEMA app REVOKE EXECUTE ON ROUTINES FROM PUBLIC RESTRICT;
        ALTER DEFAULT PRIVILEGES IN SCHEMA other REVOKE EXECUTE ON FUNCTIONS FROM PUBLIC CASCADE;
        CREATE PROCEDURE app.p()
        LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$ BEGIN NULL; END $$;
        CREATE FUNCTION other.f() RETURNS integer
        LANGUAGE sql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$ SELECT 1 $$;
    """),
    Case("unqualified_routine_still_has_known_global_public_grant", """
        ALTER DEFAULT PRIVILEGES IN SCHEMA app REVOKE EXECUTE ON ROUTINES FROM PUBLIC;
        CREATE PROCEDURE p() -- expect:public
        LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$ BEGIN NULL; END $$;
    """),
    Case("unqualified_routine_with_no_schema_grants_is_private", """
        ALTER DEFAULT PRIVILEGES REVOKE ALL ON ROUTINES FROM PUBLIC;
        ALTER DEFAULT PRIVILEGES IN SCHEMA app REVOKE EXECUTE ON ROUTINES FROM PUBLIC;
        CREATE PROCEDURE p()
        LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$ BEGIN NULL; END $$;
    """),
)

SCHEMA_DEFAULT_INCOMPLETE_CASES = (
    Case("unqualified_routine_cannot_choose_a_schema_default_grant", """
        ALTER DEFAULT PRIVILEGES REVOKE ALL ON ROUTINES FROM PUBLIC;
        ALTER DEFAULT PRIVILEGES IN SCHEMA app GRANT EXECUTE ON ROUTINES TO PUBLIC;
        CREATE PROCEDURE p()
        LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$ BEGIN NULL; END $$;
    """),
    Case("schema_default_external_role_remains_unknown", """
        ALTER DEFAULT PRIVILEGES FOR ROLE deployer IN SCHEMA app REVOKE EXECUTE ON ROUTINES FROM PUBLIC;
        CREATE PROCEDURE app.p() -- expect:path
        LANGUAGE plpgsql SECURITY DEFINER AS $$ BEGIN NULL; END $$;
    """),
    Case("schema_default_malformed_schema_list_cannot_hide_public", """
        ALTER DEFAULT PRIVILEGES IN SCHEMA app, REVOKE EXECUTE ON ROUTINES FROM PUBLIC;
        CREATE PROCEDURE app.p() -- expect:public
        LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$ BEGIN NULL; END $$;
    """),
    Case("schema_default_malformed_role_list_cannot_remove_prior_grant", """
        ALTER DEFAULT PRIVILEGES REVOKE EXECUTE ON ROUTINES FROM PUBLIC;
        ALTER DEFAULT PRIVILEGES IN SCHEMA app GRANT EXECUTE ON ROUTINES TO PUBLIC;
        ALTER DEFAULT PRIVILEGES IN SCHEMA app REVOKE EXECUTE ON ROUTINES FROM PUBLIC,;
        CREATE PROCEDURE app.p() -- expect:public
        LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$ BEGIN NULL; END $$;
    """),
    Case("schema_default_wrong_direction_cannot_hide_public", """
        ALTER DEFAULT PRIVILEGES IN SCHEMA app REVOKE EXECUTE ON ROUTINES TO PUBLIC;
        CREATE PROCEDURE app.p() -- expect:public
        LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$ BEGIN NULL; END $$;
    """),
    Case("schema_default_unsupported_procedures_keyword_is_partial", """
        ALTER DEFAULT PRIVILEGES IN SCHEMA app REVOKE EXECUTE ON PROCEDURES FROM PUBLIC;
        CREATE PROCEDURE app.p() -- expect:public
        LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$ BEGIN NULL; END $$;
    """),
)


class EvidenceTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.artifact = ROOT / "test-suite/artifacts/sql-acceptance" / (cls.__name__ + "-" + uuid.uuid4().hex[:12])
        cls.artifact.mkdir(parents=True)
        cls.identity = {
            "python": sys.version,
            "oracle_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
        }

    def setUp(self):
        self.started = time.monotonic()
        print(f"[{self.id()}] RUN evidence={self.artifact}", flush=True)

    def tearDown(self):
        print(f"[{self.id()}] END ({time.monotonic() - self.started:.3f}s)", flush=True)

    def materialize(self, cases, name):
        directory = self.artifact / name
        directory.mkdir()
        for case in cases:
            (directory / case.filename).write_text(case.source, encoding="utf-8")
        return directory


class SQLNativeTests(EvidenceTest):
    def test_unsupported_statement_diagnostics_name_their_line_once(self):
        analyzer = importlib.import_module("ubs_core.sql_scan")
        source = "SELECT 1;\nLOAD 'auto_explain';\nUSE app;\n42;\n"
        records, errors = analyzer.analyze_source(source, "diagnostics.sql")
        self.assertEqual(records, [], errors)
        self.assertEqual(errors, ["line 2: unsupported PostgreSQL statement 'load'",
                                  "line 3: non-PostgreSQL dialect syntax",
                                  "line 4: unsupported SQL or psql command"])

    def test_role_changes_do_not_reuse_another_owners_schema_defaults(self):
        analyzer = importlib.import_module("ubs_core.sql_scan")
        for index, change in enumerate(("SET ROLE next_owner", "RESET ROLE",
                                        "RESET SESSION AUTHORIZATION")):
            with self.subTest(change=change):
                case = Case("schema_default_role_change_" + str(index), f"""
                    ALTER DEFAULT PRIVILEGES IN SCHEMA app GRANT EXECUTE ON ROUTINES TO PUBLIC;
                    {change};
                    ALTER DEFAULT PRIVILEGES REVOKE EXECUTE ON ROUTINES FROM PUBLIC;
                    CREATE PROCEDURE app.p() LANGUAGE plpgsql SECURITY DEFINER
                    SET search_path = pg_catalog, pg_temp AS $$ BEGIN NULL; END $$;
                    ALTER DEFAULT PRIVILEGES IN SCHEMA app REVOKE EXECUTE ON ROUTINES FROM PUBLIC;
                    CREATE PROCEDURE app.private() LANGUAGE plpgsql SECURITY DEFINER
                    SET search_path = pg_catalog, pg_temp AS $$ BEGIN NULL; END $$;
                """)
                directory = self.materialize((case,), case.name)
                records, errors = analyzer.analyze_source(case.source, str(directory / case.filename))
                (directory / "receipt.json").write_text(json.dumps({
                    **self.identity, "findings": records, "errors": errors,
                    "analyzer_sha256": hashlib.sha256(Path(analyzer.__file__).read_bytes()).hexdigest(),
                }, indent=2) + "\n", encoding="utf-8")
                self.assertEqual(records, [], (case.source, records, errors))
                self.assertTrue(any("ACL of app.p() is unknown" in error for error in errors), errors)
                self.assertFalse(any("ACL of app.private() is unknown" in error for error in errors), errors)
                self.assertTrue(any("role change" in error for error in errors), errors)

    def test_same_line_redefinitions_keep_distinct_publication_evidence(self):
        # Both definitions can be observed by another session in autocommit
        # mode, even though the same spelling and line number are reused.
        declaration = ("CREATE FUNCTION app.f() RETURNS integer LANGUAGE sql "
                       "SECURITY DEFINER SET search_path = pg_catalog, pg_temp "
                       "AS $$ SELECT 1 $$;")
        prefix = declaration + " DROP FUNCTION app.f(); "
        case = Case("same_line_redefinitions", prefix + declaration)
        directory = self.materialize((case,), case.name)
        source = directory / case.filename
        analyzer = importlib.import_module("ubs_core.sql_scan")
        records, errors = analyzer.analyze_source(case.source, str(source))
        actual = sorted((row["rule"], row["line"], row["col"]) for row in records)
        expected = [(RULES["public"], 1, 1),
                    (RULES["public"], 1, len(prefix) + 1)]
        (directory / "receipt.json").write_text(json.dumps({
            **self.identity, "case": case.name, "expected": expected,
            "actual": actual, "findings": records, "errors": errors,
            "source_sha256": hashlib.sha256(source.read_bytes()).hexdigest(),
            "analyzer_sha256": hashlib.sha256(Path(analyzer.__file__).read_bytes()).hexdigest(),
            "elapsed_s": time.monotonic() - self.started,
        }, indent=2) + "\n", encoding="utf-8")
        self.assertEqual(errors, [], (records, errors))
        self.assertEqual(actual, expected, records)

    def check_native(self, case, incomplete=False):
        analyzer = importlib.import_module("ubs_core.sql_scan")
        directory = self.materialize((case,), case.name)
        source = directory / case.filename
        records, errors = analyzer.analyze_source(case.source, str(source))
        actual = sorted((row["rule"], row["line"], row["col"]) for row in records)
        receipt = {
            **self.identity, "case": case.name, "expected": case.expected,
            "actual": actual, "findings": records, "errors": errors,
            "source_sha256": hashlib.sha256(source.read_bytes()).hexdigest(),
            "analyzer_sha256": hashlib.sha256(Path(analyzer.__file__).read_bytes()).hexdigest(),
            "elapsed_s": time.monotonic() - self.started,
        }
        (directory / "receipt.json").write_text(json.dumps(receipt, indent=2) + "\n", encoding="utf-8")
        context = (case.source, records, errors)
        if incomplete:
            self.assertTrue(errors, context)
            if case.expected:
                self.assertEqual(actual, case.expected, context)
        else:
            self.assertEqual(errors, [], context)
            self.assertEqual(actual, case.expected, context)
        for record in records:
            self.assertEqual(record["severity"], "warning", record)
            self.assertIn(record["rule"], RULES.values(), record)
            self.assertEqual(record["path"], str(source), record)
            self.assertTrue(record["message"], record)
            self.assertGreater(record["line"], 0, record)
            self.assertGreater(record["col"], 0, record)


def native_test(case, incomplete=False):
    def run(self):
        self.check_native(case, incomplete)
    return run


for _case in CASES:
    setattr(SQLNativeTests, "test_" + _case.name, native_test(_case))
for _case in INCOMPLETE_CASES:
    setattr(SQLNativeTests, "test_incomplete_" + _case.name, native_test(_case, True))
for _case in PROCEDURE_CASES:
    setattr(SQLNativeTests, "test_" + _case.name, native_test(_case))
for _case in PROCEDURE_INCOMPLETE_CASES:
    setattr(SQLNativeTests, "test_incomplete_" + _case.name, native_test(_case, True))
for _case in SCHEMA_DEFAULT_CASES:
    setattr(SQLNativeTests, "test_" + _case.name, native_test(_case))
for _case in SCHEMA_DEFAULT_INCOMPLETE_CASES:
    setattr(SQLNativeTests, "test_incomplete_" + _case.name, native_test(_case, True))


class SQLHelperTests(EvidenceTest):
    def test_selected_migrations_through_helper_reports(self):
        """Exercise the actual helper/report boundary with retained scratch."""
        supported = {case.name: case for case in CASES}
        unsupported = {case.name: case for case in INCOMPLETE_CASES}
        mixed = (supported["reported_owner_role_migration"],
                 supported["owner_transfer_does_not_revoke_public"],
                 unsupported["do_grant_function_privileges_requires_modeling"])
        client_partial = (supported["cte_does_not_hide_later_function_exposure"],
                          unsupported["psql_include_does_not_swallow_next_function"],
                          supported["psql_directives_preserve_function_transaction"])
        for name, cases, partial in (("complete", CASES, False), ("partial", mixed, True),
                                     ("client-partial", client_partial, True)):
            with self.subTest(name=name):
                directory = self.materialize(cases, name)
                files = directory / "selected.nul"
                files.write_bytes(b"".join(os.fsencode(directory / case.filename) + b"\0" for case in cases))
                command = [sys.executable, "-B", "-m", "ubs_core.sql_scan",
                           "--files-from", str(files), "--project-dir", str(directory),
                           "--sink", str(directory / "findings.jsonl"),
                           "--json-out", str(directory / "report.json"),
                           "--sarif-out", str(directory / "report.sarif"),
                           "--text-out", str(directory / "report.txt"),
                           "--completion-out", str(directory / "complete.json"),
                           "--ci", "--fail-on-warning"]
                env = dict(os.environ, PYTHONPATH=str(ROOT / "modules/helpers"),
                           PYTHONDONTWRITEBYTECODE="1", UBS_KEEP_TEMP="1", UBS_NO_CACHE="1",
                           UBS_CACHE_DIR=str(directory / "cache"))
                result = subprocess.run(command, env=env, cwd=directory, capture_output=True,
                                        text=True, timeout=60, check=False)
                (directory / "stdout.log").write_text(result.stdout, encoding="utf-8")
                (directory / "stderr.log").write_text(result.stderr, encoding="utf-8")
                analyzer = ROOT / "modules/helpers/ubs_core/sql_scan.py"
                (directory / "receipt.json").write_text(json.dumps({
                    **self.identity, "command": command, "exit": result.returncode,
                    "analyzer_sha256": hashlib.sha256(analyzer.read_bytes()).hexdigest(),
                    "source_sha256": {case.filename: hashlib.sha256(case.source.encode()).hexdigest()
                                      for case in cases},
                }, indent=2) + "\n", encoding="utf-8")
                expected = sorted((case.filename, rule, line, col)
                                  for case in cases for rule, line, col in case.expected)
                context = (command, result.returncode, result.stdout, result.stderr)
                code = 2 if partial else int(bool(expected))
                self.assertEqual(result.returncode, code, context)
                report = json.loads((directory / "report.json").read_text(encoding="utf-8"))
                receipt = json.loads((directory / "complete.json").read_text(encoding="utf-8"))
                self.assertEqual(receipt, {"language": "sql", "status": report["status"], "exit_code": code})
                self.assertEqual(report["status"], "partial" if partial else "ok", context)
                self.assertEqual((report["files"], report["critical"], report["warning"], report["info"]),
                                 (len(cases), 0, len(expected), 0), context)
                actual = sorted((Path(row["path"]).name, row["rule"], row["line"], row["col"])
                                for row in report["findings"])
                self.assertEqual(actual, expected, context)
                sarif = json.loads((directory / "report.sarif").read_text(encoding="utf-8"))
                actual = []
                for run in sarif["runs"]:
                    self.assertEqual(run["invocations"][0]["executionSuccessful"], not partial)
                    for row in run["results"]:
                        location = row["locations"][0]["physicalLocation"]
                        actual.append((Path(location["artifactLocation"]["uri"]).name, row["ruleId"],
                                       location["region"]["startLine"], location["region"]["startColumn"]))
                self.assertEqual(sorted(actual), expected, context)


@unittest.skipUnless(os.environ.get("UBS_SQL_E2E") == "1",
                     "set UBS_SQL_E2E=1 for real SQL module/meta-runner acceptance")
class SQLPublicTests(EvidenceTest):
    def execute(self, target, mode="json", extra=(), cached=False, config=False):
        attempt = self.artifact / ("command-" + uuid.uuid4().hex[:8])
        attempt.mkdir()
        env = dict(os.environ, UBS_NO_AUTO_UPDATE="1", UBS_ENABLE_AUTO_UPDATE="0",
                   ENABLE_UV_TOOLS="0", PYTHONDONTWRITEBYTECODE="1", NO_COLOR="1", UBS_KEEP_TEMP="1",
                   UBS_NO_CACHE="0" if cached else "1", UBS_CACHE_DIR=str(self.artifact / "cache"),
                   TMPDIR=str(attempt), XDG_CACHE_HOME=str(self.artifact / "xdg-cache"),
                   XDG_CONFIG_HOME=str(self.artifact / "xdg-config"),
                   XDG_DATA_HOME=str(self.artifact / "xdg-data"),
                   XDG_STATE_HOME=str(self.artifact / "xdg-state"))
        if mode.startswith("module-"):
            command = ["bash", str(ROOT / "modules/ubs-sql.sh"), "--ci", "--fail-on-warning",
                       "--format=" + mode.split("-", 1)[1], *extra, str(target)]
        else:
            command = ["bash", str(ROOT / "ubs"), "--ci", *([] if config else ["--no-config"]), "--fail-on-warning",
                       "--format=" + mode, *extra, str(target)]
        started = time.monotonic()
        result = subprocess.run(command, cwd=target if target.is_dir() else target.parent,
                                env=env, text=True, capture_output=True, timeout=60, check=False)
        (attempt / "stdout.log").write_text(result.stdout, encoding="utf-8")
        (attempt / "stderr.log").write_text(result.stderr, encoding="utf-8")
        (attempt / "receipt.json").write_text(json.dumps({
            **self.identity, "command": command, "exit": result.returncode,
            "elapsed_s": time.monotonic() - started,
            "runner_sha256": hashlib.sha256((ROOT / "ubs").read_bytes()).hexdigest(),
        }, indent=2) + "\n", encoding="utf-8")
        print(f"[sql-cli:{attempt.name}] exit={result.returncode} {time.monotonic() - started:.3f}s", flush=True)
        try:
            report = ([json.loads(line) for line in result.stdout.split("\n") if line]
                      if mode == "jsonl" else json.loads(result.stdout))
        except json.JSONDecodeError:
            self.fail((command, result.returncode, result.stdout, result.stderr))
        return result, report

    def git(self, directory, *arguments):
        result = subprocess.run(
            ["git", "-c", "core.hooksPath=" + str(self.artifact / "unused-hooks"),
             "-c", "user.name=UBS SQL acceptance", "-c", "user.email=ubs-sql@example.invalid",
             "-c", "commit.gpgsign=false", *arguments],
            cwd=directory, text=True, capture_output=True, timeout=30, check=False,
        )
        self.assertEqual(result.returncode, 0, (result.args, result.stdout, result.stderr))
        return result.stdout

    def assert_report(self, result, report, mode, cases, *, partial=False, expected_override=None):
        expected = sorted(expected_override) if expected_override is not None else sorted(
            (case.filename, rule, line, col) for case in cases for rule, line, col in case.expected)
        context = (result.returncode, result.stdout, result.stderr)
        self.assertEqual(result.returncode, 2 if partial else int(bool(expected)), context)
        if mode.endswith("sarif"):
            rows = [row for run in report["runs"] for row in run.get("results", [])]
            actual = []
            for row in rows:
                location = row["locations"][0]["physicalLocation"]
                self.assertEqual(row["level"], "warning", context)
                actual.append((Path(location["artifactLocation"]["uri"]).name, row["ruleId"],
                               location["region"]["startLine"], location["region"]["startColumn"]))
            if partial:
                self.assertTrue(any(not item["executionSuccessful"] for run in report["runs"]
                                    for item in run.get("invocations", [])), context)
        else:
            totals = report if mode.startswith("module-") else report["totals"]
            self.assertEqual((totals["critical"], totals["warning"], totals["info"], totals["files"]),
                             (0, len(expected), 0, len(cases)), context)
            self.assertEqual(report["status"], "partial" if partial else "ok", context)
            actual = []
            for row in report.get("findings", []):
                rule = row.get("rule", row.get("rule_id"))
                self.assertEqual(row["severity"], "warning", context)
                actual.append((Path(row.get("path", row.get("file"))).name, rule, row["line"], row["col"]))
        self.assertEqual(sorted(actual), expected, context)

    def test_native_oracle_through_module_and_runner_formats(self):
        directory = self.materialize(CASES, "oracle")
        for mode in ("module-json", "module-sarif", "json", "sarif"):
            with self.subTest(mode=mode):
                self.assert_report(*self.execute(directory, mode), mode, CASES)

    def test_partial_file_keeps_neighbor_findings(self):
        cases = (CASES[0], CASES[2], INCOMPLETE_CASES[0])
        directory = self.materialize(cases, "partial")
        for mode in ("module-json", "sarif"):
            with self.subTest(mode=mode):
                self.assert_report(*self.execute(directory, mode), mode, cases, partial=True)

    def test_procedure_oracle_through_module_and_runner_formats(self):
        directory = self.materialize(PROCEDURE_CASES, "procedures")
        for mode in ("module-json", "module-sarif", "json", "sarif"):
            with self.subTest(mode=mode):
                self.assert_report(*self.execute(directory, mode), mode, PROCEDURE_CASES)

    def test_procedure_boundaries_keep_known_findings(self):
        cases = PROCEDURE_INCOMPLETE_CASES
        directory = self.materialize(cases, "procedure-boundaries")
        for mode in ("module-json", "module-sarif", "json", "sarif"):
            with self.subTest(mode=mode):
                self.assert_report(*self.execute(directory, mode), mode, cases, partial=True)

    def test_schema_default_privileges_through_module_and_runner_formats(self):
        directory = self.materialize(SCHEMA_DEFAULT_CASES, "schema-defaults")
        for mode in ("module-json", "module-sarif", "json", "sarif"):
            with self.subTest(mode=mode):
                self.assert_report(*self.execute(directory, mode), mode, SCHEMA_DEFAULT_CASES)

    def test_schema_default_boundaries_preserve_public_findings(self):
        cases = SCHEMA_DEFAULT_INCOMPLETE_CASES
        directory = self.materialize(cases, "schema-default-boundaries")
        for mode in ("module-json", "module-sarif", "json", "sarif"):
            with self.subTest(mode=mode):
                self.assert_report(*self.execute(directory, mode), mode, cases, partial=True)

    def test_identity_boundaries_preserve_selected_function_findings(self):
        supported = {case.name: case for case in CASES}
        unsupported = {case.name: case for case in INCOMPLETE_CASES}
        cases = (supported["rename_then_revoke_uses_new_function_identity"],
                 unsupported["rename_cannot_overwrite_another_function"],
                 unsupported["old_schema_no_longer_resolves_after_transfer"])
        directory = self.materialize(cases, "identity-partial")
        for mode in ("module-json", "module-sarif", "json", "sarif"):
            with self.subTest(mode=mode):
                self.assert_report(*self.execute(directory, mode), mode, cases, partial=True)

    def test_cte_and_psql_boundaries_keep_known_findings(self):
        supported = {case.name: case for case in CASES}
        unsupported = {case.name: case for case in INCOMPLETE_CASES}
        cases = (supported["cte_does_not_hide_later_function_exposure"],
                 unsupported["psql_include_does_not_swallow_next_function"],
                 supported["psql_directives_preserve_function_transaction"])
        directory = self.materialize(cases, "client-partial")
        for mode in ("module-json", "module-sarif", "json", "sarif"):
            with self.subTest(mode=mode):
                self.assert_report(*self.execute(directory, mode), mode, cases, partial=True)

    def test_selection_and_vendor_ignores(self):
        unsafe, clean = CASES[0], CASES[2]
        directory = self.materialize((unsafe, clean), "selection")
        vendor = directory / "vendor"
        vendor.mkdir()
        (vendor / "ignored.sql").write_text(unsafe.source, encoding="utf-8")
        self.assert_report(*self.execute(directory), "json", (unsafe, clean))
        self.assert_report(*self.execute(directory / clean.filename), "json", (clean,))
        selected = self.artifact / "selected-paths.nul"
        selected.write_bytes(os.fsencode(directory / clean.filename) + b"\0")
        self.assert_report(*self.execute(directory, "module-json", ("--files-from=" + str(selected),)),
                           "module-json", (clean,))

    def test_source_cache_cannot_hide_added_exposure(self):
        clean = CASES[2]
        directory = self.materialize((clean,), "cache")
        target = directory / clean.filename
        for _ in range(2):
            self.assert_report(*self.execute(target, cached=True), "json", (clean,))
        unsafe = Case(clean.name, CASES[0].code)
        target.write_text(unsafe.source, encoding="utf-8")
        self.assert_report(*self.execute(target, cached=True), "json", (unsafe,))

    def test_suppression_uses_migration_comments_not_body_literals(self):
        suppressed = Case("selected_rule_suppressed", """
            CREATE FUNCTION app.f() RETURNS integer -- expect:path
            -- ubs:ignore[sql.security.definer-public-execute]
            LANGUAGE sql SECURITY DEFINER AS $$ SELECT 1 $$;
        """)
        decoy = Case("body_suppression_is_literal", """
            CREATE FUNCTION app.f() RETURNS text -- expect:path,public
            LANGUAGE sql SECURITY DEFINER AS $body$
            SELECT '-- ubs:ignore[sql.security.definer-search-path,sql.security.definer-public-execute]';
            $body$;
        """)
        cases = (suppressed, decoy)
        directory = self.materialize(cases, "suppression")
        for mode in ("module-json", "json"):
            with self.subTest(mode=mode):
                self.assert_report(*self.execute(directory, mode), mode, cases)

    def test_category_skip_and_default_warning_exit(self):
        case = CASES[0]
        directory = self.materialize((case,), "category")
        expected = [(case.filename, rule, line, col) for rule, line, col in case.expected
                    if rule == RULES["public"]]
        self.assert_report(*self.execute(directory, extra=("--skip-sql=1",)),
                           "json", (case,), expected_override=expected)

    def test_staged_sql_uses_index_bytes_and_preserves_worktree(self):
        clean = Case("migration with space", CASES[2].code)
        staged = Case(clean.name, CASES[0].code)
        directory = self.materialize((clean,), "staged")
        source = directory / clean.filename
        self.git(directory, "init", "-q", "-b", "main")
        self.git(directory, "add", "--", source.name)
        self.git(directory, "commit", "-qm", "SQL fixture baseline")
        source.write_text(staged.source, encoding="utf-8")
        self.git(directory, "add", "--", source.name)
        source.write_text(clean.source, encoding="utf-8")
        (directory / "untracked.sql").write_text(staged.source, encoding="utf-8")
        index = self.git(directory, "ls-files", "--stage", "-z")
        self.assert_report(*self.execute(source), "json", (clean,))
        occurrences = self.artifact / "staged-occurrences.jsonl"
        result, report = self.execute(directory, extra=("--staged", "--all-occurrences",
                                                       "--also=jsonl:" + str(occurrences)))
        self.assert_report(result, report, "json", (staged,))
        rows = [json.loads(line) for line in occurrences.read_text(encoding="utf-8").split("\n") if line]
        findings = [row for row in rows if row["type"] == "finding"]
        self.assertEqual(len(findings), len(staged.expected), rows)
        self.assertEqual({row["file"] for row in findings}, {str(source)}, rows)
        for row in findings:
            self.assertIs(row["code_available"], True, row)
            self.assertEqual(row["code"], staged.source.split("\n")[row["line"] - 1], row)
        self.assertIs(rows[-1]["occurrence_export"]["complete"], True, rows[-1])
        self.assertEqual(source.read_text(encoding="utf-8"), clean.source)
        self.assertEqual(self.git(directory, "ls-files", "--stage", "-z"), index)
        self.assertEqual(self.git(directory, "show", ":" + source.name), staged.source)

    def test_baseline_new_only_retains_only_new_sql_findings(self):
        old = CASES[0]
        directory = self.materialize((old,), "baseline")
        baseline = self.artifact / "sql-baseline.json"
        self.assert_report(*self.execute(directory, extra=("--save-baseline=" + str(baseline),)),
                           "json", (old,))
        document = json.loads(baseline.read_text(encoding="utf-8"))
        self.assertEqual(len(document["findings"]), len(old.expected), document)
        flags = ("--baseline=" + str(baseline), "--new-only")
        self.assert_report(*self.execute(directory, extra=flags), "json", (old,), expected_override=[])
        new = Case("newly_added", """
            CREATE FUNCTION app.new_function() RETURNS integer -- expect:path,public
            LANGUAGE sql SECURITY DEFINER AS $$ SELECT 2 $$;
        """)
        (directory / new.filename).write_text(new.source, encoding="utf-8")
        expected = [(new.filename, rule, line, col) for rule, line, col in new.expected]
        self.assert_report(*self.execute(directory, extra=flags), "json", (old, new), expected_override=expected)

    def test_jsonl_occurrences_and_report_sidecars_share_sql_ledger(self):
        case = CASES[0]
        directory = self.materialize((case,), "jsonl")
        summary, beads = self.artifact / "sql-summary.json", self.artifact / "sql-beads.jsonl"
        result, rows = self.execute(directory, mode="jsonl", extra=("--all-occurrences",
                                   "--report-json=" + str(summary), "--beads-jsonl=" + str(beads)))
        context = (result.returncode, result.stdout, result.stderr)
        self.assertEqual(result.returncode, 1, context)
        self.assertEqual(rows, [json.loads(line) for line in beads.read_text(encoding="utf-8").split("\n") if line])
        findings = [row for row in rows if row["type"] == "finding"]
        self.assertEqual(sorted((row["rule_id"], row["line"], row["col"]) for row in findings), case.expected)
        self.assertEqual(len({row["occurrence_id"] for row in findings}), len(case.expected))
        for row in findings:
            self.assertEqual((row["language"], row["severity"], row["count"]), ("sql", "warning", 1), row)
            self.assertEqual(row["file"], str(directory / case.filename), row)
            self.assertEqual(row["code"], case.source.split("\n")[row["line"] - 1], row)
            self.assertIs(row["code_available"], True, row)
            self.assertRegex(row["occurrence_id"], r"^sha256:[0-9a-f]{64}$")
        self.assertEqual(rows[-1]["type"], "totals", rows[-1])
        coverage = rows[-1]["occurrence_export"]
        self.assertIs(coverage["complete"], True, coverage)
        self.assertEqual((coverage["reported"], coverage["emitted"], coverage["omitted"]), (2, 2, 0))
        report = json.loads(summary.read_text(encoding="utf-8"))
        self.assert_report(result, report, "json", (case,))
        (directory / "unknown_context.sql").write_text("\\i external-privileges.sql\n", encoding="utf-8")
        partial, rows = self.execute(directory, mode="jsonl", extra=("--all-occurrences", "--profile=strict"))
        self.assertEqual(partial.returncode, 2, (partial.stdout, partial.stderr))
        self.assertEqual(rows[-1]["status"], "partial", rows[-1])
        self.assertIs(rows[-1]["occurrence_export"]["complete"], False, rows[-1])
        self.assertIs(rows[-1]["occurrence_export"]["analysis_complete"], False, rows[-1])
        self.assertEqual(sorted((row["rule_id"], row["line"], row["col"]) for row in rows
                                if row["type"] == "finding"), case.expected)

    def test_project_config_selects_sql_and_cli_overrides_category_skip(self):
        case = CASES[0]
        directory = self.materialize((case,), "configured")
        self.git(directory, "init", "--template=")
        (directory / "ignored.sql").write_text(case.source, encoding="utf-8")
        (directory / "other.py").write_text("answer = 42\n", encoding="utf-8")
        (directory / ".ubs.json").write_text(json.dumps({
            "version": 1, "only": ["sql"], "exclude": ["ignored.sql"],
            "profile": "strict", "skip_by_lang": {"sql": [1]},
        }) + "\n", encoding="utf-8")
        expected_public = [(case.filename, rule, line, col) for rule, line, col in case.expected
                           if rule == RULES["public"]]
        self.assert_report(*self.execute(directory, config=True), "json", (case,), expected_override=expected_public)
        expected_path = [(case.filename, rule, line, col) for rule, line, col in case.expected
                         if rule == RULES["path"]]
        self.assert_report(*self.execute(directory, config=True, extra=("--skip-sql=2",)),
                           "json", (case,), expected_override=expected_path)
        self.assert_report(*self.execute(directory, extra=("--only=sql", "--exclude=ignored.sql", "--skip-sql=1")),
                           "json", (case,), expected_override=expected_public)


if __name__ == "__main__":
    unittest.main()
