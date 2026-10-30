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
                column = len(source) - len(source.lstrip()) + 1
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
    Case("schema_default_revoke_does_not_override_global_grant", """
        ALTER DEFAULT PRIVILEGES IN SCHEMA app REVOKE EXECUTE ON FUNCTIONS FROM PUBLIC;
        CREATE FUNCTION app.f() RETURNS integer LANGUAGE sql SECURITY DEFINER
        SET search_path = pg_catalog, pg_temp AS $$ SELECT 1 $$;
    """),
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


@unittest.skipUnless(os.environ.get("UBS_SQL_E2E") == "1",
                     "set UBS_SQL_E2E=1 for real SQL module/meta-runner acceptance")
class SQLPublicTests(EvidenceTest):
    def execute(self, target, mode="json", extra=(), cached=False, config=False):
        attempt = self.artifact / ("command-" + uuid.uuid4().hex[:8])
        attempt.mkdir()
        env = dict(os.environ, UBS_NO_AUTO_UPDATE="1", UBS_ENABLE_AUTO_UPDATE="0",
                   ENABLE_UV_TOOLS="0", PYTHONDONTWRITEBYTECODE="1", NO_COLOR="1",
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
