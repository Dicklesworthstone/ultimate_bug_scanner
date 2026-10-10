"""Independent selected PHP request/security oracle for mj1j.31/.32.

The labels and sink locations were authored before examining the PHP engine.
They describe PHP/API behavior, not a second implementation of its analysis.
Pure Python execution does not certify PHP compilation or framework execution.
The public probes invoke the real module and meta-runner on retained files.
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
from unittest.mock import patch
import uuid

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "modules/helpers"))
RULES = {
    "sql": "php.security.sql-injection",
    "command": "php.security.command-injection",
    "code": "php.security.dynamic-code",
    "include": "php.security.dynamic-include",
    "deserialize": "php.security.unsafe-deserialization",
    "xss": "php.security.xss",
}
CATEGORIES = {
    RULES["sql"]: "php.sql",
    RULES["command"]: "php.execution",
    RULES["code"]: "php.execution",
    RULES["include"]: "php.includes",
    RULES["deserialize"]: "php.deserialization",
    RULES["xss"]: "php.output",
}


@dataclass(frozen=True)
class Case:
    name: str
    code: str
    template: bool = False
    template_expected: tuple = ()

    @property
    def source(self):
        result = textwrap.dedent(self.code).strip("\n") + "\n"
        return result if self.template or result.startswith("<?php") else "<?php\n" + result

    @property
    def filename(self):
        return self.name + (".phtml" if self.template else ".php")

    @property
    def expected(self):
        rows = []
        for number, line in enumerate(self.source.splitlines(), 1):
            if "// expect:" in line:
                key, target = line.split("// expect:", 1)[1].strip().split(" ", 1)
                rows.append((RULES[key], number, line.index(target) + 1))
        for key, number, target in self.template_expected:
            rows.append((RULES[key], number, self.source.splitlines()[number - 1].index(target) + 1))
        return sorted(rows)


# Fixed behavior set: a finding is at execution/output, not preparation or input.
CASES = (
    Case("pdo_raw_query", """
        $db = new PDO('sqlite::memory:');
        $db->query("SELECT '" . $_GET['name'] . "'"); // expect: sql $db->query
    """),
    Case("pdo_alias_and_interpolation", r"""
        $db = new \PDO('sqlite::memory:');
        $connection = $db;
        $name = $_POST['name'];
        $sql = "SELECT '$name'";
        $connection->exec($sql); // expect: sql $connection->exec
    """),
    Case("pdo_bound_values", """
        $db = new PDO('sqlite::memory:');
        $stmt = $db->prepare('SELECT ?');
        $stmt->execute([$_GET['value']]);
    """),
    Case("pdo_tainted_prepared_execution", """
        $db = new PDO('sqlite::memory:');
        $stmt = $db->prepare("SELECT '" . $_GET['value'] . "'");
        $stmt->execute(); // expect: sql $stmt->execute
    """),
    Case("pdo_binding_does_not_repair_query", """
        $db = new PDO('sqlite::memory:');
        $stmt = $db->prepare("SELECT ? FROM " . $_GET['table']);
        $stmt->bindValue(1, $_GET['name']);
        $stmt->execute(); // expect: sql $stmt->execute
    """),
    Case("pdo_prepared_snapshot_after_literal_rebind", """
        $db = new PDO('sqlite::memory:');
        $sql = "SELECT '" . $_GET['name'] . "'";
        $stmt = $db->prepare($sql);
        $sql = 'SELECT 1';
        $stmt->execute(); // expect: sql $stmt->execute
    """),
    Case("pdo_safe_prepared_snapshot_after_tainted_rebind", """
        $db = new PDO('sqlite::memory:');
        $sql = 'SELECT ?';
        $stmt = $db->prepare($sql);
        $sql = $_GET['sql'];
        $stmt->execute([$_GET['value']]);
    """),
    Case("pdo_preparation_without_execution", """
        $db = new PDO('sqlite::memory:');
        $stmt = $db->prepare($_GET['sql']);
    """),
    Case("pdo_helper_query_return", """
        function queryText($name) {
            return "SELECT '" . $name . "'";
        }
        $db = new PDO('sqlite::memory:');
        $db->query(queryText($_GET['name'])); // expect: sql $db->query
    """),
    Case("pdo_helper_executes_typed_receiver", r"""
        function runQuery(\PDO $database, $text) {
            $database->query($text); // expect: sql $database->query
        }
        $db = new PDO('sqlite::memory:');
        runQuery($db, "SELECT '" . $_GET['name'] . "'");
    """),
    Case("pdo_helper_returns_statement_identity", """
        function prepareQuery($database, $query) {
            return $database->prepare($query);
        }
        $db = new PDO('sqlite::memory:');
        $stmt = prepareQuery($db, $_GET['sql']);
        $stmt->execute(); // expect: sql $stmt->execute
    """),
    Case("pdo_helper_preserves_separate_safe_statement", """
        function prepareQuery($database, $query) {
            return $database->prepare($query);
        }
        $db = new PDO('sqlite::memory:');
        $unsafe = prepareQuery($db, $_GET['sql']);
        $safe = prepareQuery($db, 'SELECT ?');
        $safe->execute([$_GET['value']]);
    """),
    Case("pdo_namespaced_import", r"""
        namespace Application;
        use PDO as Database;
        $db = new Database('sqlite::memory:');
        $db->query($_GET['sql']); // expect: sql $db->query
    """),
    Case("pdo_local_class_shadow", """
        namespace Application;
        class PDO {
            function query($text) { return 1; }
        }
        $db = new PDO();
        $db->query($_GET['sql']);
    """),
    Case("unrelated_query_method", """
        class Search {
            function query($text) { return 1; }
        }
        $search = new Search();
        $search->query($_GET['term']);
    """),
    Case("mysqli_procedural_query", """
        $db = mysqli_connect('localhost', 'app', 'password', 'app');
        mysqli_query($db, $_GET['sql']); // expect: sql mysqli_query
    """),
    Case("mysqli_object_query", """
        $db = new mysqli('localhost', 'app', 'password', 'app');
        $alias = $db;
        $alias->multi_query($_GET['sql']); // expect: sql $alias->multi_query
    """),
    Case("mysqli_bound_statement", """
        $db = new mysqli('localhost', 'app', 'password', 'app');
        $stmt = $db->prepare('SELECT ?');
        $value = $_POST['value'];
        $stmt->bind_param('s', $value);
        $stmt->execute();
    """),
    Case("mysqli_statement_constructor", """
        $db = new mysqli('localhost', 'app', 'password', 'app');
        $stmt = new mysqli_stmt($db, $_GET['sql']);
        $stmt->execute(); // expect: sql $stmt->execute
    """),
    Case("mysqli_statement_constructor_bound_clean", """
        $db = new mysqli('localhost', 'app', 'password', 'app');
        $stmt = new mysqli_stmt($db, 'SELECT ?');
        $value = $_GET['value'];
        $stmt->bind_param('s', $value);
        $stmt->execute();
    """),
    Case("unknown_branch_preserves_request", """
        $db = new PDO('sqlite::memory:');
        $sql = 'SELECT 1';
        if ($_GET['mode']) {
            $sql = $_GET['sql'];
        }
        $db->query($sql); // expect: sql $db->query
    """),
    Case("constant_branch_excludes_unreachable_request", """
        $db = new PDO('sqlite::memory:');
        $sql = 'SELECT 1';
        if (false) {
            $sql = $_GET['sql'];
        }
        $db->query($sql);
    """),
    Case("literal_rebind_kills_query_taint", """
        $db = new PDO('sqlite::memory:');
        $sql = $_GET['sql'];
        $sql = 'SELECT 1';
        $db->query($sql);
    """),
    Case("integer_cast_sql_text", """
        $db = new PDO('sqlite::memory:');
        $id = (int) $_GET['id'];
        $db->query('SELECT * FROM accounts WHERE id = ' . $id);
    """),
    Case("numeric_character_filter_is_not_numeric_conversion", """
        $db = new PDO('sqlite::memory:');
        $id = filter_var($_GET['id'], FILTER_SANITIZE_NUMBER_INT);
        $db->query('SELECT ' . $id . ' FROM accounts'); // expect: sql $db->query
    """),
    Case("shell_command_concatenation", """
        $command = 'printf %s ' . $_GET['name'];
        system($command); // expect: command system
    """),
    Case("shell_single_escaped_argument", """
        system('printf %s ' . escapeshellarg($_GET['name']));
    """),
    Case("proc_open_shell_string", """
        proc_open('printf %s ' . $_GET['name'], [], $pipes); // expect: command proc_open
    """),
    Case("proc_open_argument_array", """
        proc_open(['/bin/printf', '%s', $_GET['name']], [], $pipes);
    """),
    Case("proc_open_dynamic_executable", """
        proc_open([$_GET['program'], 'fixed'], [], $pipes); // expect: command proc_open
    """),
    Case("proc_open_shell_interpreter_code", """
        proc_open(['/bin/sh', '-c', $_GET['code']], [], $pipes); // expect: command proc_open
    """),
    Case("proc_open_shell_positional_data", r"""
        proc_open(['/bin/sh', '-c', 'printf "%s" "$1"', 'shell', $_GET['name']], [], $pipes);
    """),
    Case("namespaced_system_shadow", """
        namespace Application;
        function system($value) { return 0; }
        system($_GET['name']);
    """),
    Case("imported_real_system", r"""
        namespace Application;
        use function system as runCommand;
        runCommand($_GET['command']); // expect: command runCommand
    """),
    Case("request_dynamic_code", """
        eval($_POST['code']); // expect: code eval
    """),
    Case("static_dynamic_code", """
        eval('$answer = 42;');
    """),
    Case("request_include", """
        require __DIR__ . '/' . $_GET['template']; // expect: include require
    """),
    Case("trusted_static_include", """
        require __DIR__ . '/known-template.php';
    """),
    Case("request_deserialization", """
        unserialize($_COOKIE['state']); // expect: deserialize unserialize
    """),
    Case("deserialization_class_filter_is_not_input_trust", """
        unserialize($_COOKIE['state'], ['allowed_classes' => false]); // expect: deserialize unserialize
    """),
    Case("trusted_static_deserialization", """
        unserialize('a:1:{s:4:"name";s:5:"fixed";}');
    """),
    Case("namespaced_unserialize_shadow", """
        namespace Application;
        function unserialize($value) { return []; }
        unserialize($_COOKIE['state']);
    """),
    Case("raw_echo", """
        echo $_GET['name']; // expect: xss echo
    """),
    Case("raw_print", """
        print $_POST['name']; // expect: xss print
    """),
    Case("print_r_default_outputs", """
        print_r($_GET['name']); // expect: xss print_r
    """),
    Case("print_r_return_only", """
        $saved = print_r($_GET['name'], true);
    """),
    Case("print_r_return_later_output", """
        $saved = print_r($_GET['name'], true);
        echo $saved; // expect: xss echo
    """),
    Case("escaped_html_text", """
        echo htmlspecialchars($_GET['name'], ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
    """),
    Case("noquotes_safe_for_html_text", """
        echo htmlspecialchars($_GET['name'], ENT_NOQUOTES, 'UTF-8');
    """),
    Case("helper_returns_escaped_text", """
        function safeText($value) {
            return htmlspecialchars($value, ENT_QUOTES, 'UTF-8');
        }
        echo safeText($_GET['name']);
    """),
    Case("escaping_function_shadow_returns_raw", """
        namespace Application;
        function htmlspecialchars($value) { return $value; }
        echo htmlspecialchars($_GET['name']); // expect: xss echo
    """),
    Case("entity_decode_invalidates_escaping", """
        $escaped = htmlspecialchars($_GET['name'], ENT_QUOTES, 'UTF-8');
        echo html_entity_decode($escaped); // expect: xss echo
    """),
    Case("json_decode_invalidates_text_escaping", """
        $escaped = htmlspecialchars($_GET['encoded'], ENT_NOQUOTES, 'UTF-8');
        echo json_decode($escaped); // expect: xss echo
    """),
    Case("template_raw_html", "<p><?= $_GET['name'] ?></p>", True, (("xss", 1, "<?="),)),
    Case("template_escaped_attribute", """<input value="<?= htmlspecialchars($_GET['name'], ENT_QUOTES, 'UTF-8') ?>">""", True),
    Case("template_compat_double_attribute", """<input value="<?= htmlspecialchars($_GET['name'], ENT_COMPAT, 'UTF-8') ?>">""", True),
    Case("template_compat_single_attribute", """<input value='<?= htmlspecialchars($_GET['name'], ENT_COMPAT, 'UTF-8') ?>'>""",
         True, (("xss", 1, "<?="),)),
    Case("template_noquotes_double_attribute", """<input value="<?= htmlspecialchars($_GET['name'], ENT_NOQUOTES, 'UTF-8') ?>">""",
         True, (("xss", 1, "<?="),)),
    Case("template_unquoted_attribute", """<input value=<?= htmlspecialchars($_GET['name'], ENT_QUOTES, 'UTF-8') ?>>""",
         True, (("xss", 1, "<?="),)),
    Case("template_url_requires_scheme_proof", """<a href="<?= htmlspecialchars($_GET['url'], ENT_QUOTES, 'UTF-8') ?>">link</a>""",
         True, (("xss", 1, "<?="),)),
    Case("template_encoded_query_component", """<a href="/search?q=<?= rawurlencode($_GET['query']) ?>">search</a>""", True),
    Case("template_script_context", """<script>let value = <?= htmlspecialchars($_GET['value'], ENT_QUOTES, 'UTF-8') ?>;</script>""",
         True, (("xss", 1, "<?="),)),
    Case("imported_noquotes_constant_does_not_quote", r"""
        <?php
        namespace Application;
        use const ENT_NOQUOTES as AttributeFlags;
        ?>
        <input value="<?= htmlspecialchars($_GET['name'], AttributeFlags, 'UTF-8') ?>">
    """, True, (("xss", 5, "<?="),)),
    Case("imported_quotes_constant_quotes", r"""
        <?php
        namespace Application;
        use const ENT_QUOTES as AttributeFlags;
        ?>
        <input value="<?= htmlspecialchars($_GET['name'], AttributeFlags, 'UTF-8') ?>">
    """, True),
    Case("request_array_untouched_key", """
        $data = $_GET;
        $data['unrelated'] = 'fixed';
        echo $data['name']; // expect: xss echo
    """),
    Case("request_array_overwritten_key", """
        $data = $_GET;
        $data['name'] = 'fixed';
        echo $data['name'];
    """),
    Case("array_copy_preserves_original", """
        $original = $_GET;
        $copy = $original;
        $copy['name'] = 'fixed';
        echo $original['name']; // expect: xss echo
    """),
    Case("array_decimal_string_key_coercion", """
        $values = ['12' => $_GET['name']];
        echo $values[12]; // expect: xss echo
    """),
    Case("array_decimal_string_key_overwrite", """
        $values = ['12' => $_GET['name']];
        $values[12] = 'fixed';
        echo $values['12'];
    """),
    Case("array_literal_safe_neighbor", """
        $values = ['raw' => $_GET['name'], 'safe' => 'fixed'];
        echo $values['safe'];
    """),
    Case("bitwise_string_preserves_input", """
        $value = $_GET['name'] | ' ';
        echo $value; // expect: xss echo
    """),
    Case("string_increment_preserves_input", """
        $value = $_GET['name'];
        $value++;
        echo $value; // expect: xss echo
    """),
    Case("laravel_typed_request", r"""
        use Illuminate\Http\Request;
        function handle(Request $request) {
            echo $request->input('name'); // expect: xss echo
        }
    """),
    Case("symfony_typed_query_bag", r"""
        function handle(\Symfony\Component\HttpFoundation\Request $request) {
            echo $request->query->get('name'); // expect: xss echo
        }
    """),
    Case("lexical_decoys", r"""
        // echo $_GET['name'];
        /* system($_GET['command']); */
        $literal = 'eval($_POST["code"]);';
        $other = "unserialize literal text";
    """),
    Case("parameter_name_alone_is_not_request", """
        function output($request) {
            echo $request;
        }
        output('fixed');
    """),
)

# The selected subset must refuse these operations explicitly. The first sink
# remains independently knowable even when a later construct cannot be modeled.
PARTIAL = (
    Case("tainted_call_on_unresolved_entry_receiver", """
        function run($database) {
            $database->query($_GET['sql']);
        }
    """),
    Case("unknown_request_transform", """
        $value = externalTransform($_GET['name']);
        echo $value;
    """),
    Case("external_reference_effect", """
        $value = 'fixed';
        externalMutate($value);
        echo $value;
    """),
    Case("external_global_effect", """
        $value = 'fixed';
        externalMutate();
        echo $value;
    """),
    Case("request_array_union", """
        $values = $_GET + ['name' => 'fixed'];
        echo $values['name'];
    """),
    Case("variable_function_dispatch", """
        $function = $_GET['function'];
        $function($_GET['value']);
    """),
    Case("known_finding_before_unsupported", """
        echo $_GET['name']; // expect: xss echo
        externalTransform($_GET['name']);
    """),
    Case("malformed_php", """
        $value = $_GET['name'];
        if (
    """),
)

# Independent review witnesses preserve the original oracle. Encoding facts
# belong to the exact resulting value; subsequent transformations can remove
# quoting or reintroduce syntax. The two JSON cases distinguish a complete JS
# expression from insertion inside an existing JS string.
REVIEW_CASES = (
    Case("review_html_replacement_reintroduces_tags", """
        $escaped = htmlspecialchars($_GET['name'], ENT_QUOTES, 'UTF-8');
        echo str_replace(['&lt;', '&gt;'], ['<', '>'], $escaped); // expect: xss echo
    """),
    Case("review_pdo_quote_slice_removes_delimiters", """
        $db = new PDO('sqlite::memory:');
        $quoted = $db->quote($_GET['id']);
        $raw = substr($quoted, 1, -1);
        $db->query('SELECT * FROM accounts WHERE id = ' . $raw); // expect: sql $db->query
    """),
    Case("review_pdo_url_decode_reintroduces_quote", """
        $db = new PDO('sqlite::memory:');
        $quoted = $db->quote($_GET['name']);
        $db->query('SELECT * FROM accounts WHERE name = ' . rawurldecode($quoted)); // expect: sql $db->query
    """),
    Case("review_mysqli_decode_removes_escape", """
        $db = new mysqli('localhost', 'app', 'password', 'app');
        $escaped = $db->real_escape_string($_GET['name']);
        $db->query("SELECT * FROM accounts WHERE name = '" . stripslashes($escaped) . "'"); // expect: sql $db->query
    """),
    Case("review_shell_quote_slice_removes_delimiters", """
        $argument = escapeshellarg($_GET['name']);
        $raw = substr($argument, 1, -1);
        system('printf %s ' . $raw); // expect: command system
    """),
    Case("review_filter_explicit_unknown_flags", """
        <?php $flags = (int) $_GET['flags']; ?>
        <input value="<?= filter_var($_GET['name'], FILTER_SANITIZE_FULL_SPECIAL_CHARS, $flags) ?>">
    """, True, (("xss", 2, "<?="),)),
    Case("review_filter_omitted_flags_quote_attribute", """
        <input value="<?= filter_var($_GET['name'], FILTER_SANITIZE_FULL_SPECIAL_CHARS) ?>">
    """, True),
    Case("review_even_backslash_interpolates", r"""
        $value = $_GET['name'];
        echo "\\$value"; // expect: xss echo
    """),
    Case("review_odd_backslash_escapes_variable", r"""
        $value = $_GET['name'];
        echo "\\\$value";
    """),
    Case("review_builtin_constant_name_is_shadowable", r"""
        <?php
        namespace Application;
        use const ENT_NOQUOTES as ENT_QUOTES;
        ?>
        <input value="<?= htmlspecialchars($_GET['name'], ENT_QUOTES, 'UTF-8') ?>">
    """, True, (("xss", 5, "<?="),)),
    Case("review_json_encoding_inside_existing_js_quotes", """
        <script>let value = "<?= json_encode($_GET['value'], JSON_HEX_TAG | JSON_HEX_AMP | JSON_HEX_APOS | JSON_HEX_QUOT) ?>";</script>
    """, True, (("xss", 1, "<?="),)),
    Case("review_json_encoding_is_complete_js_expression", """
        <script>let value = <?= json_encode($_GET['value'], JSON_HEX_TAG | JSON_HEX_AMP | JSON_HEX_APOS | JSON_HEX_QUOT) ?>;</script>
    """, True),
    Case("review_pcntl_exec_interpreter_code", """
        pcntl_exec('/bin/sh', ['-c', $_GET['code']]); // expect: command pcntl_exec
    """),
    Case("review_pcntl_exec_argument_data", """
        pcntl_exec('/usr/bin/printf', ['%s', $_GET['name']]);
    """),
)
CASES = (*CASES, *REVIEW_CASES)


def identities():
    paths = [
        Path(__file__),
        ROOT / "modules/helpers/ubs_core/php_frontend.py",
        ROOT / "modules/helpers/ubs_core/analyzers/taint_php.py",
        ROOT / "modules/helpers/ubs_core/php_scan.py",
        ROOT / "modules/ubs-php.sh",
        ROOT / "ubs",
    ]
    return {
        "python": sys.version,
        "files_sha256": {str(path.relative_to(ROOT)): hashlib.sha256(path.read_bytes()).hexdigest()
                         for path in paths if path.is_file()},
    }


class EvidenceTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.artifact = ROOT / "test-suite/artifacts/php-acceptance" / (cls.__name__ + "-" + uuid.uuid4().hex[:12])
        cls.artifact.mkdir(parents=True)
        cls.identity = identities()
        (cls.artifact / "identity.json").write_text(json.dumps(cls.identity, indent=2), encoding="utf-8")

    def setUp(self):
        self.started = time.monotonic()
        print(f"[{self.id()}] RUN", flush=True)

    def tearDown(self):
        result = self._outcome.result
        failed = any(test is self or getattr(test, "test_case", None) is self
                     for test, _ in result.failures + result.errors)
        status = "FAIL" if failed else "PASS"
        print(f"[{self.id()}] {status} ({time.monotonic() - self.started:.3f}s)", flush=True)

    def materialize(self, cases, label):
        directory = self.artifact / (label + "-" + uuid.uuid4().hex[:8])
        directory.mkdir()
        for case in cases:
            (directory / case.filename).write_text(case.source, encoding="utf-8")
        return directory


class PHPNativeTests(EvidenceTest):
    def check_native(self, case, incomplete=False):
        native = importlib.import_module("ubs_core.analyzers.taint_php")
        directory = self.materialize((case,), case.name)
        source = directory / case.filename
        findings = []
        error = None
        try:
            for finding in native.scan_file_findings(source):
                findings.append(finding)
        except ValueError as caught:
            error = str(caught)
        actual = sorted((row["rule"], row["line"], row["col"]) for row in findings)
        (directory / "receipt.json").write_text(json.dumps({
            **self.identity, "case": case.name, "expected": case.expected,
            "actual": actual, "findings": findings, "incomplete": error,
            "source_sha256": hashlib.sha256(source.read_bytes()).hexdigest(),
            "elapsed": time.monotonic() - self.started,
        }, indent=2), encoding="utf-8")
        if incomplete:
            self.assertIsNotNone(error, (case.source, findings))
            self.assertRegex(error.lower(), "incomplete|unsupported|limit|budget|syntax|parse")
        else:
            self.assertIsNone(error, (case.source, error, findings))
        self.assertEqual(actual, case.expected, (case.source, findings, error))
        for row in findings:
            self.assertEqual(row["severity"], "critical", row)
            self.assertEqual(row["category_id"], CATEGORIES[row["rule"]], row)

    def test_analysis_budget_is_not_a_clean_scan(self):
        native = importlib.import_module("ubs_core.analyzers.taint_php")
        source = self.materialize((CASES[0],), "budget") / CASES[0].filename
        for name in ("UBS_PHP_MAX_TOKENS", "UBS_PHP_MAX_STEPS"):
            with self.subTest(budget=name), patch.dict(os.environ, {name: "2"}):
                with self.assertRaisesRegex(ValueError, "(?i)incomplete|budget|limit"):
                    list(native.scan_file_findings(source))


def native_test(case, incomplete=False):
    def run(self):
        self.check_native(case, incomplete)
    return run


for _case in CASES:
    setattr(PHPNativeTests, "test_" + _case.name, native_test(_case))
for _case in PARTIAL:
    setattr(PHPNativeTests, "test_partial_" + _case.name, native_test(_case, True))


@unittest.skipUnless(os.environ.get("UBS_PHP_E2E") == "1",
                     "set UBS_PHP_E2E=1 for real PHP module/meta-runner acceptance")
class PHPPublicTests(EvidenceTest):
    def execute(self, target, mode="json", extra=(), cached=False, config=False, environment=None,
                parse_json=True):
        attempt = self.artifact / ("command-" + uuid.uuid4().hex[:8])
        attempt.mkdir()
        env = dict(os.environ, UBS_NO_AUTO_UPDATE="1", UBS_ENABLE_AUTO_UPDATE="0",
                   ENABLE_UV_TOOLS="0", PYTHONDONTWRITEBYTECODE="1", NO_COLOR="1",
                   UBS_NO_CACHE="0" if cached else "1",
                   UBS_CACHE_DIR=str(self.artifact / "cache"), TMPDIR=str(attempt))
        if environment:
            env.update(environment)
        if mode.startswith("module-"):
            command = [str(ROOT / "modules/ubs-php.sh"), "--ci", "--no-color",
                       "--format=" + mode.split("-", 1)[1], *extra, str(target)]
        else:
            command = [str(ROOT / "ubs"), "--ci", *([] if config else ["--no-config"]),
                       "--format=" + mode, *extra, str(target)]
        started = time.monotonic()
        result = subprocess.run(command, cwd=target if target.is_dir() else target.parent,
                                env=env, text=True, capture_output=True, timeout=120)
        (attempt / "stdout.json").write_text(result.stdout, encoding="utf-8")
        (attempt / "stderr.log").write_text(result.stderr, encoding="utf-8")
        (attempt / "receipt.json").write_text(json.dumps({
            **self.identity, "command": command, "exit": result.returncode,
            "environment": {key: env[key] for key in
                            ("UBS_NO_AUTO_UPDATE", "UBS_NO_CACHE", "UBS_CACHE_DIR", "TMPDIR")},
            "elapsed": time.monotonic() - started,
        }, indent=2), encoding="utf-8")
        print(f"[php-cli:{attempt.name}] exit={result.returncode} {time.monotonic() - started:.3f}s "
              + " ".join(command), flush=True)
        if not parse_json:
            return result, None
        self.assertTrue(result.stdout.strip(), (result.returncode, result.stdout, result.stderr))
        try:
            report = json.loads(result.stdout)
        except json.JSONDecodeError:
            self.fail((result.returncode, result.stdout, result.stderr))
        return result, report

    def assert_report(self, result, report, mode, cases, partial=False, expected_override=None):
        expected = sorted(expected_override) if expected_override is not None else sorted(
            (case.filename, rule, line, col) for case in cases for rule, line, col in case.expected)
        context = (result.returncode, result.stdout, result.stderr)
        self.assertEqual(result.returncode, 2 if partial else int(bool(expected)), context)
        if mode.endswith("sarif"):
            rows = [row for run in report["runs"] for row in run.get("results", [])]
            actual = []
            for row in rows:
                location = row["locations"][0]["physicalLocation"]
                self.assertEqual(row["level"], "error", context)
                actual.append((Path(location["artifactLocation"]["uri"]).name, row["ruleId"],
                               location["region"]["startLine"], location["region"]["startColumn"]))
            if partial:
                self.assertTrue(any(not item["executionSuccessful"] for run in report["runs"]
                                    for item in run.get("invocations", [])), context)
        else:
            totals = report if mode.startswith("module-") else report["totals"]
            self.assertEqual((totals["critical"], totals["warning"], totals["info"], totals["files"]),
                             (len(expected), 0, 0, len(cases)), context)
            self.assertEqual(report["status"], "partial" if partial else "ok", context)
            actual = []
            rows = report.get("findings", [])
            for row in rows:
                rule = row.get("rule", row.get("rule_id"))
                self.assertEqual((row["severity"], row["category_id"]),
                                 ("critical", CATEGORIES[rule]), context)
                actual.append((Path(row.get("path", row.get("file"))).name, rule, row["line"], row["col"]))
        self.assertEqual(sorted(actual), expected, context)

    def test_public_native_oracle_in_all_formats(self):
        directory = self.materialize(CASES, "oracle")
        for mode in ("module-json", "module-sarif", "json", "sarif"):
            with self.subTest(mode=mode):
                self.assert_report(*self.execute(directory, mode), mode, CASES)

    def test_public_partial_keeps_known_findings_and_neighbor(self):
        cases = (CASES[0], CASES[2], PARTIAL[-2])
        directory = self.materialize(cases, "partial")
        for mode in ("module-json", "sarif"):
            with self.subTest(mode=mode):
                self.assert_report(*self.execute(directory, mode), mode, cases, partial=True)

    def test_public_file_list_selection_and_default_ignores(self):
        unsafe, clean = CASES[0], CASES[2]
        directory = self.materialize((unsafe, clean), "selection")
        vendor = directory / "vendor"
        vendor.mkdir()
        (vendor / unsafe.filename).write_text(unsafe.source, encoding="utf-8")
        scripts = directory / "bin"
        scripts.mkdir()
        entry = Case("entry", unsafe.code)
        (scripts / entry.filename).write_text(entry.source, encoding="utf-8")
        self.assert_report(*self.execute(directory), "json", (unsafe, clean, entry))
        self.assert_report(*self.execute(directory / unsafe.filename), "json", (unsafe,))
        selected = self.artifact / "selected-paths.nul"
        selected.write_bytes(os.fsencode(directory / clean.filename) + b"\0")
        self.assert_report(*self.execute(directory, "module-json", ("--files-from=" + str(selected),)),
                           "module-json", (clean,))

    def test_public_ignore_and_category_profile(self):
        unsafe, clean = CASES[0], CASES[2]
        directory = self.materialize((unsafe, clean), "policy")
        (directory / ".ubsignore").write_text(unsafe.filename + "\n", encoding="utf-8")
        self.assert_report(*self.execute(directory), "json", (clean,))
        target = self.materialize((unsafe,), "category")
        self.assert_report(*self.execute(target, extra=("--skip-php=1",)), "json", (unsafe,), expected_override=[])
        self.assert_report(*self.execute(target, extra=("--profile=loose", "--skip=11")), "json", (unsafe,))

    def test_public_cache_source_and_suppression_invalidation(self):
        case = next(item for item in CASES if item.name == "raw_echo")
        directory = self.materialize((case,), "cache")
        target = directory / case.filename
        self.assert_report(*self.execute(directory, cached=True), "json", (case,))
        self.assert_report(*self.execute(directory, cached=True), "json", (case,))
        suppressed = Case(case.name, "<?php\necho $_GET['name']; // ubs:ignore[" + RULES["xss"] + "]\n")
        target.write_text(suppressed.source, encoding="utf-8")
        self.assert_report(*self.execute(directory, cached=True), "json", (suppressed,))
        clean = Case(case.name, "echo 'fixed';")
        target.write_text(clean.source, encoding="utf-8")
        self.assert_report(*self.execute(directory, cached=True), "json", (clean,))
        target.write_text(case.source, encoding="utf-8")
        self.assert_report(*self.execute(directory, cached=True), "json", (case,))

    def test_public_budget_failure_is_explicit(self):
        directory = self.materialize((CASES[0],), "budget")
        result, report = self.execute(directory, environment={"UBS_PHP_MAX_TOKENS": "2"})
        context = (result.returncode, result.stdout, result.stderr)
        self.assertEqual(result.returncode, 2, context)
        self.assertNotEqual(report["status"], "ok", context)
        self.assertEqual(report["totals"]["critical"], 0, context)

    def test_public_repository_fixture_totals(self):
        expected_buggy = [
            ("sample.php", RULES["sql"], 3, 1),
            ("sample.php", RULES["command"], 4, 1),
            ("sample.php", RULES["code"], 5, 1),
            ("sample.php", RULES["include"], 6, 1),
            ("sample.php", RULES["deserialize"], 7, 1),
            ("sample.php", RULES["xss"], 8, 1),
            ("request_output.phtml", RULES["xss"], 1, 4),
            ("request_output.phtml", RULES["xss"], 2, 10),
            ("request_output.phtml", RULES["xss"], 3, 15),
        ]
        for label, expected in (("buggy", expected_buggy), ("clean", [])):
            directory = self.artifact / ("fixture-" + label)
            directory.mkdir()
            originals = ROOT / "test-suite/php" / label
            for path in originals.iterdir():
                if path.suffix in {".php", ".phtml"}:
                    (directory / path.name).write_bytes(path.read_bytes())
            for mode in ("module-json", "sarif"):
                with self.subTest(fixture=label, mode=mode):
                    # The fixture identities are checked directly, without
                    # rewriting expectations from any scanner output.
                    self.assert_report(*self.execute(directory, mode), mode,
                                       (None, None), expected_override=expected)

    def test_public_project_config_and_explicit_override(self):
        case = CASES[0]
        directory = self.materialize((case,), "configuration")
        # Automatic policy discovery reads the nearest Git worktree root,
        # not an arbitrary nested source directory (robot-docs config).
        command = ["git", "init", "--quiet", "--initial-branch=main", str(directory)]
        initialized = subprocess.run(command, cwd=self.artifact, text=True, capture_output=True,
                                     env={key: value for key, value in os.environ.items()
                                          if not key.startswith("GIT_")}, timeout=30)
        (directory / "git-init.json").write_text(json.dumps({
            "command": command, "exit": initialized.returncode,
            "stdout": initialized.stdout, "stderr": initialized.stderr,
        }, indent=2), encoding="utf-8")
        self.assertEqual(initialized.returncode, 0, (initialized.stdout, initialized.stderr))
        config = directory / ".ubs.json"
        config.write_text(json.dumps({"version": 1, "only": ["php"], "skip_by_lang": {"php": [1]}}),
                          encoding="utf-8")
        self.assert_report(*self.execute(directory, cached=True, config=True), "json", (case,),
                           expected_override=[])
        self.assert_report(*self.execute(directory, extra=("--skip-php=",), cached=True, config=True),
                           "json", (case,))
        config.write_text(json.dumps({"version": 1, "only": ["php"]}), encoding="utf-8")
        self.assert_report(*self.execute(directory, cached=True, config=True), "json", (case,))

    def test_public_custom_rule_failure_preserves_native_findings(self):
        case = CASES[0]
        directory = self.materialize((case,), "custom-failure")
        rules = self.artifact / "invalid-custom-rules"
        rules.mkdir()
        (rules / "invalid.yml").write_text("id: php.invalid\nlanguage: php\nrule: [\n", encoding="utf-8")
        result, report = self.execute(directory, "module-json", ("--rules=" + str(rules),))
        self.assert_report(result, report, "module-json", (case,), partial=True)
        self.assertTrue(report.get("errors"), (result.stdout, result.stderr))

    def test_public_text_and_required_flag_errors(self):
        directory = self.materialize((CASES[0],), "module-contract")
        result, _ = self.execute(directory, "module-text", parse_json=False)
        self.assertEqual(result.returncode, 1, (result.stdout, result.stderr))
        self.assertIn(RULES["sql"], result.stdout)
        result, _ = self.execute(directory, "module-json", ("--only=99",), parse_json=False)
        self.assertEqual(result.returncode, 2, (result.stdout, result.stderr))
        self.assertTrue(result.stderr.strip(), result.stdout)
        blocked = self.artifact / "report-parent-is-a-file"
        blocked.write_text("The report path cannot create a child here.\n", encoding="utf-8")
        result, _ = self.execute(directory, "module-json", ("--json-out=" + str(blocked / "report.json"),),
                                 parse_json=False)
        self.assertEqual(result.returncode, 2, (result.stdout, result.stderr))
        self.assertTrue(result.stderr.strip(), result.stdout)


if __name__ == "__main__":
    unittest.main()
