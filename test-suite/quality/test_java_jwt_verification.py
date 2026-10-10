#!/usr/bin/env python3
"""Independent Auth0 JWT verification oracle, including real library execution.

Auth0's NoneAlgorithm verifies an empty signature. JWTVerifier also checks the
algorithm header and configured claims; issuer/audience checks do not restore a
signature. These cases report actual verification with the selected algorithm,
not constructing it, signing a token, or merely decoding one.

Primary contracts: auth0/java-jwt tag 4.6.1, algorithms/NoneAlgorithm.java,
JWTVerifier.java and interfaces/Verification.java. The optional compiler proof
requires the exact released dependencies below, never substitute API stubs.
"""
from __future__ import annotations

from dataclasses import dataclass, replace
import hashlib
import io
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import textwrap
import time
import unittest
import uuid

import test_java_tls_verifier as tls

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "modules/helpers"))
from ubs_core import java_scan

RULE = "java.security.jwt-signature-bypass"
DETECTOR = ROOT / "modules/helpers/ubs_core/java_detectors/jwt_verification.py"
DEPENDENCIES = {
    "java-jwt-4.6.1.jar": "1fea79118317f6aee30f6c8c962e2b05e9e66f30c6f157a4102b567de43b3401",
    "jackson-core-2.22.2.jar": "ff167a6317be15895706c26668f45b898efe40ab8780970658210fe1393d52a6",
    "jackson-databind-2.22.2.jar": "d0da14c12b16b5d54719aa172d83b542ff4abeb8b0fb7db476fde8ceece760ca",
    "jackson-annotations-2.22.jar": "21ddb598807d3a51a876704eb979d9296e1c6a6f47ab1826ff88c6d6a127a2d0",
    "jakarta.servlet-api-6.1.0.jar": "8a31f465f3593bf2351531a5c952014eb839da96a605b5825b93dd54714c48c4",
}


@dataclass(frozen=True)
class Case:
    name: str
    body: str
    receiver: str | None = None
    members: str = ""
    imports: str = ""
    instance: bool = False
    incomplete: bool = False
    accepts: bool = False

    @property
    def source(self):
        return ("import com.auth0.jwt.JWT;\n"
                "import com.auth0.jwt.algorithms.Algorithm;\n"
                "import com.auth0.jwt.interfaces.JWTVerifier;\n"
                "import com.auth0.jwt.interfaces.Verification;\n"
                "import com.auth0.jwt.interfaces.DecodedJWT;\n"
                "import jakarta.servlet.http.HttpServletRequest;\n" + self.imports
                + f"class Case_{self.name} {{\n"
                + ("" if self.instance else "static ")
                + "Object accept(HttpServletRequest request, byte[] material) {\n"
                + textwrap.dedent(self.body).strip() + "\n}\n"
                + textwrap.dedent(self.members).strip() + "\n}\n")

    @property
    def sites(self):
        return [(line, text.index(self.receiver) + 1)
                for line, text in enumerate(self.source.splitlines(), 1)
                if self.receiver is not None and "// JWT_VERIFY" in text]


def unsafe(name, body, receiver="JWT", **kwargs):
    return Case(name, body, receiver=receiver, accepts=True, **kwargs)


CASES = (
    unsafe("inline_header", '''
        return JWT.require(Algorithm.none()).build().verify(request.getHeader("X-JWT")); // JWT_VERIFY
    '''),
    unsafe("request_alias", '''
        String incoming = request.getParameter("jwt");
        String encoded = incoming;
        return JWT.require(Algorithm.none()).build().verify(encoded); // JWT_VERIFY
    '''),
    unsafe("configured_claims", '''
        return JWT.require(Algorithm.none()).withIssuer("issuer").withAudience("audience") // JWT_VERIFY
            .withSubject("admin").build().verify(request.getHeader("X-JWT"));
    '''),
    unsafe("algorithm_alias", '''
        Algorithm algorithm = Algorithm.none();
        Algorithm alias = algorithm;
        return JWT.require(alias).build().verify(request.getHeader("X-JWT")); // JWT_VERIFY
    '''),
    unsafe("builder_alias", '''
        Verification builder = JWT.require(Algorithm.none());
        Verification alias = builder;
        return alias.withIssuer("issuer").build().verify(request.getHeader("X-JWT")); // JWT_VERIFY
    ''', receiver="alias"),
    unsafe("verifier_alias", '''
        JWTVerifier verifier = JWT.require(Algorithm.none()).build();
        JWTVerifier alias = verifier;
        return alias.verify(request.getHeader("X-JWT")); // JWT_VERIFY
    ''', receiver="alias"),
    unsafe("concrete_verifier", '''
        com.auth0.jwt.JWTVerifier verifier =
            (com.auth0.jwt.JWTVerifier) JWT.require(Algorithm.none()).build();
        return verifier.verify(request.getHeader("X-JWT")); // JWT_VERIFY
    ''', receiver="verifier"),
    unsafe("captured_algorithm", '''
        Algorithm algorithm = Algorithm.none();
        Verification builder = JWT.require(algorithm);
        algorithm = Algorithm.HMAC256(material);
        return builder.build().verify(request.getHeader("X-JWT")); // JWT_VERIFY
    ''', receiver="builder"),
    unsafe("captured_verifier", '''
        JWTVerifier verifier = JWT.require(Algorithm.none()).build();
        JWTVerifier captured = verifier;
        verifier = JWT.require(Algorithm.HMAC256(material)).build();
        return captured.verify(request.getHeader("X-JWT")); // JWT_VERIFY
    ''', receiver="captured"),
    unsafe("decoded_overload", '''
        DecodedJWT decoded = JWT.decode(request.getHeader("X-JWT"));
        JWTVerifier verifier = JWT.require(Algorithm.none()).build();
        return verifier.verify(decoded); // JWT_VERIFY
    ''', receiver="verifier"),
    unsafe("algorithm_verify", '''
        Algorithm algorithm = Algorithm.none();
        algorithm.verify(JWT.decode(request.getHeader("X-JWT"))); // JWT_VERIFY
        return Boolean.TRUE;
    ''', receiver="algorithm"),
    unsafe("static_imports", '''
        return require(none()).build().verify(request.getHeader("X-JWT")); // JWT_VERIFY
    ''', receiver="require", imports=(
        "import static com.auth0.jwt.JWT.require;\n"
        "import static com.auth0.jwt.algorithms.Algorithm.none;\n")),
    unsafe("qualified", '''
        return com.auth0.jwt.JWT.require(com.auth0.jwt.algorithms.Algorithm.none()) // JWT_VERIFY
            .build().verify(request.getHeader("X-JWT"));
    ''', receiver="com.auth0.jwt.JWT"),
    unsafe("static_final_fields", '''
        return verifier.verify(request.getHeader("X-JWT")); // JWT_VERIFY
    ''', receiver="verifier", members='''
        private static final Algorithm algorithm = Algorithm.none();
        private static final JWTVerifier verifier = JWT.require(algorithm).build();
    '''),
    unsafe("instance_final_fields", '''
        return verifier.verify(request.getHeader("X-JWT")); // JWT_VERIFY
    ''', receiver="verifier", instance=True, members='''
        private final Algorithm algorithm = Algorithm.none();
        private final JWTVerifier verifier = JWT.require(algorithm).build();
    '''),
    Case("hmac", '''
        return JWT.require(Algorithm.HMAC256(material)).build().verify(request.getHeader("X-JWT"));
    '''),
    Case("hmac_final_field", '''
        return verifier.verify(request.getHeader("X-JWT"));
    ''', instance=True, members='''
        private final Algorithm algorithm = Algorithm.HMAC256(new byte[32]);
        private final JWTVerifier verifier = JWT.require(algorithm).build();
    '''),
    Case("unused_algorithm", '''
        Algorithm unused = Algorithm.none();
        return Boolean.FALSE;
    '''),
    Case("unused_builder", '''
        Verification unused = JWT.require(Algorithm.none());
        return Boolean.FALSE;
    '''),
    Case("unused_verifier", '''
        JWTVerifier unused = JWT.require(Algorithm.none()).build();
        return Boolean.FALSE;
    '''),
    Case("signing_only", '''
        JWT.create().withSubject("admin").sign(Algorithm.none());
        return Boolean.FALSE;
    '''),
    Case("decode_only", '''
        JWT.decode(request.getHeader("X-JWT"));
        return Boolean.FALSE;
    '''),
    Case("algorithm_rebound", '''
        Algorithm algorithm = Algorithm.none();
        algorithm = Algorithm.HMAC256(material);
        return JWT.require(algorithm).build().verify(request.getHeader("X-JWT"));
    '''),
    Case("builder_rebound", '''
        Verification builder = JWT.require(Algorithm.none());
        builder = JWT.require(Algorithm.HMAC256(material));
        return builder.build().verify(request.getHeader("X-JWT"));
    '''),
    Case("verifier_rebound", '''
        JWTVerifier verifier = JWT.require(Algorithm.none()).build();
        verifier = JWT.require(Algorithm.HMAC256(material)).build();
        return verifier.verify(request.getHeader("X-JWT"));
    '''),
    Case("fake_jwt", '''
        return JWT.require(Algorithm.none()).build().verify(request.getHeader("X-JWT"));
    ''', members='''
        static class JWT {
            static Verification require(Algorithm ignored) { throw new SecurityException("local factory"); }
        }
    '''),
    Case("fake_algorithm_class", '''
        return JWT.require(Algorithm.none()).build().verify(request.getHeader("X-JWT"));
    ''', members='''
        static class Algorithm {
            static com.auth0.jwt.algorithms.Algorithm none() {
                return com.auth0.jwt.algorithms.Algorithm.HMAC256(new byte[32]);
            }
        }
    '''),
    Case("fake_algorithm_variable", '''
        AlgoFactory Algorithm = new AlgoFactory();
        return JWT.require(Algorithm.none()).build().verify(request.getHeader("X-JWT"));
    ''', members='''
        static class AlgoFactory {
            com.auth0.jwt.algorithms.Algorithm none() {
                return com.auth0.jwt.algorithms.Algorithm.HMAC256(new byte[32]);
            }
        }
    '''),
    Case("fake_verifier", '''
        JWTVerifier unused = JWT.require(Algorithm.none()).build();
        LocalVerifier verifier = new LocalVerifier();
        return verifier.verify(request.getHeader("X-JWT"));
    ''', members='''
        static class LocalVerifier { Boolean verify(String value) { return Boolean.FALSE; } }
    '''),
    Case("sibling_scope", '''
        JWTVerifier verifier = JWT.require(Algorithm.HMAC256(material)).build();
        return verifier.verify(request.getHeader("X-JWT"));
    ''', members='''
        static void unused() { JWTVerifier verifier = JWT.require(Algorithm.none()).build(); }
    '''),
    Case("computed_receiver", '''
        JWTVerifier verifier = JWT.require(Algorithm.none()).build();
        return holder().verifier.verify(request.getHeader("X-JWT"));
    ''', members='''
        static class LocalVerifier { Boolean verify(String value) { return Boolean.FALSE; } }
        static class Holder { LocalVerifier verifier = new LocalVerifier(); }
        static Holder holder() { return new Holder(); }
    '''),
    Case("static_import_shadow", '''
        return require(none()).build().verify(request.getHeader("X-JWT"));
    ''', imports=("import static com.auth0.jwt.JWT.require;\n"
                  "import static com.auth0.jwt.algorithms.Algorithm.none;\n"), members='''
        static Verification require(Algorithm ignored) { throw new SecurityException("local method"); }
    '''),
    Case("unknown_algorithm", '''
        return JWT.require(choose(material)).build().verify(request.getHeader("X-JWT"));
    ''', members='''
        static Algorithm choose(byte[] material) { return Algorithm.HMAC256(material); }
    '''),
    Case("lexical_decoys", '''
        String example = "JWT.require(Algorithm.none()).build().verify(incoming)";
        // JWT.require(Algorithm.none()).build().verify(request.getHeader("X-JWT"));
        /* Algorithm.none().verify(JWT.decode(incoming)); */
        return Boolean.FALSE;
    '''),
    unsafe("owner_qualified_unsafe", '''
        return Inner.run(request);
    ''', receiver="Case_owner_qualified_unsafe.verifier", members='''
        private static final JWTVerifier verifier = JWT.require(Algorithm.none()).build();
        static class Inner {
            private static final JWTVerifier verifier = JWT.require(Algorithm.HMAC256(new byte[32])).build();
            static Object run(HttpServletRequest request) {
                return Case_owner_qualified_unsafe.verifier.verify(request.getHeader("X-JWT")); // JWT_VERIFY
            }
        }
    '''),
    Case("owner_qualified_safe", '''
        return Inner.run(request);
    ''', members='''
        private static final JWTVerifier verifier = JWT.require(Algorithm.HMAC256(new byte[32])).build();
        static class Inner {
            private static final JWTVerifier verifier = JWT.require(Algorithm.none()).build();
            static Object run(HttpServletRequest request) {
                return Case_owner_qualified_safe.verifier.verify(request.getHeader("X-JWT"));
            }
        }
    '''),
    unsafe("this_field_shadow", '''
        JWTVerifier verifier = JWT.require(Algorithm.HMAC256(material)).build();
        return this.verifier.verify(request.getHeader("X-JWT")); // JWT_VERIFY
    ''', receiver="this.verifier", instance=True, members='''
        private final JWTVerifier verifier = JWT.require(Algorithm.none()).build();
    '''),
    Case("this_field_safe", '''
        JWTVerifier verifier = JWT.require(Algorithm.none()).build();
        return this.verifier.verify(request.getHeader("X-JWT"));
    ''', instance=True, members='''
        private final JWTVerifier verifier = JWT.require(Algorithm.HMAC256(new byte[32])).build();
    '''),
    Case("method_ref_applied", '''
        JWTVerifier verifier = JWT.require(Algorithm.none()).build();
        java.util.function.Function<String, DecodedJWT> callback = verifier::verify;
        return callback.apply(request.getHeader("X-JWT"));
    ''', incomplete=True, accepts=True),
    Case("method_ref_unused", '''
        JWTVerifier verifier = JWT.require(Algorithm.none()).build();
        java.util.function.Function<String, DecodedJWT> callback = verifier::verify;
        return Boolean.FALSE;
    '''),
    Case("method_ref_hmac", '''
        JWTVerifier verifier = JWT.require(Algorithm.HMAC256(material)).build();
        java.util.function.Function<String, DecodedJWT> callback = verifier::verify;
        return callback.apply(request.getHeader("X-JWT"));
    '''),
    unsafe("cast_type_shadow", '''
        Algorithm algorithm = Algorithm.none();
        int Algorithm = 0;
        return JWT.require((Algorithm) algorithm).build().verify(request.getHeader("X-JWT")); // JWT_VERIFY
    '''),
    Case("qualified_fake_root", '''
        Root com = new Root();
        return com.auth0.jwt.JWT.require(Algorithm.none()).build().verify(request.getHeader("X-JWT"));
    ''', members='''
        static class Root { Auth auth0 = new Auth(); }
        static class Auth { Package jwt = new Package(); }
        static class Package { Factory JWT = new Factory(); }
        static class Factory {
            Verification require(Algorithm ignored) {
                return com.auth0.jwt.JWT.require(Algorithm.HMAC256(new byte[32]));
            }
        }
    '''),
    unsafe("grouped_receiver", '''
        JWTVerifier verifier = JWT.require(Algorithm.none()).build();
        return ((verifier)).verify(request.getHeader("X-JWT")); // JWT_VERIFY
    ''', receiver="((verifier))"),
    unsafe("static_import_sibling_method", '''
        return require(none()).build().verify(request.getHeader("X-JWT")); // JWT_VERIFY
    ''', receiver="require", imports=(
        "import static com.auth0.jwt.JWT.require;\n"
        "import static com.auth0.jwt.algorithms.Algorithm.none;\n"
    ), members='''
        static class Sibling {
            static Verification require(Algorithm ignored) {
                return JWT.require(Algorithm.HMAC256(new byte[32]));
            }
        }
    '''),
    Case("mutable_field_transfer", '''
        shared = JWT.require(Algorithm.none()).build();
        return Boolean.FALSE;
    ''', members="static JWTVerifier shared;", incomplete=True),
    Case("unknown_helper_transfer", '''
        JWTVerifier verifier = JWT.require(Algorithm.none()).build();
        consume(verifier);
        return Boolean.FALSE;
    ''', members="static void consume(JWTVerifier selected) {}", incomplete=True),
    Case("callback_transfer", '''
        java.util.function.Supplier<JWTVerifier> supplier = () -> JWT.require(Algorithm.none()).build();
        return supplier.get().verify(request.getHeader("X-JWT"));
    ''', incomplete=True, accepts=True),
)
COMPLETE_CASES = tuple(case for case in CASES if not case.incomplete)


def artifact(name):
    path = ROOT / "test-suite/artifacts/java-jwt-verification" / (name + "-" + uuid.uuid4().hex[:12])
    path.mkdir(parents=True)
    return path


class JavaJwtDirectTests(unittest.TestCase):
    def test_independent_consumed_verification_cases(self):
        target = artifact("direct")
        observations = []
        for case in CASES:
            with self.subTest(case=case.name):
                source = target / ("Case_" + case.name + ".java")
                source.write_text(case.source, encoding="utf-8")
                sink, errors = io.StringIO(), []
                started = time.monotonic()
                java_scan.run_detectors([source], sink, set(range(1, 20)) - {4}, errors=errors)
                rows = [json.loads(row) for row in sink.getvalue().splitlines()]
                actual = [(row["rule"], row["line"], row["col"], row["severity"], row["category_id"])
                          for row in rows if row["rule"] == RULE]
                expected = [(RULE, line, col, "critical", "java.security") for line, col in case.sites]
                observations.append({"case": case.name, "source_sha256": hashlib.sha256(source.read_bytes()).hexdigest(),
                                     "actual": actual, "expected": expected, "errors": errors,
                                     "elapsed": time.monotonic() - started})
                (target / (case.name + ".stdout.log")).write_text(sink.getvalue(), encoding="utf-8")
                (target / (case.name + ".stderr.log")).write_text("\n".join(errors), encoding="utf-8")
                if case.incomplete:
                    self.assertTrue(errors, case.name)
                    self.assertTrue(any("JWT" in message for message in errors), errors)
                else:
                    self.assertEqual(errors, [], case.name)
                self.assertEqual(actual, expected, case.name)
        identities = {str(path.relative_to(ROOT)): hashlib.sha256(path.read_bytes()).hexdigest()
                      for path in (Path(__file__), DETECTOR, ROOT / "modules/helpers/ubs_core/java_scan.py") if path.is_file()}
        (target / "receipt.json").write_text(json.dumps({"command": sys.argv, "python": sys.version,
            "tools": identities, "cases": observations}, indent=2) + "\n", encoding="utf-8")
        print("[java-jwt-direct] " + str(target), flush=True)


@unittest.skipUnless(os.environ.get("UBS_JAVA_JWT_COMPILE") == "1",
                     "set UBS_JAVA_JWT_COMPILE=1 to require the pinned real Java dependencies")
class JavaJwtRuntimeTests(unittest.TestCase):
    def test_compiler_and_unsigned_token_execution(self):
        target = artifact("compiler-runtime")
        sources = target / "sources"
        sources.mkdir()
        classes = target / "classes"
        classes.mkdir()
        tools = Path(os.environ.get("UBS_JAVA_JWT_TOOL_DIR", str(ROOT / "test-suite/artifacts/java-jwt-tools")))
        dependencies = []
        for name, digest in DEPENDENCIES.items():
            jar = tools / name
            self.assertTrue(jar.is_file(), "Required real dependency missing: " + str(jar))
            self.assertEqual(hashlib.sha256(jar.read_bytes()).hexdigest(), digest, str(jar))
            dependencies.append(jar)
        java = shutil.which("java")
        self.assertIsNotNone(java, "The real JDK compiler and JVM are required")
        for case in CASES:
            (sources / ("Case_" + case.name + ".java")).write_text(case.source, encoding="utf-8")
        runner = '''
            import com.auth0.jwt.JWT;
            import com.auth0.jwt.algorithms.Algorithm;
            import com.auth0.jwt.exceptions.JWTVerificationException;
            import com.auth0.jwt.interfaces.DecodedJWT;
            import jakarta.servlet.http.HttpServletRequest;
            import java.lang.reflect.*;
            public class JwtRuntimeOracle {
                public static void main(String[] args) throws Exception {
                    byte[] material = new byte[32];
                    String unsigned = JWT.create().withIssuer("issuer").withAudience("audience")
                        .withSubject("admin").sign(Algorithm.none());
                    String signed = JWT.create().withSubject("legitimate").sign(Algorithm.HMAC256(material));
                    if (!"legitimate".equals(JWT.require(Algorithm.HMAC256(material)).build()
                        .verify(signed).getSubject())) throw new AssertionError("Secure control rejected a real signature");
                    try {
                        JWT.require(Algorithm.HMAC256(material)).build().verify(unsigned);
                        throw new AssertionError("Secure control accepted unsigned token");
                    } catch (JWTVerificationException expected) { }
                    HttpServletRequest request = (HttpServletRequest) Proxy.newProxyInstance(
                        JwtRuntimeOracle.class.getClassLoader(), new Class<?>[] {HttpServletRequest.class},
                        (proxy, method, values) -> {
                            if (method.getName().equals("getHeader") || method.getName().equals("getParameter"))
                                return unsigned;
                            throw new UnsupportedOperationException(method.getName());
                        });
                    for (String name : args) {
                        Class<?> type = Class.forName("Case_" + name);
                        Method method = type.getDeclaredMethod("accept", HttpServletRequest.class, byte[].class);
                        method.setAccessible(true);
                        Object receiver = Modifier.isStatic(method.getModifiers()) ? null : type.getDeclaredConstructor().newInstance();
                        boolean accepted = false;
                        try {
                            Object result = method.invoke(receiver, request, material);
                            accepted = Boolean.TRUE.equals(result)
                                || result instanceof DecodedJWT && "admin".equals(((DecodedJWT) result).getSubject());
                        } catch (InvocationTargetException failure) {
                            Throwable cause = failure.getCause();
                            if (!(cause instanceof JWTVerificationException) && !(cause instanceof SecurityException))
                                throw failure;
                        }
                        System.out.println(name + "=" + accepted);
                    }
                }
            }
        '''
        (sources / "JwtRuntimeOracle.java").write_text(textwrap.dedent(runner), encoding="utf-8")
        classpath = os.pathsep.join(str(path) for path in dependencies)
        records = []

        def execute(label, command):
            started = time.monotonic()
            result = subprocess.run(command, cwd=target, capture_output=True, text=True, timeout=120,
                                    check=False)  # ubs:ignore[py.security.command-injection,python.taint.command] fixed JDK executable and compiler/runtime argv
            for stream in ("stdout", "stderr"):
                (target / (label + "." + stream + ".log")).write_text(getattr(result, stream), encoding="utf-8")
            records.append({"label": label, "command": command, "exit": result.returncode,
                            "elapsed": time.monotonic() - started})
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            return result

        execute("compiler", [java, "-m", "jdk.compiler/com.sun.tools.javac.Main", "--release", "17",
                             "-cp", classpath, "-d", str(classes), *map(str, sorted(sources.glob("*.java")))])
        result = execute("runtime", [java, "-cp", str(classes) + os.pathsep + classpath, "JwtRuntimeOracle",
                                     *[case.name for case in CASES]])
        actual = dict(line.split("=", 1) for line in result.stdout.splitlines())
        self.assertEqual(actual, {case.name: str(case.accepts).lower() for case in CASES})
        (target / "receipt.json").write_text(json.dumps({"java": subprocess.check_output([java, "-version"],
            stderr=subprocess.STDOUT, text=True, timeout=10), "dependencies": DEPENDENCIES,
            "source_sha256": {path.name: hashlib.sha256(path.read_bytes()).hexdigest() for path in sources.glob("*.java")},
            "commands": records, "expected_acceptance": {case.name: case.accepts for case in CASES},
            "observed_acceptance": actual}, indent=2) + "\n", encoding="utf-8")
        print("[java-jwt-compiler-runtime] " + str(target), flush=True)


class JavaJwtPublicTests(unittest.TestCase):
    scan = tls.JavaTlsVerifierTests.scan
    assert_json = tls.JavaTlsVerifierTests.assert_json
    assert_sarif = tls.JavaTlsVerifierTests.assert_sarif
    assert_cache = tls.JavaTlsVerifierTests.assert_cache

    def setUp(self):
        self.artifact = artifact(self._testMethodName)
        identities = {str(path.relative_to(ROOT)): hashlib.sha256(path.read_bytes()).hexdigest()
                      for path in (Path(__file__), DETECTOR) if path.is_file()}
        (self.artifact / "oracle.identity.json").write_text(json.dumps(identities, indent=2) + "\n", encoding="utf-8")

    def fixture(self, cases):
        project = self.artifact / "project"
        project.mkdir(exist_ok=True)
        expected = []
        for case in cases:
            source = project / ("Case_" + case.name + ".java")
            source.write_text(case.source, encoding="utf-8")
            expected.extend((source.name, RULE, line, col, "critical") for line, col in case.sites)
        return project, sorted(expected)

    def test_ordinary_scans_with_and_without_ast(self):
        project, expected = self.fixture(COMPLETE_CASES)
        for no_ast in (False, True):
            result, payload = self.scan("ordinary-" + str(int(no_ast)), project, no_ast=no_ast)
            self.assert_json(result, payload, expected, files=len(COMPLETE_CASES))

    def test_formats_cache_and_source_repair(self):
        selected = tuple(case for case in CASES if case.name in {"inline_header", "verifier_alias", "hmac"})
        project, expected = self.fixture(selected)
        result, payload = self.scan("cold", project)
        self.assert_json(result, payload, expected, files=3)
        self.assert_cache("cold", 0, 3)
        result, payload = self.scan("warm-sarif", project, fmt="sarif")
        self.assert_sarif(result, payload, expected)
        self.assert_cache("warm-sarif", 3, 0)
        result, payload = self.scan("meta-json", project, meta=True)
        self.assert_json(result, payload, expected, meta=True, files=3)
        result, stream = self.scan("meta-jsonl", project, meta=True, fmt="jsonl")
        summaries = [row for row in stream if row["type"] == "totals"]
        self.assertEqual(len(summaries), 1, stream)
        summary = summaries[0]
        self.assert_json(result, {"status": summary["status"], "failed_modules": summary["failed_modules"],
            "totals": summary, "findings": [row for row in stream if row["type"] == "finding"]},
            expected, meta=True, files=3)
        repaired = replace(next(case for case in CASES if case.name == "hmac"), name="inline_header")
        self.fixture((repaired,))
        result, payload = self.scan("repair", project)
        self.assert_json(result, payload, [row for row in expected if row[0] != "Case_inline_header.java"], files=3)
        self.assert_cache("repair", 2, 1)

    def test_selection_category_and_scoped_suppression(self):
        selected = tuple(case for case in CASES if case.name in {"inline_header", "verifier_alias", "hmac"})
        project, expected = self.fixture(selected)
        result, payload = self.scan("category-skip", project, meta=True, extra=("--skip-java=4",))
        self.assert_json(result, payload, [], meta=True, files=3)
        selection = self.artifact / "selected-files"
        selection.write_bytes(os.fsencode(project / "Case_hmac.java") + b"\0")
        result, payload = self.scan("selected", project, extra=("--files-from", str(selection)))
        self.assert_json(result, payload, [], files=1)
        result, payload = self.scan("ignored", project, meta=True,
                                    extra=("--exclude=Case_inline_header.java,Case_verifier_alias.java",))
        self.assert_json(result, payload, [], meta=True, files=1)
        original = next(case for case in CASES if case.name == "inline_header")
        self.fixture((replace(original, body=original.body.replace("// JWT_VERIFY", "// ubs:ignore[" + RULE + "]")),))
        result, payload = self.scan("suppressed", project)
        self.assert_json(result, payload, [row for row in expected if row[0] != "Case_inline_header.java"], files=3)

    def assert_partial(self, result, payload, retained, files):
        detail = result.stdout + "\n" + result.stderr
        self.assertEqual(result.returncode, 2, detail)
        self.assertEqual(payload["status"], "partial", detail)
        self.assertEqual({row["language"] for row in payload["failed_modules"]}, {"java"}, detail)
        actual = [(Path(row["file"]).name, row["rule_id"], row["line"], row["col"], row["severity"])
                  for row in payload["findings"]]
        self.assertEqual(sorted(actual), retained, detail)
        self.assertEqual((payload["totals"]["files"], payload["totals"]["critical"], payload["totals"]["warning"],
                          payload["totals"]["info"]), (files, len(retained), 0, 0), detail)
        return detail

    def test_limits_partial_and_recovery(self):
        ordinary = next(case for case in CASES if case.name == "inline_header")
        budget = replace(ordinary, name="budget", body=";" * 800 + "\n" + ordinary.body)
        project, expected = self.fixture((ordinary, budget))
        retained = [row for row in expected if row[0] == "Case_inline_header.java"]
        for label in ("limited", "limited-warm"):
            result, payload = self.scan(label, project, meta=True, no_ast=True,
                                        environment={"UBS_JAVA_JWT_MAX_TOKENS": "200"})
            self.assertIn("token budget", self.assert_partial(result, payload, retained, 2))
            if label == "limited":
                result, payload = self.scan("recovery", project, meta=True, no_ast=True)
                self.assert_json(result, payload, expected, meta=True, files=2)
        (project / "Case_budget.java").write_text(budget.source.rstrip()[:-1] + "\n", encoding="utf-8")
        result, payload = self.scan("malformed", project, meta=True, no_ast=True)
        self.assertIn("Unbalanced Java JWT", self.assert_partial(result, payload, retained, 2))
        result, payload = self.scan("disabled-invalid-policy", project, meta=True, no_ast=True,
                                    extra=("--skip-java=4",), environment={"UBS_JAVA_JWT_MAX_TOKENS": "invalid"})
        self.assert_json(result, payload, [], meta=True, files=2)

    def test_unsupported_transfer_retains_neighbor(self):
        selected = tuple(case for case in CASES if case.name in {"inline_header", "mutable_field_transfer"})
        project, expected = self.fixture(selected)
        result, payload = self.scan("unsupported-transfer", project, meta=True, no_ast=True)
        self.assertIn("JWT", self.assert_partial(result, payload, expected, 2))


if __name__ == "__main__":
    unittest.main()
