# PostgreSQL function-identity checkpoint

**Historical checkpoint:** the November 15 implementation was archived without activation after interrupted execution. The November 20 recovery and qualification results are recorded below; the original interrupted run is still not a passing result.

## November 20 recovery and source qualification

The candidate was restored against `06222fb6b9069ec95d2c72d6f753403613804702`.
Before changing the analyzer, the restored independent oracle ran through DSR's
native quality executor: **179 source tests, 20 failures**. After restoring the
identity transfer, all original cases passed. A new regression additionally
checks that two autocommit definitions on the same physical line retain
separate publication evidence after dropping and recreating the same name.

The final native/helper cohort passed **181 tests, no skips**, including exact
finding identities and helper JSON/SARIF completion. Public coverage now also
checks that a rejected destination collision or stale old identity retains
known findings in both module and runner JSON/SARIF output. Public scanner
tests explicitly retain their scratch files with `UBS_KEEP_TEMP=1`.

Retained DSR receipts and full logs are under
`test-suite/artifacts/sql-identity-session/`:

- `baseline-native.log`: 179 tests, 20 failures; SHA-256
  `472dca07ea9b25cc1acab4fcd1e2b53d0fc00e7f0ef4bd1d9836b89bb57fcbae`.
- `final-native.log`: 181 tests passed; SHA-256
  `9825f3d2d21532bc7e972b7e04b621b69b024aed82b287dd21cc067e62af745a`.

The source change is activated in development version **5.5.88**. An independent
20-case oracle passed all exact rule/location/completion assertions; the incumbent
passed only 3 of those 20 cases. Independent candidate log SHA-256:
`0b462f7b9ffa44fd87fcce3b6ac3741cecb46ead7ba8d2403088421aa1b94dd9`.

An isolated integration checkout ran the ordinary module and meta-runner against
the complete native fixture corpus in both JSON and SARIF: all four legs passed,
including every new rename/schema-transfer fixture. Retrieved public logs also
show passing retained-finding identity boundaries, CTE/psql boundaries, neighboring
partial files, category selection, baseline comparison, JSONL/occurrence sidecars
and project configuration. No observed assertion failure occurred in these
completed integration cases.

Canonical module/helper checksums, SHA256SUMS, runner Bash syntax and whitespace
checks passed through DSR (17,900 ms; log SHA-256
`ee4d2e19677e37ff23e913fefcdbe0fc17867cd190c6a2ae4f9cf12633093241`).
The production scanner and test blobs were uploaded through GitHub and matched
the exact local Git object hashes before publication.

Qualification limits remain explicit. The initial 120-second combined source/
public run timed out; a subsequent public run lost its execution transport after
25 actual CLI calls, before the full class returned. The remaining selection,
cache, suppression and staged-index methods were submitted separately, but their
final result was not recovered before the environment became unavailable.
The prescribed full suite and changed-source self-scan were also submitted
through DSR with retained scratch and the repository's deletion guard; no final
result was observed. Full ShellCheck was killed with exit 137. An earlier
integrity attempt timed out before the successful unchanged-gate rerun.

These are bounded source and observed CLI results, not a complete public-suite,
full-repository, live PostgreSQL, platform or release qualification. The original
acceptance gates and umbrella beads remain open.

## Recoverable implementation

- Base commit: `f1c06ea3f80497432a29581871b3719ad8462f9d`.
- Patch: `test-suite/patches/sql-function-identity-candidate.apply-patch`.
- Immutable patch blob: `63b4778d6605c0eb274df16fa7040d9ebdfae38e`.
- Base scanner blob: `9d2a02e9c9400e33b7b97e7c57c00f2725e9fddc`.
- Format: manually authored `apply_patch` instructions using repository-relative paths.
- Affects `modules/helpers/ubs_core/sql_scan.py` and `test-suite/quality/test_sql_scanner.py`.

The implementation follows a selected function through `ALTER FUNCTION ... RENAME TO ...` and `ALTER FUNCTION ... SET SCHEMA ...`. It preserves PUBLIC execution privileges, SECURITY DEFINER/INVOKER, function-local search_path, body, original evidence location, overload types and transaction/savepoint snapshots. Old identities stop resolving; selected destination collisions remain incomplete without overwriting either function.

Publication evidence is keyed by defining statement offset and rule rather than a mutable function name. A rename or schema move should not duplicate an unchanged dangerous definition, and later hardening or deletion should not erase an already committed exposure. Distinct statements on the same line remain distinct.

The patch adds 33 fixed cases: 18 intended complete migrations and 15 incomplete-boundary controls. It also strengthens incomplete-case checks to require the exact independently expected findings where those labels are present.

## Evidence actually obtained

Before the scanner edit, four focused tests ran:

- Rename followed by REVOKE: failed as expected with incomplete analysis and a false PUBLIC warning.
- Schema transfer followed by REVOKE: failed as expected with the same defect.
- Two selected destination-collision controls: passed on the base.

Baseline artifacts were recorded locally under `test-suite/artifacts/sql-acceptance/SQLNativeTests-757d41fecb35/`. Those files were in the unavailable workspace and are not claimed to be preserved by this checkpoint.

After editing, this command was launched from `test-suite/`:

```bash
PYTHONDONTWRITEBYTECODE=1 python3 -B -m unittest \
  quality.test_sql_scanner.SQLNativeTests \
  quality.test_sql_scanner.SQLHelperTests
```

Output was redirected to `test-suite/artifacts/sql-identity-tests.log` (execution session 31922). **No result was retrieved.** The candidate is not reported as passing.

The archive was reconstructed from the successful manual patch calls. All seven hunks matched the exact base; in-memory forward and reverse replay restored byte-identical source files. The archive contains 33 new `Case` entries. This confirms recoverability, not execution or correctness.

## Review scope

The fixtures cover later REVOKE/GRANT/replacement, schema-wide privileges, original-name reuse, quoted identifiers, overload distinction, commit history, rollback/savepoints, unresolved external targets, malformed clauses and renamed/moved `format` functions that must not acquire builtin authority.

PostgreSQL's documented/source behavior informed the same-target controls: a move to the existing schema is a no-op; renaming to the existing name encounters the duplicate-function check.

Primary references:

- https://www.postgresql.org/docs/current/sql-alterfunction.html
- https://doxygen.postgresql.org/alter_8c_source.html

## Remaining activation work

1. Retrieve the interrupted native/helper log or rerun both suites, including all existing cases.
2. Resolve any mismatch without weakening complete/partial status, finding identity or privilege assertions.
3. Run the real SQL module and meta-runner matrix with `UBS_SQL_E2E=1`, including `test_native_oracle_through_module_and_runner_formats`.
4. Check whitespace and Python syntax, regenerate canonical integrity pins and SHA256SUMS, and run required project checks through DSR.
5. Activate only after the evidence supports the production change.

The SQL migration coverage and broader D6/quality beads remain open. Existing WITH/psql directive reports were already handled on the initial main; this candidate extends a separate verified identity-tracking gap. There is no full-suite or release qualification.
