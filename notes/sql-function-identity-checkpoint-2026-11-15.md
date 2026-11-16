# PostgreSQL function-identity checkpoint

**Status: implemented in the disconnected workspace, archived here without activation.** Regression execution was interrupted and its result could not be retrieved. This checkpoint does not change the production scanner.

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
