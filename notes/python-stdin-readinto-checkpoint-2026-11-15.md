# Python stdin buffer mutation checkpoint

**Status: unactivated, unverified candidate.** The execution workspace disconnected during implementation. This checkpoint does not change the running scanner and does not close the stdin-provenance or D6 beads.

## Recoverable implementation

- Base commit: `f1c06ea3f80497432a29581871b3719ad8462f9d`.
- Patch: `test-suite/patches/python-stdin-readinto.apply-patch`.
- Immutable patch blob: `588972610de2c33af160d20d4ca1db23b409d187`.
- Format: manually authored `apply_patch` instructions, with paths relative to the repository root.
- Affects `modules/helpers/ubs_core/analyzers/taint_py.py` and `test-suite/quality/test_taint_python_dataflow.py`.
- Includes eight regression methods covering source domains, aliases, helpers, count results, empty buffers, copies/rebinding, control flow, sanitizers and unsupported identities.

The proposed implementation represents exact native bytearray storage as a finite binding marker. Binary stdin `readinto` and `readinto1` write source provenance into the supplied allocation's shared heap; their returned byte counts stay clean. Opaque buffers, memoryview, dynamic allocations and producer-lifetime uncertainty remain intended incomplete boundaries.

## Evidence actually obtained

Before editing, this source raised `AnalysisLimit: stdin buffer mutation or detachment is unmodeled; analysis is incomplete`, with no retained effects:

```python
import sys
buffer = bytearray(4096)
sys.stdin.buffer.readinto(buffer)
eval(buffer.decode())
```

This is a confirmed coverage refusal, not a claimed complete-clean security miss.

The production patch was applied in the lost workspace. The regression patch and final probe did not return a result. **No candidate runtime test is reported as passing.** The archived patch was reconstructed from the exact manual edits. In-memory exact-context replay against the immutable base and reverse replay both succeeded; reverse replay restored byte-identical original sources. That establishes patch recoverability, not Python syntax or scanner correctness.

## Known unresolved implementation problem

Static review found that `solve_function` quarantines a function and all of its contexts after an `AnalysisLimit`. A generic helper such as `def fill(buffer): sys.stdin.buffer.readinto(buffer)` initially receives a symbolic parameter. The proposed reader transfer can reject it before a concrete bytearray context is analyzed. Merely adding the marker to context/capture lists does not establish correct helper specialization. The fixed-helper regression expectations may fail.

Resolve that with a sound deferred type/effect obligation or equivalent specialization design. Do not silence the analysis error or discard those regression expectations. Also verify empty-capacity invalidation after resizing, saved native reader/constructor identities, exceptions after partial writes, and producer-lifetime/reflection boundaries.

## Remaining activation work

1. Recover the workspace or apply the checkpoint to its exact base in a working checkout.
2. Resolve the helper specialization problem and run the eight focused methods, including native harmless-input witnesses.
3. Run the broader Python taint/dataflow, callable, summary and completion cohorts.
4. Exercise actual module and meta-runner JSON/SARIF cases for unsafe, safe and incomplete outcomes.
5. Regenerate canonical integrity pins and SHA256SUMS; run required checks through the project's DSR path.
6. Only after evidence supports the behavior, activate and commit the production change. This checkpoint carries no release qualification.
