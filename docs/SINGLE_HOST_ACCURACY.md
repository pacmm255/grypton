# Single-host accuracy: verification limits

Source reviewed: commit `1e3e99e`, 2026-09-10. This is a source-level assessment;
it does not report a new live engagement or an accuracy benchmark result.

## Corrected conclusion

The prior three-program investigation demonstrated limited observed coverage
and extensive repetitive activity. It did not establish that scope size was
the primary cause of zero useful findings. A single host can expose substantial
application functionality. Conversely, a zero-finding run on a host with an
unknown defect inventory cannot establish either successful coverage or missed
vulnerabilities.

The previous changes addressed operational efficiency and input completeness.
Their effect on discovery accuracy remains unmeasured. Successful provider
calls do not establish the quality of either model's decisions.

## What the repository actually verifies

| Evidence | What it establishes | What it does not establish |
| --- | --- | --- |
| 33 unit-test methods in `tests/test_core.py` | CLI, transport, persistence, constraints, model routing, and selected control behavior | Single-host discovery precision or recall |
| `test_mock_loop_persists_independent_verdict` | Findings and verdicts move through the orchestrator and persist | Discovery or independent reproduction: the mock inserts findings and returns confirmation |
| Live local integration described in `VERIFICATION.md` | An example of real provider/tool communication and persisted results | Performance across unseen positive and negative examples |
| `audit_workspace` in `grypton/reporting.py` | Routing, required review provenance, scope checks, and referenced-file integrity | Whether a recorded security claim is true or an unrecorded defect was missed |
| Required fields in `_record_finding` | The supplied fields have nonempty string representations | That the evidence exists or supports the claimed impact |

The mock worker inserts findings directly in `grypton/mockbackends.py` at lines
98 and 106. Its `validate_severity` method returns `confirm` without inspecting
the supplied evidence. This is useful integration scaffolding; its results
cannot count as measured discovery or validation accuracy.

## New convergence behavior has an unmeasured accuracy risk

`Engine._network_signature` retains tool, method, host, path, and query-key names.
It omits request bodies, header values, query values, response content, and
changes in the evidence. Therefore, a repeated signature does not establish
that the underlying observation is unchanged.

The repetition streak also advances independently of newly recorded findings
or surface. After the guard has already offered a pivot, a subsequent repeated
signature can trigger stopping before that turn's manager review and automatic
validation block. This is a source-level regression risk in `1e3e99e`; it is not
an explanation for the earlier runs, which predated that commit.

The existing guard test checks that an unproductive mock stops. It does not
check whether the guard preserves useful analysis or new evidence on a repeated
request shape. Consequently, the current tests cannot support the claim that
the guard preserves accuracy.

## Evidence needed for a defensible accuracy assessment

Use a fixed, offline evidence-review corpus from one controlled application,
with independently established labels and a held-out portion. Include examples
that support a finding, examples that refute it, and examples that are
insufficient to decide. Keep expected answers out of the reviewer's inputs.

Measure supported findings correctly recognized, known findings missed,
unsupported claims accepted, correct abstentions, and severity agreement.
Separate missing evidence from a failure to interpret available evidence, and
separate worker interpretation from manager decisions and validator judgments.
Compare versions on the same evidence and record repeated-run variation.

This evaluates reasoning over supplied evidence. It does not measure live
discovery or show that unobserved portions of an application were covered.
Until such evidence exists, single-host accuracy is **unknown**. No external
rerun, broader scope, higher activity count, or longer runtime substitutes for
that measurement.
