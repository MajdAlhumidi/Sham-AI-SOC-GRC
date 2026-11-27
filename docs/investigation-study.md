# Manual and agent-assisted investigation study

Run this study from the repository root using the SHAM Python environment.
It uses a separate SQLite database and frozen evidence responses. Both
analysts start with the same Wazuh alert. They choose from the same
read-only evidence tools within the same six-call budget. In the assisted arm,
the configured local Ollama model uses SHAM's native tool loop, argument
checks and validated report. The analyst then records their own decision.
The fixtures supply the captured evidence, so the study runs without access
to live Wazuh, ChromaDB or an incident store.

## Assign and run

Four synthetic practice cases are bundled. For a formal study, prepare a
new dataset of independently selected, redacted cases with representative
benign, suspicious, malicious and limited-telemetry events. Use the same
format as [the practice dataset](../scripts/investigation_study_cases.json).
Each case contains an `id`, a Wazuh `alert` and `tools` keyed by
their names. Add `--dataset path/to/cases.json` before the subcommand for
every step. Use `--state path/to/study.sqlite3` for a separate cohort.

```sh
python -m scripts.casework.investigation_study plan --analysts reviewer-a reviewer-b
python -m scripts.casework.investigation_study run --case I01 --analyst reviewer-a --arm manual
python -m scripts.casework.investigation_study run --case I01 --analyst reviewer-b --arm assisted
```

Use the suggested assignments so each participant sees a given case once
and the two participants alternate arms across cases. Keep them blind to
the reference labels and each other's responses. Each session collects a
classification, escalation decision, rationale and evidence references.
The timer starts with the case, includes model waiting and ends at
submission. The assisted arm also records model time and failures. An
interrupted session counts as incomplete in this cohort.

To check the configured local model before involving analysts, run
`python -m scripts.casework.investigation_study check --case I01`.
Set `SOC_OLLAMA_MODEL` to an installed model with tool support. This check
runs the actual tool loop and leaves the study results untouched.

## Blind review and scoring

Have a separate reviewer adjudicate each case and record the reference
classification and escalation. Share the output from the following
command with that reviewer to grade factual support. It includes
anonymous submissions and the evidence each analyst saw.

```sh
python -m scripts.casework.investigation_study blind
```

The reviewer records unsupported claims per trial ID and returns a reference file
using the dataset fingerprint from `plan` or `blind`. This is its format.

```json
{
  "dataset_sha256": "replace with the dataset hash",
  "labels": {"I01": {"classification": "suspicious", "escalate": true}},
  "unsupported_claims": {"replace with anonymous trial id": 0}
}
```

```sh
python -m scripts.casework.investigation_study score --reference reference.json
```

Report completed, incomplete, labelled and graded counts alongside
classification and escalation agreement, unsupported claims and elapsed
time. The paired median difference uses the same case across the two arms
with a completed assistant run. Keep the model identity and fixture hash
with the reported results. The replay measures investigation decisions and
evidence selection on the chosen cases. A production study also needs
representative alert coverage and separate measurement of live query latency.
