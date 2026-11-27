"""Blinded analyst study using isolated Wazuh evidence and the real SHAM tool loop."""
import argparse
from collections import Counter
from contextlib import closing, contextmanager
from hashlib import sha256
import json
import os
from pathlib import Path
import sqlite3
from statistics import median
import time
from urllib.parse import urlsplit
from uuid import uuid4

from .. import investigation_agent as agent
from ..ollama_reporting import evidence_packet
from .benchmark import LABELS, _decision


DATASET = Path(__file__).resolve().parents[1] / "investigation_study_cases.json"
TOOLS = {"search_historical_incidents", "search_related_agent_logs",
         "inspect_process_tree", "inspect_network_connections"}
ARMS = ("manual", "assisted")
TOOL_BUDGET = 6


def load_dataset(path):
    body = Path(path).read_bytes()
    dataset = json.loads(body)
    if not isinstance(dataset, dict) or not isinstance(dataset.get("cases"), list) or not dataset["cases"]:
        raise ValueError("Study dataset must contain cases")
    cases = {}
    for case in dataset["cases"]:
        if not isinstance(case, dict) or set(case) != {"id", "alert", "tools"}:
            raise ValueError("Each case needs an id, an alert and tool responses")
        name, alert, tools = case["id"], case["alert"], case["tools"]
        if not isinstance(name, str) or not name or len(name) > 80 or name in cases:
            raise ValueError("Use unique case IDs of at most 80 characters")
        if (not isinstance(alert, dict) or not isinstance(alert.get("rule"), dict)
                or any(alert.get(key) is not None and not isinstance(alert[key], dict)
                       for key in ("agent", "data", "predecoder", "decoder"))):
            raise ValueError(f"Case {name} needs a Wazuh alert with a rule")
        if not isinstance(tools, dict) or not set(tools) <= TOOLS or not all(
            isinstance(value, dict) and isinstance(value.get("status"), str) for value in tools.values()
        ):
            raise ValueError(f"Case {name} contains an invalid fixture tool response")
        cases[name] = case
    return sha256(body).hexdigest(), cases


def assignments(cases, analysts):
    names = [analyst.strip().casefold() for analyst in analysts]
    if len(names) != 2 or len(set(names)) != 2 or any(not name or len(name) > 80 for name in names):
        raise ValueError("Choose two distinct analyst pseudonyms")
    return [
        {"case_id": case_id, ARMS[index % 2]: names[0], ARMS[(index + 1) % 2]: names[1]}
        for index, case_id in enumerate(cases)
    ]


@contextmanager
def study_db(path):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    os.close(os.open(path, os.O_CREAT | os.O_RDWR, 0o600))
    with closing(sqlite3.connect(path, timeout=15)) as conn:
        conn.row_factory = sqlite3.Row
        tables = {row[0] for row in conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'"
        )}
        if tables - {"investigation_trials"}:
            raise ValueError("Use a separate SQLite database for the study")
        if os.name != "nt":
            path.chmod(0o600)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS investigation_trials (
                id TEXT PRIMARY KEY, dataset TEXT NOT NULL, case_id TEXT NOT NULL,
                analyst TEXT NOT NULL, arm TEXT NOT NULL, result TEXT,
                UNIQUE(dataset, case_id, arm), UNIQUE(dataset, case_id, analyst)
            )
        """)
        yield conn


def begin_trial(conn, dataset, case_id, analyst, arm):
    if not isinstance(analyst, str) or not 1 <= len(analyst.strip()) <= 80 or arm not in ARMS:
        raise ValueError("Provide an analyst pseudonym and a valid study arm")
    trial_id = uuid4().hex
    try:
        with conn:
            conn.execute("INSERT INTO investigation_trials VALUES (?,?,?,?,?,NULL)",
                         (trial_id, dataset, case_id, analyst.strip().casefold(), arm))
    except sqlite3.IntegrityError:
        raise ValueError("This arm or analyst has already started this case in the study") from None
    return trial_id


def finish_trial(conn, trial_id, decision, evidence, elapsed, assistance, audit):
    decision = dict(decision)
    escalate = decision.pop("escalate", None)
    if type(escalate) is not bool:
        raise ValueError("Record the analyst's escalation decision")
    result = {
        "decision": {**_decision(decision, evidence), "escalate": escalate},
        "evidence": evidence, "elapsed_seconds": round(elapsed, 3),
        "assistance": assistance, "tool_audit": audit,
    }
    with conn:
        updated = conn.execute("UPDATE investigation_trials SET result=? WHERE id=? AND result IS NULL",
                               (json.dumps(result), trial_id))
        if updated.rowcount != 1:
            raise ValueError("This trial is missing or has already been submitted")
    return result


class EvidenceSession:
    def __init__(self, case, trial_id):
        self.case = case
        self.alert = case["alert"]
        self.context = agent._new_context(self.alert, trial_id)
        self.context["max_tool_calls"] = TOOL_BUDGET
        self.audit = []

    def tool_names(self):
        return [tool["function"]["name"] for tool in agent._ollama_tools(self.context, self.case["tools"])]

    def dispatch(self, name, arguments):
        # The same frozen response is available to both arms. Scope and budget
        # checks still run in SHAM before any fixture is returned.
        return self.case["tools"].get(name, {"status": "error", "message": "No fixture for this source"})

    def write_audit(self, event):
        self.audit.append(event)
        return True

    def lookup(self, name):
        if name not in self.tool_names() or self.context["tool_calls"] >= TOOL_BUDGET:
            raise ValueError("Choose a listed tool within the remaining budget")
        query = str(self.alert["rule"].get("description") or "Related event")
        args = {"query": query, "n_results": 2} if name == "search_historical_incidents" else {
            "agent_id": str((self.alert.get("agent") or {}).get("id", "")), "time_range_minutes": 30,
        }
        if name == "search_related_agent_logs":
            args["query"] = query
        agent._execute_tool(self.context, name, args, dispatch=self.dispatch, audit_writer=self.write_audit)

    def assist(self):
        endpoint = os.getenv("SOC_OLLAMA_URL", "http://127.0.0.1:11434/api/chat")
        url = urlsplit(endpoint)
        if (url.scheme not in {"http", "https"} or url.hostname not in {"127.0.0.1", "::1", "localhost"}
                or url.username is not None or url.password is not None or url.path != "/api/chat"
                or url.query or url.fragment):
            raise ValueError("Investigation study requires a loopback Ollama URL")
        self.context["ollama_loopback_url"] = endpoint
        started = time.monotonic()
        try:
            report, self.context = agent.run_dynamic_ollama_agent(
                self.alert, "Investigate the alert using this isolated study's evidence.",
                self.context["incident_id"], self.context, dispatch=self.dispatch,
                audit_writer=self.write_audit, available_tools=self.case["tools"],
            )
            status = "completed"
        except agent.OllamaInvestigationError as error:
            report, self.context = None, error.context
            status = "failed"
        return report, {
            "status": status,
            "model": self.context.get("llm_model") or os.getenv("SOC_OLLAMA_MODEL", "qwen2.5:7b"),
            "elapsed_seconds": round(time.monotonic() - started, 3),
            "tool_calls": self.context["tool_calls"],
        }


def blind_submissions(conn, dataset):
    submissions = []
    for row in conn.execute(
        "SELECT id, case_id, result FROM investigation_trials WHERE dataset=? AND result IS NOT NULL ORDER BY id",
        (dataset,),
    ):
        result = json.loads(row["result"])
        submissions.append({"trial_id": row["id"], "case_id": row["case_id"],
                            "decision": result["decision"], "evidence": result["evidence"]})
    return submissions


def score(conn, dataset, reference):
    if not isinstance(reference, dict) or reference.get("dataset_sha256") != dataset:
        raise ValueError("Reference grades must match the study dataset SHA-256")
    labels, grades = reference.get("labels"), reference.get("unsupported_claims", {})
    if (not isinstance(labels, dict) or any(
        not isinstance(label, dict) or label.get("classification") not in LABELS
        or type(label.get("escalate")) is not bool for label in labels.values()
    ) or not isinstance(grades, dict) or any(type(n) is not int or n < 0 for n in grades.values())):
        raise ValueError("Invalid reference labels or unsupported-claim counts")
    rows = conn.execute("SELECT * FROM investigation_trials WHERE dataset=?", (dataset,)).fetchall()
    if not set(grades) <= {row["id"] for row in rows if row["result"] is not None}:
        raise ValueError("Unsupported-claim grades must reference completed trials in this study")
    groups = {arm: [row for row in rows if row["arm"] == arm] for arm in ARMS}
    completed = {arm: {} for arm in ARMS}
    metrics = {}
    for arm, trials in groups.items():
        correct_labels = correct_escalations = labelled = graded = claims = assistance_failures = citation_errors = 0
        elapsed = []
        for row in trials:
            if row["result"] is None:
                continue
            result = json.loads(row["result"])
            completed[arm][row["case_id"]] = result
            elapsed.append(result["elapsed_seconds"])
            assistance_failures += result["assistance"].get("status") == "failed"
            citation_errors += len(result["decision"]["reference_errors"])
            label = labels.get(row["case_id"])
            if label:
                labelled += 1
                correct_labels += result["decision"]["classification"] == label["classification"]
                correct_escalations += result["decision"]["escalate"] == label["escalate"]
            if row["id"] in grades:
                graded += 1
                claims += grades[row["id"]]
        metrics[arm] = {
            "started": len(trials), "completed": len(elapsed), "incomplete": len(trials) - len(elapsed),
            "labelled": labelled, "correct_classifications": correct_labels,
            "correct_escalations": correct_escalations, "graded_claims_trials": graded,
            "unsupported_claims": claims if graded else None, "citation_errors": citation_errors,
            "assistance_failures": assistance_failures,
            "median_elapsed_seconds": median(elapsed) if elapsed else None,
        }
    paired = completed["manual"].keys() & completed["assisted"].keys()
    differences = [completed["manual"][case]["elapsed_seconds"] - completed["assisted"][case]["elapsed_seconds"]
                   for case in paired if completed["assisted"][case]["assistance"]["status"] == "completed"]
    models = Counter(result["assistance"]["model"] for result in completed["assisted"].values()
                     if result["assistance"].get("model"))
    return {"dataset_sha256": dataset, "completed_pairs": len(paired), "pairs_with_assistance": len(differences),
            "paired_median_elapsed_difference_seconds": round(median(differences), 3) if differences else None,
            "assisted_models": dict(models), "arms": metrics}


def _print(value):
    print(json.dumps(value, indent=2))


def _run(conn, dataset, case, analyst, arm):
    trial_id = begin_trial(conn, dataset, case["id"], analyst, arm)
    started = time.monotonic()
    session = EvidenceSession(case, trial_id)
    _print(evidence_packet(session.alert, session.context))
    assistance = {"status": "not_requested"}
    if arm == "assisted":
        report, assistance = session.assist()
        if report:
            print("".join(char for char in report if char.isprintable() or char in "\n\t"))
        else:
            print("Assistant failed. Continue with the available evidence.")
        _print(evidence_packet(session.alert, session.context))
    print("Request a tool by name. Press Enter to record your decision.")
    while session.context["tool_calls"] < TOOL_BUDGET and session.tool_names():
        print(", ".join(session.tool_names()))
        name = input("Evidence tool: ").strip()
        if not name:
            break
        try:
            session.lookup(name)
            _print(evidence_packet(session.alert, session.context))
        except ValueError as error:
            print(str(error))
    evidence = evidence_packet(session.alert, session.context)
    print("Available evidence references: " + ", ".join(evidence))
    while True:
        decision = {"classification": input("Classification (malicious/suspicious/benign/insufficient): ").strip(),
                    "rationale": input("Rationale: ").strip(),
                    "evidence_refs": input("Evidence IDs, separated by spaces: ").split()}
        escalate = input("Escalate (yes/no): ").strip().lower()
        if escalate not in {"yes", "no"}:
            print("Enter yes or no to record escalation.")
            continue
        decision["escalate"] = escalate == "yes"
        try:
            result = finish_trial(conn, trial_id, decision, evidence, time.monotonic() - started,
                                  assistance, session.audit)
        except ValueError as error:
            print(str(error))
        else:
            _print({"trial_id": trial_id, "recorded": True, "assistance": result["assistance"]})
            return


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--dataset", type=Path, default=DATASET)
    parser.add_argument("--state", type=Path, default=Path("data/investigation-study.sqlite3"))
    commands = parser.add_subparsers(dest="command", required=True)
    plan = commands.add_parser("plan")
    plan.add_argument("--analysts", nargs=2, required=True)
    for command in ("run", "check"):
        sub = commands.add_parser(command)
        sub.add_argument("--case", required=True)
        if command == "run":
            sub.add_argument("--analyst", required=True)
            sub.add_argument("--arm", choices=ARMS, required=True)
    commands.add_parser("blind")
    results = commands.add_parser("score")
    results.add_argument("--reference", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        dataset, cases = load_dataset(args.dataset)
        if args.command == "plan":
            _print({"dataset_sha256": dataset, "assignments": assignments(cases, args.analysts)})
        elif args.command == "check":
            session = EvidenceSession(cases[args.case], "study-check")
            _, assistance = session.assist()
            _print({"case_id": args.case, **assistance, "tool_statuses": [item["status"] for item in session.audit]})
            return 0 if assistance["status"] == "completed" else 1
        else:
            with study_db(args.state) as conn:
                if args.command == "run":
                    _run(conn, dataset, cases[args.case], args.analyst, args.arm)
                elif args.command == "blind":
                    _print({"dataset_sha256": dataset, "submissions": blind_submissions(conn, dataset)})
                else:
                    _print(score(conn, dataset, json.loads(args.reference.read_text(encoding="utf-8"))))
    except (KeyError, OSError, ValueError, sqlite3.Error) as error:
        parser.exit(2, f"Investigation study: {error}\n")
    except (EOFError, KeyboardInterrupt):
        parser.exit(1, "Investigation study stopped. Any started trial remains incomplete.\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
