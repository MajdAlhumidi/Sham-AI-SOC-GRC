"""Explicit, idempotent import of currently retained Chroma incidents only.

Never reads GRC's retained/deleted incident references, never guesses raw alerts.
Run with the same user and runtime environment as the agent.
"""
import argparse
import json
from .store import capture


def run(path, alerts_file=None):
    import chromadb
    collection = chromadb.PersistentClient(path=path).get_collection("security_incidents")
    page = collection.get(include=["metadatas"])
    wanted = {str((m or {}).get("source_alert_id") or "") for m in page["metadatas"]} - {""}
    originals = {}
    if alerts_file:
        with open(alerts_file, encoding="utf-8") as stream:
            for line in stream:
                try:
                    alert = json.loads(line)
                except ValueError:
                    continue
                if isinstance(alert, dict) and str(alert.get("id", "")) in wanted:
                    originals[str(alert["id"])] = alert
    recovered = 0
    for incident_id, metadata in zip(page["ids"], page["metadatas"]):
        original = originals.get(str((metadata or {}).get("source_alert_id") or ""))
        capture({**(metadata or {}), "incident_id": incident_id}, original,
                {"audit_warnings": ["Source alert recovered by exact Wazuh alert ID during migration. Original structured model findings and tool responses were not recovered."]} if original else None)
        recovered += bool(original)
    return {"retained_incidents_processed": len(page["ids"]), "matching_source_alerts_available": recovered}


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--chroma-path", required=True)
    parser.add_argument("--alerts-file", help="Optional original Wazuh JSONL; exact source-alert-ID matches only")
    args = parser.parse_args()
    print(run(args.chroma_path, args.alerts_file))
