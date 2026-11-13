"""Optional one-deployment cursor; normal startup still tails new alerts at EOF."""
import json
import os
from pathlib import Path


def resume_point(stream, alert_path):
    state_path = os.getenv("SOC_ALERT_RESUME_FILE", "").strip()
    stat = os.fstat(stream.fileno())
    if not state_path:
        return stat.st_size, set()
    state = json.loads(Path(state_path).read_text(encoding="utf-8"))
    offset = state["offset"]
    if (Path(state["path"]).resolve() != Path(alert_path).resolve()
        or state["inode"] != stat.st_ino or state["device"] != stat.st_dev
        or type(offset) is not int or not 0 <= offset <= stat.st_size):
        raise ValueError("Deployment resume cursor does not match the alert file; refusing to skip evidence")
    if offset:
        stream.seek(offset-1)
        if stream.read(1) != "\n":
            raise ValueError("Deployment resume offset is not a complete JSONL boundary")
    ids = state.get("already_processed_ids", [])
    if not isinstance(ids, list) or not all(isinstance(x, str) for x in ids):
        raise ValueError("Invalid resume deduplication list")
    return offset, set(ids)
