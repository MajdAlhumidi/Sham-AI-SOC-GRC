"""Durable Wazuh JSONL intake with recovery from retained rotations."""
from contextlib import closing, contextmanager
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
import gzip
from hashlib import sha256
import json
import logging
import os
from pathlib import Path
import re
import sqlite3
from stat import S_ISREG
import time
import uuid

if __package__:
    from .alert_resume import resume_point
else:
    from alert_resume import resume_point


logger = logging.getLogger(__name__)
BATCH_SIZE = 256
SAMPLE_SIZE = 128
MONTHS = ("Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec")


@dataclass(frozen=True)
class Position:
    device: int
    inode: int
    modified_ns: int
    offset: int
    fingerprint: str


def _fingerprint(stream, offset):
    size = min(offset, SAMPLE_SIZE)
    stream.seek(0)
    prefix = stream.read(size)
    stream.seek(offset - size)
    tail = stream.read(size)
    if len(prefix) != size or len(tail) != size:
        return None
    return sha256(prefix + tail).hexdigest()


def _complete_boundary(stream, end):
    """Start after complete records on first installation, even during a write."""
    while end:
        start = max(0, end - 4096)
        stream.seek(start)
        index = stream.read(end - start).rfind(b"\n")
        if index >= 0:
            return start + index + 1
        end = start
    return 0


def _matches(stream, position, *, identity=True):
    stat = os.fstat(stream.fileno())
    if identity and (stat.st_dev, stat.st_ino) != (position.device, position.inode):
        return False
    return _fingerprint(stream, position.offset) == position.fingerprint


def _archive_reader(path):
    return gzip.open(path, "rb") if path.suffix == ".gz" else path.open("rb")


@contextmanager
def open_alert_intake(source, database, min_level):
    path = Path(database).resolve()
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    # Own intake and delivery for this database. The OS releases the lock on a crash.
    with closing(os.fdopen(os.open(str(path) + ".lock", os.O_RDWR | os.O_CREAT, 0o600), "rb+")) as lock:
        if os.name == "nt":
            import msvcrt
            msvcrt.locking(lock.fileno(), msvcrt.LK_NBLCK, 1)
        else:
            import fcntl
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        os.close(os.open(path, os.O_CREAT | os.O_RDWR, 0o600))
        if os.name != "nt":
            path.chmod(0o600)
        with closing(sqlite3.connect(path, timeout=20)) as conn:
            yield AlertIntake(Path(source).absolute(), conn, min_level)


class AlertIntake:
    def __init__(self, source, conn, min_level):
        self.source = source
        self.conn = conn
        self.min_level = min_level
        self.conn.row_factory = sqlite3.Row
        tables = {row[0] for row in self.conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'"
        )}
        if tables - {"alert_cursor", "alert_jobs"}:
            raise ValueError("Alert intake requires its own SQLite database")
        self.conn.execute("PRAGMA secure_delete=ON")
        self.conn.executescript("""
            CREATE TABLE IF NOT EXISTS alert_cursor(
                singleton INTEGER PRIMARY KEY CHECK(singleton=1),
                source TEXT NOT NULL, position TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS alert_jobs(
                event_key TEXT PRIMARY KEY, incident_id TEXT, alert TEXT, prepared TEXT,
                attempts INTEGER NOT NULL DEFAULT 0, retry_at REAL NOT NULL DEFAULT 0);
            CREATE INDEX IF NOT EXISTS alert_jobs_pending ON alert_jobs(retry_at) WHERE alert IS NOT NULL;
        """)
        cursor = self.conn.execute("SELECT source, position FROM alert_cursor").fetchone()
        if cursor and cursor["source"] != str(self.source):
            raise ValueError("Alert intake database belongs to a different input log")

    def _checkpoint(self, position):
        self.conn.execute(
            """INSERT INTO alert_cursor VALUES (1, ?, ?)
               ON CONFLICT(singleton) DO UPDATE SET position=excluded.position""",
            (str(self.source), json.dumps(asdict(position))),
        )

    @staticmethod
    def _position(stream, offset, stat):
        fingerprint = _fingerprint(stream, offset)
        if fingerprint is None:
            raise OSError("Wazuh alert log shortened during capture")
        return Position(stat.st_dev, stat.st_ino, stat.st_mtime_ns, offset, fingerprint)

    def _initialize(self, stream):
        stat = os.fstat(stream.fileno())
        offset, processed = resume_point(stream, str(self.source))
        position = self._position(stream, _complete_boundary(stream, offset), stat)
        with self.conn:
            self.conn.executemany("INSERT OR IGNORE INTO alert_jobs(event_key) VALUES (?)",
                                  (("id:" + identifier,) for identifier in processed))
            self._checkpoint(position)
        return position

    def _pending_job(self, line, location):
        if not line.strip():
            return None
        try:
            value = json.loads(line)
            level = int(value["rule"]["level"])
        except (ValueError, TypeError, KeyError, OverflowError):
            logger.warning("Ignored malformed Wazuh alert at byte %d", location)
            return None
        if level < self.min_level:
            return None
        raw = json.dumps(value, sort_keys=True)
        alert_id = value.get("id")
        event_key = "id:" + str(alert_id) if isinstance(alert_id, (str, int)) and alert_id else (
            "sha256:" + sha256(raw.encode()).hexdigest())
        incident_id = f"INC-{datetime.now(timezone.utc):%Y%m%d}-{uuid.uuid4().hex.upper()}"
        return event_key, incident_id, raw

    def _collect(self, stream, offset, *, sealed=False, checkpoint_empty=False):
        stat = os.fstat(stream.fileno())
        initial = offset
        size = min(offset, SAMPLE_SIZE)
        stream.seek(0)
        prefix = stream.read(size)
        stream.seek(offset - size)
        tail = stream.read(size)
        if len(tail) != size or len(prefix) != size:
            raise OSError("Wazuh alert log shortened during capture")
        while True:
            start = offset
            pending = []
            for _ in range(BATCH_SIZE):
                line = stream.readline()
                if not line or (not sealed and not line.endswith(b"\n")):
                    break
                job = self._pending_job(line, offset)
                if job:
                    pending.append(job)
                offset += len(line)
                prefix += line[:SAMPLE_SIZE - len(prefix)]
                tail = (tail + line[-SAMPLE_SIZE:])[-SAMPLE_SIZE:]
            if offset == start and not checkpoint_empty:
                return offset > initial
            fingerprint = sha256(prefix + tail).hexdigest()
            if not sealed and _fingerprint(stream, offset) != fingerprint:
                raise OSError("Wazuh alert log changed while reading")
            position = Position(stat.st_dev, stat.st_ino, stat.st_mtime_ns, offset, fingerprint)
            with self.conn:
                self.conn.executemany(
                    "INSERT OR IGNORE INTO alert_jobs(event_key, incident_id, alert) VALUES (?, ?, ?)", pending)
                self._checkpoint(position)
            if not sealed or offset == start:
                return offset > initial
            checkpoint_empty = False

    def _archives(self, live_stat, position):
        root = self.source.parent
        name = re.escape(self.source.name)
        rotated = re.compile(rf"{name}(?:\.\d+|-\d+)(?:\.gz)?$|ossec-alerts-\d+(?:-\d+)?\.json(?:\.gz)?$")
        candidates = []
        for path in (*root.glob(self.source.name + "[.-]*"),
                     *root.glob("ossec-alerts-*.json*"),
                     *root.glob("[0-9][0-9][0-9][0-9]/*/ossec-alerts-*.json*")):
            if not rotated.fullmatch(path.name):
                continue
            try:
                info = path.stat()
            except FileNotFoundError:
                continue
            if (S_ISREG(info.st_mode) and not os.path.samestat(info, live_stat)
                    and info.st_mtime_ns >= position.modified_ns - 1_000_000_000):
                # Numbered logrotate generations count backwards. Native Wazuh
                # uses the day followed by its forward rotation sequence.
                native = re.fullmatch(r"ossec-alerts-(\d+)(?:-(\d+))?\.json(?:\.gz)?", path.name)
                if native:
                    month = path.parent.name
                    year = path.parent.parent.name
                    tie = (int(year) if year.isdigit() else 0, MONTHS.index(month) if month in MONTHS else 0,
                           int(native[1]), int(native[2] or 0))
                else:
                    number = re.fullmatch(rf"{name}\.(\d+)(?:\.gz)?", path.name)
                    tie = (0, 0, 0, -int(number[1]) if number else 0)
                candidates.append((info.st_mtime_ns, tie, path))
        return [path for _, _, path in sorted(candidates)]

    def _recover(self, live, position):
        paths = self._archives(os.fstat(live.fileno()), position)
        match = None
        # Prefer the old inode. A compressed or copied archive has a new inode,
        # so match the saved prefix and bytes at the record boundary as well.
        for identity in (True, False):
            if not identity and position.offset == 0:
                break
            for index, path in enumerate(paths):
                with _archive_reader(path) as archive:
                    if _matches(archive, position, identity=identity):
                        match = index
                        break
            if match is not None:
                break
        if match is None and position.offset:
            logger.warning("Previous Wazuh alert generation unavailable at its checkpoint. Recovering retained logs.")
        start = match if match is not None else 0
        for index in range(start, len(paths)):
            offset = position.offset if index == match else 0
            with _archive_reader(paths[index]) as archive:
                self._collect(archive, offset, sealed=True, checkpoint_empty=True)
        advanced = self._collect(live, 0, checkpoint_empty=True)
        return advanced or bool(paths)

    def capture(self):
        try:
            live = self.source.open("rb")
        except FileNotFoundError:
            # Wazuh can remove the live hard link briefly during rotation.
            return False
        with live:
            row = self.conn.execute("SELECT position FROM alert_cursor").fetchone()
            position = Position(**json.loads(row["position"])) if row else self._initialize(live)
            if not _matches(live, position):
                return self._recover(live, position)
            return self._collect(live, position.offset)

    def deliver(self, prepare, publish):
        job = self.conn.execute(
            "SELECT * FROM alert_jobs WHERE alert IS NOT NULL AND retry_at<=? ORDER BY rowid LIMIT 1",
            (time.time(),),
        ).fetchone()
        if job is None:
            return False
        alert = json.loads(job["alert"])
        try:
            if job["prepared"] is None:
                prepared = prepare(alert, job["incident_id"])
                with self.conn:
                    self.conn.execute("UPDATE alert_jobs SET prepared=? WHERE event_key=?",
                                      (json.dumps(prepared), job["event_key"]))
            else:
                prepared = json.loads(job["prepared"])
            publish(alert, prepared)
        except Exception as exc:
            delay = min(2 ** min(job["attempts"] + 1, 6), 60)
            logger.error("Investigation %s remains queued after %s. Retrying in %ds.",
                         job["incident_id"], type(exc).__name__, delay)
            with self.conn:
                self.conn.execute("UPDATE alert_jobs SET attempts=attempts+1,retry_at=? WHERE event_key=?",
                                  (time.time() + delay, job["event_key"]))
        else:
            with self.conn:
                self.conn.execute("UPDATE alert_jobs SET alert=NULL,prepared=NULL WHERE event_key=?",
                                  (job["event_key"],))
        return True
