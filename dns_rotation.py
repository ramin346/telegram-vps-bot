import json
import time
from typing import NamedTuple

import cloudflare

MAX_RETRIES = 5
MAX_DELAY = 3650 * 86400


class Rotation(NamedTuple):
    id: int
    user_id: int
    zone_id: str
    record_id: str
    name: str
    kind: str
    expected: str
    steps: str
    due_at: int
    attempts: int
    status: str
    note: str
    account_id: int | None


def init(db):
    with db:
        db.execute("""
            CREATE TABLE IF NOT EXISTS dns_rotations (
                id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER NOT NULL,
                zone_id TEXT NOT NULL, record_id TEXT NOT NULL, name TEXT NOT NULL,
                kind TEXT NOT NULL, expected TEXT NOT NULL, steps TEXT NOT NULL,
                due_at INTEGER NOT NULL, attempts INTEGER NOT NULL DEFAULT 0,
                status TEXT NOT NULL DEFAULT 'active', note TEXT NOT NULL DEFAULT ''
            )
        """)
        if "account_id" not in {col[1] for col in db.execute("PRAGMA table_info(dns_rotations)")}:
            db.execute("ALTER TABLE dns_rotations ADD COLUMN account_id INTEGER REFERENCES cloudflare_profiles(id)")
        db.execute("""
            CREATE UNIQUE INDEX IF NOT EXISTS dns_rotations_active
            ON dns_rotations (zone_id, record_id) WHERE status = 'active'
        """)
        db.execute("""
            CREATE INDEX IF NOT EXISTS dns_rotations_due ON dns_rotations (status, due_at)
        """)


def schedule(db, user_id, zone_id, record, steps, account_id=None):
    due_at = int(time.time()) + steps[0][0]
    with db:
        return db.execute("""
            INSERT INTO dns_rotations (user_id, zone_id, record_id, name, kind, expected, steps, due_at, account_id)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (user_id, zone_id, record["id"], record["name"], record["type"], record["content"],
              json.dumps(steps, separators=(",", ":")), due_at, account_id)).lastrowid


def for_zone(db, user_id, zone_id, account_id=None):
    return db.execute(
        "SELECT id, name, status FROM dns_rotations WHERE user_id = ? AND zone_id = ? AND account_id IS ? ORDER BY id DESC",
        (user_id, zone_id, account_id),
    ).fetchall()


def get(db, user_id, rotation_id):
    row = db.execute("SELECT * FROM dns_rotations WHERE user_id = ? AND id = ?", (user_id, rotation_id)).fetchone()
    return Rotation(*row) if row else None


def due(db):
    return db.execute("""
        SELECT user_id, id FROM dns_rotations
        WHERE status = 'active' AND due_at <= ? ORDER BY due_at, id LIMIT 10
    """, (int(time.time()),)).fetchall()


def stop(db, rotation, status, note=""):
    with db:
        db.execute(
            "UPDATE dns_rotations SET status = ?, note = ? WHERE id = ? AND status = 'active'",
            (status, note, rotation.id),
        )


def delete(db, user_id, zone_id, rotation_id, account_id=None):
    with db:
        result = db.execute(
            "DELETE FROM dns_rotations WHERE user_id = ? AND zone_id = ? AND id = ? AND account_id IS ?",
            (user_id, zone_id, rotation_id, account_id),
        )
    return result.rowcount == 1


def retry(db, rotation):
    attempts = rotation.attempts + 1
    if attempts >= MAX_RETRIES:
        stop(db, rotation, "failed", "Cloudflare پس از چند تلاش پاسخ موفق نداد.")
        return
    with db:
        db.execute(
            "UPDATE dns_rotations SET attempts = ?, due_at = ? WHERE id = ?",
            (attempts, int(time.time()) + 60 * 2**(attempts - 1), rotation.id),
        )


def read_steps(rotation):
    steps = json.loads(rotation.steps)
    if rotation.kind not in {"A", "AAAA"} or not isinstance(steps, list):
        raise ValueError
    for step in steps:
        if not isinstance(step, list) or len(step) != 2:
            raise ValueError
        delay, target = step
        if type(delay) is not int or not 1 <= delay <= MAX_DELAY or not isinstance(target, str):
            raise ValueError
        if cloudflare.destination(target, rotation.kind) != target:
            raise ValueError
    if rotation.status == "active" and not steps:
        raise ValueError
    return steps


async def apply_step(db, rotation, token):
    if not token:
        stop(db, rotation, "failed", "توکن Cloudflare در دسترس نیست.")
        return
    try:
        steps = read_steps(rotation)
        _, target = steps[0]
    except (IndexError, TypeError, ValueError):
        stop(db, rotation, "failed", "اطلاعات مرحله نامعتبر است.")
        return

    try:
        record = await cloudflare.record(token, rotation.zone_id, rotation.record_id)
        if record.get("type") != rotation.kind or record.get("name") != rotation.name:
            stop(db, rotation, "failed", "نام یا نوع رکورد از زمان برنامه‌ریزی تغییر کرده است.")
            return
        try:
            current = cloudflare.destination(record.get("content") or "", rotation.kind)
        except ValueError:
            stop(db, rotation, "failed", "مقدار فعلی رکورد معتبر نیست.")
            return
        if current != target:
            if current != rotation.expected:
                stop(db, rotation, "failed", "IP رکورد خارج از این برنامه تغییر کرده است.")
                return
            path = cloudflare.records_path(rotation.zone_id, rotation.record_id)
            response = await cloudflare.request("PATCH", path, token, payload={"content": target})
            result = response.get("result")
            if not isinstance(result, dict) or result.get("id") != rotation.record_id:
                raise cloudflare.APIError()
            try:
                if cloudflare.destination(result.get("content") or "", rotation.kind) != target:
                    raise cloudflare.APIError()
            except ValueError:
                raise cloudflare.APIError() from None
    except cloudflare.APIError as exc:
        if exc.status is None or exc.status >= 500 or exc.status == 429:
            retry(db, rotation)
        else:
            stop(db, rotation, "failed", f"Cloudflare تغییر را نپذیرفت (HTTP {exc.status}).")
        return

    remaining = steps[1:]
    with db:
        db.execute("""
            UPDATE dns_rotations SET expected = ?, steps = ?, due_at = ?, attempts = 0, status = ?
            WHERE id = ?
        """, (target, json.dumps(remaining, separators=(",", ":")),
              int(time.time()) + remaining[0][0] if remaining else rotation.due_at,
              "active" if remaining else "done", rotation.id))
