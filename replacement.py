import time
from typing import NamedTuple

PROVIDERS = {"hetzner": "Hetzner", "linode": "Linode", "kamatera": "Kamatera", "vultr": "Vultr", "cherry": "Cherry"}
REGION_KEY = {"hetzner": "location", "kamatera": "datacenter"}
NAME_KEY = {"hetzner": "name", "kamatera": "name", "cherry": "hostname"}
TERMINAL = {"done", "failed", "cancelled"}
POLL = 60


class Rule(NamedTuple):
    id: int
    user_id: int
    rotation_id: int
    target: str
    provider: str
    account_id: int | None
    project_id: int | None
    recipe: bytes | None
    old_id: str | None
    state: str
    next_at: int
    remote_id: str | None
    deadline: int
    evidence: int
    note: str


def init(db):
    with db:
        db.execute("""
            CREATE TABLE IF NOT EXISTS node_replacements (
                id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER NOT NULL,
                rotation_id INTEGER NOT NULL, target TEXT NOT NULL, provider TEXT NOT NULL,
                account_id INTEGER, project_id INTEGER, recipe BLOB, old_id TEXT,
                state TEXT NOT NULL, next_at INTEGER NOT NULL, remote_id TEXT,
                deadline INTEGER NOT NULL, evidence INTEGER NOT NULL DEFAULT 0, note TEXT NOT NULL DEFAULT ''
            )
        """)
        db.execute("""
            CREATE UNIQUE INDEX IF NOT EXISTS node_replacements_active
            ON node_replacements(rotation_id, target)
            WHERE state NOT IN ('done', 'failed', 'cancelled')
        """)
        db.execute("CREATE INDEX IF NOT EXISTS node_replacements_due ON node_replacements(state, next_at)")


def add(db, user_id, rotation, target, provider, account, project, recipe, old_id, interval):
    now = int(time.time())
    with db:
        db.execute("""
            INSERT INTO node_replacements
                (user_id, rotation_id, target, provider, account_id, project_id, recipe, old_id, state, next_at, deadline)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'watching', ?, ?)
        """, (user_id, rotation, target, provider, account, project, recipe, old_id, now + interval, now + interval))


def for_user(db, user_id):
    return db.execute(
        "SELECT id, target, provider, state FROM node_replacements WHERE user_id = ? ORDER BY id DESC",
        (user_id,),
    ).fetchall()


def get(db, user_id, rule_id):
    row = db.execute("SELECT * FROM node_replacements WHERE user_id = ? AND id = ?", (user_id, rule_id)).fetchone()
    return Rule(*row) if row else None


def due(db):
    return [Rule(*row) for row in db.execute("""
        SELECT * FROM node_replacements WHERE next_at <= ?
        AND state NOT IN ('done', 'failed', 'cancelled') ORDER BY next_at, id LIMIT 6
    """, (int(time.time()),))]


def update(db, rule, **changes):
    # A restore or cancellation may have changed this row while the API call was running.
    if get(db, rule.user_id, rule.id) != rule:
        return None
    fields = rule._replace(**changes)
    with db:
        db.execute("""
            UPDATE node_replacements SET recipe = ?, state = ?, next_at = ?, remote_id = ?,
                deadline = ?, evidence = ?, note = ? WHERE id = ?
        """, (fields.recipe, fields.state, fields.next_at, fields.remote_id, fields.deadline,
              fields.evidence, fields.note, rule.id))
    return fields
