from __future__ import annotations

import json
import sqlite3
from pathlib import Path
from threading import Lock
from typing import Any

from honeypot.models import HoneypotEvent, PortConfig, Protocol

SCHEMA = """
CREATE TABLE IF NOT EXISTS meta (
  key TEXT PRIMARY KEY,
  value TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS events (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  ts TEXT NOT NULL,
  event_id TEXT NOT NULL UNIQUE,
  conn_id TEXT NOT NULL,
  src_ip TEXT NOT NULL,
  src_port INTEGER NOT NULL,
  dst_port INTEGER NOT NULL,
  configured_primary TEXT NOT NULL,
  detected_protocol TEXT NOT NULL,
  event_type TEXT NOT NULL,
  username TEXT,
  password TEXT,
  auth_scheme TEXT,
  http_method TEXT,
  http_target TEXT,
  tls INTEGER NOT NULL DEFAULT 0,
  client_first_bytes_hex TEXT,
  extra_json TEXT
);

CREATE INDEX IF NOT EXISTS idx_events_ts ON events(ts);
CREATE INDEX IF NOT EXISTS idx_events_src_ip ON events(src_ip, ts);
CREATE INDEX IF NOT EXISTS idx_events_dst_port ON events(dst_port, ts);
CREATE INDEX IF NOT EXISTS idx_events_type ON events(event_type);
CREATE INDEX IF NOT EXISTS idx_events_creds ON events(username, password);

CREATE TABLE IF NOT EXISTS credentials (
  username TEXT NOT NULL,
  password TEXT NOT NULL,
  hit_count INTEGER NOT NULL DEFAULT 0,
  first_seen TEXT NOT NULL,
  last_seen TEXT NOT NULL,
  ports_json TEXT NOT NULL DEFAULT '{}',
  protocols_json TEXT NOT NULL DEFAULT '{}',
  src_ip_count INTEGER NOT NULL DEFAULT 0,
  src_ips_json TEXT NOT NULL DEFAULT '{}',
  PRIMARY KEY (username, password)
);

CREATE TABLE IF NOT EXISTS sources (
  src_ip TEXT PRIMARY KEY,
  first_seen TEXT NOT NULL,
  last_seen TEXT NOT NULL,
  conn_count INTEGER NOT NULL DEFAULT 0,
  auth_count INTEGER NOT NULL DEFAULT 0,
  ports_json TEXT NOT NULL DEFAULT '{}',
  protocols_json TEXT NOT NULL DEFAULT '{}',
  last_username TEXT,
  last_password TEXT
);

CREATE TABLE IF NOT EXISTS port_stats_daily (
  day TEXT NOT NULL,
  dst_port INTEGER NOT NULL,
  connects INTEGER NOT NULL DEFAULT 0,
  auths INTEGER NOT NULL DEFAULT 0,
  unique_ips INTEGER NOT NULL DEFAULT 0,
  unique_creds INTEGER NOT NULL DEFAULT 0,
  PRIMARY KEY (day, dst_port)
);

CREATE TABLE IF NOT EXISTS ports (
  port INTEGER PRIMARY KEY,
  primary_proto TEXT NOT NULL,
  also_accept_json TEXT NOT NULL DEFAULT '[]',
  enabled INTEGER NOT NULL DEFAULT 1,
  note TEXT NOT NULL DEFAULT '',
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  source TEXT NOT NULL DEFAULT 'config'
);
"""


class SqliteStore:
    def __init__(self, path: Path) -> None:
        self.path = path
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = Lock()
        self._conn = sqlite3.connect(str(path), check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self._conn.execute("PRAGMA journal_mode=WAL;")
        self._conn.execute("PRAGMA synchronous=NORMAL;")
        self._init_schema()

    def _init_schema(self) -> None:
        with self._lock:
            self._conn.executescript(SCHEMA)
            self._conn.execute(
                "INSERT OR REPLACE INTO meta(key, value) VALUES(?, ?)",
                ("schema_version", "1"),
            )
            self._conn.commit()

    def close(self) -> None:
        with self._lock:
            self._conn.close()

    def write_event(self, event: HoneypotEvent) -> None:
        with self._lock:
            self._conn.execute(
                """
                INSERT OR IGNORE INTO events(
                  ts, event_id, conn_id, src_ip, src_port, dst_port,
                  configured_primary, detected_protocol, event_type,
                  username, password, auth_scheme, http_method, http_target,
                  tls, client_first_bytes_hex, extra_json
                ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
                """,
                (
                    event.ts,
                    event.event_id,
                    event.conn_id,
                    event.src_ip,
                    event.src_port,
                    event.dst_port,
                    event.configured_primary,
                    event.detected_protocol,
                    event.event_type,
                    event.username,
                    event.password,
                    event.auth_scheme,
                    event.http_method,
                    event.http_target,
                    1 if event.tls else 0,
                    event.client_first_bytes_hex,
                    json.dumps(event.extra, ensure_ascii=False),
                ),
            )
            self._upsert_source(event)
            if event.event_type == "auth" and (event.username is not None or event.password is not None):
                self._upsert_credential(event)
            self._bump_daily(event)
            self._conn.commit()

    def _json_counter_bump(self, raw: str, key: str, n: int = 1) -> str:
        data = json.loads(raw or "{}")
        data[str(key)] = int(data.get(str(key), 0)) + n
        return json.dumps(data, ensure_ascii=False)

    def _upsert_source(self, event: HoneypotEvent) -> None:
        row = self._conn.execute("SELECT * FROM sources WHERE src_ip=?", (event.src_ip,)).fetchone()
        is_connect = event.event_type == "connect"
        is_auth = event.event_type == "auth"
        if row is None:
            ports = {str(event.dst_port): 1}
            protos = {event.detected_protocol: 1} if event.detected_protocol else {}
            self._conn.execute(
                """
                INSERT INTO sources(
                  src_ip, first_seen, last_seen, conn_count, auth_count,
                  ports_json, protocols_json, last_username, last_password
                ) VALUES (?,?,?,?,?,?,?,?,?)
                """,
                (
                    event.src_ip,
                    event.ts,
                    event.ts,
                    1 if is_connect else 0,
                    1 if is_auth else 0,
                    json.dumps(ports),
                    json.dumps(protos),
                    event.username if is_auth else None,
                    event.password if is_auth else None,
                ),
            )
            return

        ports_json = self._json_counter_bump(row["ports_json"], str(event.dst_port))
        protos_json = self._json_counter_bump(row["protocols_json"], event.detected_protocol or "unknown")
        self._conn.execute(
            """
            UPDATE sources SET
              last_seen=?,
              conn_count=conn_count + ?,
              auth_count=auth_count + ?,
              ports_json=?,
              protocols_json=?,
              last_username=CASE WHEN ? THEN ? ELSE last_username END,
              last_password=CASE WHEN ? THEN ? ELSE last_password END
            WHERE src_ip=?
            """,
            (
                event.ts,
                1 if is_connect else 0,
                1 if is_auth else 0,
                ports_json,
                protos_json,
                1 if is_auth else 0,
                event.username,
                1 if is_auth else 0,
                event.password,
                event.src_ip,
            ),
        )

    def _upsert_credential(self, event: HoneypotEvent) -> None:
        user = event.username or ""
        password = event.password or ""
        row = self._conn.execute(
            "SELECT * FROM credentials WHERE username=? AND password=?",
            (user, password),
        ).fetchone()
        if row is None:
            ports = {str(event.dst_port): 1}
            protos = {event.detected_protocol: 1}
            ips = {event.src_ip: 1}
            self._conn.execute(
                """
                INSERT INTO credentials(
                  username, password, hit_count, first_seen, last_seen,
                  ports_json, protocols_json, src_ip_count, src_ips_json
                ) VALUES (?,?,1,?,?,?,?,1,?)
                """,
                (
                    user,
                    password,
                    event.ts,
                    event.ts,
                    json.dumps(ports),
                    json.dumps(protos),
                    json.dumps(ips),
                ),
            )
            return

        ports_json = self._json_counter_bump(row["ports_json"], str(event.dst_port))
        protos_json = self._json_counter_bump(row["protocols_json"], event.detected_protocol or "unknown")
        ips = json.loads(row["src_ips_json"] or "{}")
        if event.src_ip not in ips:
            ips[event.src_ip] = 0
        ips[event.src_ip] = int(ips[event.src_ip]) + 1
        self._conn.execute(
            """
            UPDATE credentials SET
              hit_count=hit_count+1,
              last_seen=?,
              ports_json=?,
              protocols_json=?,
              src_ip_count=?,
              src_ips_json=?
            WHERE username=? AND password=?
            """,
            (
                event.ts,
                ports_json,
                protos_json,
                len(ips),
                json.dumps(ips, ensure_ascii=False),
                user,
                password,
            ),
        )

    def _bump_daily(self, event: HoneypotEvent) -> None:
        day = event.ts[:10]
        row = self._conn.execute(
            "SELECT * FROM port_stats_daily WHERE day=? AND dst_port=?",
            (day, event.dst_port),
        ).fetchone()
        if row is None:
            self._conn.execute(
                """
                INSERT INTO port_stats_daily(day, dst_port, connects, auths, unique_ips, unique_creds)
                VALUES (?,?,?,?,0,0)
                """,
                (
                    day,
                    event.dst_port,
                    1 if event.event_type == "connect" else 0,
                    1 if event.event_type == "auth" else 0,
                ),
            )
            return
        self._conn.execute(
            """
            UPDATE port_stats_daily SET
              connects=connects + ?,
              auths=auths + ?
            WHERE day=? AND dst_port=?
            """,
            (
                1 if event.event_type == "connect" else 0,
                1 if event.event_type == "auth" else 0,
                day,
                event.dst_port,
            ),
        )

    # --- ports config ---

    def upsert_port(self, cfg: PortConfig, source: str = "config") -> None:
        from honeypot.models import utc_now_iso

        now = utc_now_iso()
        also = json.dumps([p.value for p in cfg.also_accept])
        with self._lock:
            existing = self._conn.execute("SELECT port FROM ports WHERE port=?", (cfg.port,)).fetchone()
            if existing:
                self._conn.execute(
                    """
                    UPDATE ports SET primary_proto=?, also_accept_json=?, enabled=?, note=?, updated_at=?,
                      source=CASE WHEN source='runtime' AND ?='config' THEN source ELSE ? END
                    WHERE port=?
                    """,
                    (
                        cfg.primary.value,
                        also,
                        1 if cfg.enabled else 0,
                        cfg.note,
                        now,
                        source,
                        source,
                        cfg.port,
                    ),
                )
            else:
                self._conn.execute(
                    """
                    INSERT INTO ports(port, primary_proto, also_accept_json, enabled, note, created_at, updated_at, source)
                    VALUES (?,?,?,?,?,?,?,?)
                    """,
                    (
                        cfg.port,
                        cfg.primary.value,
                        also,
                        1 if cfg.enabled else 0,
                        cfg.note,
                        now,
                        now,
                        source,
                    ),
                )
            self._conn.commit()

    def set_port_enabled(self, port: int, enabled: bool) -> None:
        from honeypot.models import utc_now_iso

        with self._lock:
            self._conn.execute(
                "UPDATE ports SET enabled=?, updated_at=? WHERE port=?",
                (1 if enabled else 0, utc_now_iso(), port),
            )
            self._conn.commit()

    def list_ports(self) -> list[PortConfig]:
        with self._lock:
            rows = self._conn.execute("SELECT * FROM ports ORDER BY port").fetchall()
        out: list[PortConfig] = []
        for r in rows:
            also = [Protocol(x) for x in json.loads(r["also_accept_json"] or "[]")]
            out.append(
                PortConfig(
                    port=int(r["port"]),
                    primary=Protocol(r["primary_proto"]),
                    also_accept=also,
                    enabled=bool(r["enabled"]),
                    note=r["note"] or "",
                )
            )
        return out

    def get_port(self, port: int) -> PortConfig | None:
        with self._lock:
            r = self._conn.execute("SELECT * FROM ports WHERE port=?", (port,)).fetchone()
        if not r:
            return None
        also = [Protocol(x) for x in json.loads(r["also_accept_json"] or "[]")]
        return PortConfig(
            port=int(r["port"]),
            primary=Protocol(r["primary_proto"]),
            also_accept=also,
            enabled=bool(r["enabled"]),
            note=r["note"] or "",
        )

    def delete_port(self, port: int) -> None:
        with self._lock:
            self._conn.execute("DELETE FROM ports WHERE port=?", (port,))
            self._conn.commit()

    # --- queries for web / export ---

    def query(self, sql: str, params: tuple[Any, ...] = ()) -> list[sqlite3.Row]:
        with self._lock:
            cur = self._conn.execute(sql, params)
            return cur.fetchall()

    def summary_stats(self, since_ts: str | None = None) -> dict[str, Any]:
        with self._lock:
            if since_ts:
                connects = self._conn.execute(
                    "SELECT COUNT(*) AS c FROM events WHERE ts>=? AND event_type='connect'",
                    (since_ts,),
                ).fetchone()["c"]
                auths = self._conn.execute(
                    "SELECT COUNT(*) AS c FROM events WHERE ts>=? AND event_type='auth'",
                    (since_ts,),
                ).fetchone()["c"]
                ips = self._conn.execute(
                    "SELECT COUNT(DISTINCT src_ip) AS c FROM events WHERE ts>=?",
                    (since_ts,),
                ).fetchone()["c"]
                creds = self._conn.execute(
                    "SELECT COUNT(*) AS c FROM credentials WHERE last_seen>=?",
                    (since_ts,),
                ).fetchone()["c"]
            else:
                connects = self._conn.execute(
                    "SELECT COUNT(*) AS c FROM events WHERE event_type='connect'"
                ).fetchone()["c"]
                auths = self._conn.execute(
                    "SELECT COUNT(*) AS c FROM events WHERE event_type='auth'"
                ).fetchone()["c"]
                ips = self._conn.execute(
                    "SELECT COUNT(DISTINCT src_ip) AS c FROM events"
                ).fetchone()["c"]
                creds = self._conn.execute("SELECT COUNT(*) AS c FROM credentials").fetchone()["c"]
        return {
            "connects": connects,
            "auths": auths,
            "unique_ips": ips,
            "credentials": creds,
        }

    def top_credentials(self, limit: int = 100) -> list[dict[str, Any]]:
        rows = self.query(
            """
            SELECT username, password, hit_count, first_seen, last_seen,
                   ports_json, protocols_json, src_ip_count
            FROM credentials
            ORDER BY hit_count DESC, last_seen DESC
            LIMIT ?
            """,
            (limit,),
        )
        return [dict(r) for r in rows]

    def recent_events(self, limit: int = 100, event_type: str | None = None) -> list[dict[str, Any]]:
        if event_type:
            rows = self.query(
                """
                SELECT ts, src_ip, src_port, dst_port, detected_protocol, event_type,
                       username, password, auth_scheme, http_method, http_target
                FROM events WHERE event_type=?
                ORDER BY id DESC LIMIT ?
                """,
                (event_type, limit),
            )
        else:
            rows = self.query(
                """
                SELECT ts, src_ip, src_port, dst_port, detected_protocol, event_type,
                       username, password, auth_scheme, http_method, http_target
                FROM events
                ORDER BY id DESC LIMIT ?
                """,
                (limit,),
            )
        return [dict(r) for r in rows]

    def list_sources(self, limit: int = 100) -> list[dict[str, Any]]:
        rows = self.query(
            """
            SELECT src_ip, first_seen, last_seen, conn_count, auth_count,
                   ports_json, protocols_json, last_username, last_password
            FROM sources
            ORDER BY last_seen DESC
            LIMIT ?
            """,
            (limit,),
        )
        return [dict(r) for r in rows]
