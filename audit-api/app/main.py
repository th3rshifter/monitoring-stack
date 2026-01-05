import asyncio
import json
import os
from contextlib import asynccontextmanager
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from io import BytesIO
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlencode

import httpx
import pandas as pd
from fastapi import FastAPI, Request
from fastapi.encoders import jsonable_encoder
from fastapi.responses import HTMLResponse, PlainTextResponse, JSONResponse, Response
from jinja2 import Environment, BaseLoader, select_autoescape
from openpyxl.utils import get_column_letter
from pydantic import BaseModel, Field, ValidationError, ConfigDict
from sqlalchemy import text
from sqlalchemy.ext.asyncio import create_async_engine


# ------------------------
# Configuration
# ------------------------

DATABASE_URL = os.getenv("DATABASE_URL")
PROM_URL = os.getenv("PROM_URL", "http://prometheus:9090").rstrip("/")
LOKI_URL = os.getenv("LOKI_URL", "http://loki:3100").rstrip("/")
WINDOW_MINUTES = int(os.getenv("REPORT_WINDOW_MINUTES", "60"))
PROCESS_EXPORTER_PORT = int(os.getenv("PROCESS_EXPORTER_PORT", "9256"))

if not DATABASE_URL:
    raise RuntimeError("DATABASE_URL is not set")

engine = create_async_engine(DATABASE_URL, pool_pre_ping=True)


# ------------------------
# Shared HTTP client
# ------------------------

@asynccontextmanager
async def lifespan(app: FastAPI):
    app.state.http = httpx.AsyncClient(timeout=httpx.Timeout(20.0))
    try:
        yield
    finally:
        await app.state.http.aclose()


app = FastAPI(title="IT-Monitor Incident Center", lifespan=lifespan)


# ------------------------
# Jinja2
# ------------------------

jinja = Environment(
    loader=BaseLoader(),
    autoescape=select_autoescape(enabled_extensions=("html", "xml")),
)


# ------------------------
# Pydantic models
# ------------------------

class AlertLabels(BaseModel):
    alertname: Optional[str] = None
    instance: Optional[str] = None
    job: Optional[str] = None
    severity: Optional[str] = None


class AlertAnnotations(BaseModel):
    model_config = ConfigDict(extra="allow")
    summary: Optional[str] = None
    description: Optional[str] = None
    message: Optional[str] = None


class AlertItem(BaseModel):
    status: Optional[str] = None
    labels: AlertLabels = Field(default_factory=AlertLabels)
    annotations: AlertAnnotations = Field(default_factory=AlertAnnotations)
    startsAt: Optional[str] = None
    endsAt: Optional[str] = None
    fingerprint: Optional[str] = None
    generatorURL: Optional[str] = None


class AlertmanagerPayload(BaseModel):
    receiver: Optional[str] = None
    status: Optional[str] = None
    groupKey: Optional[str] = None
    version: Optional[str] = None
    externalURL: Optional[str] = None
    alerts: List[AlertItem] = Field(default_factory=list)


# ------------------------
# Helpers: json/time/html
# ------------------------
def _json_dumps(obj: Any) -> str:
    return json.dumps(obj, ensure_ascii=False, default=str)


def _ensure_json(v: Any) -> Any:
    if v is None:
        return None
    if isinstance(v, (dict, list, int, float, bool)):
        return v
    if isinstance(v, str):
        s = v.strip()
        if (s.startswith("{") and s.endswith("}")) or (s.startswith("[") and s.endswith("]")):
            try:
                return json.loads(s)
            except Exception:
                return v
        return v
    try:
        return json.loads(json.dumps(v, default=str, ensure_ascii=False))
    except Exception:
        return str(v)


def _esc(s: Any) -> str:
    if s is None:
        return ""
    x = str(s)
    return (
        x.replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace('"', "&quot;")
    )


def _fmt_num(v: Any, nd: int = 2) -> str:
    if v is None:
        return "n/a"
    try:
        return f"{float(v):.{nd}f}"
    except Exception:
        return "n/a"


def _parse_iso_to_dt(s: Optional[str]) -> Optional[datetime]:
    if not s:
        return None
    try:
        x = s.replace("Z", "+00:00")
        dt = datetime.fromisoformat(x)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt.astimezone(timezone.utc)
    except Exception:
        return None


def _fmt_dt_ui(dt: Any) -> str:
    """DD.MM.YYYY HH:MM:SS UTC"""
    if dt is None:
        return "—"
    try:
        if isinstance(dt, str):
            p = _parse_iso_to_dt(dt)
            if p:
                dt = p
        if isinstance(dt, datetime):
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            dt = dt.astimezone(timezone.utc)
            return dt.strftime("%d.%m.%Y %H:%M:%S UTC")
        return str(dt)
    except Exception:
        return str(dt)


def _ts_ui(ts: Any) -> str:
    try:
        if ts is None:
            return "n/a"
        dt = datetime.fromtimestamp(float(ts), tz=timezone.utc)
        return dt.strftime("%d.%m.%Y %H:%M:%S UTC")
    except Exception:
        return "n/a"


def _instance_host(instance: str) -> str:
    if not instance:
        return instance
    return instance.split(":")[0]


def _replace_port(instance: str, new_port: int) -> str:
    host = _instance_host(instance)
    return f"{host}:{new_port}" if host else instance


# ------------------------
# Prometheus / Loki clients
# ------------------------
async def prom_query(app: FastAPI, query: str) -> Dict[str, Any]:
    r = await app.state.http.get(f"{PROM_URL}/api/v1/query", params={"query": query})
    r.raise_for_status()
    return r.json()


async def prom_query_range(app: FastAPI, query: str, start: datetime, end: datetime, step: int = 60) -> Dict[str, Any]:
    params = {"query": query, "start": start.timestamp(), "end": end.timestamp(), "step": step}
    r = await app.state.http.get(f"{PROM_URL}/api/v1/query_range", params=params)
    r.raise_for_status()
    return r.json()


async def loki_query_range(app: FastAPI, query: str, start: datetime, end: datetime, limit: int = 80) -> Dict[str, Any]:
    params = {
        "query": query,
        "start": int(start.timestamp() * 1_000_000_000),
        "end": int(end.timestamp() * 1_000_000_000),
        "limit": limit,
        "direction": "BACKWARD",
    }
    r = await app.state.http.get(f"{LOKI_URL}/loki/api/v1/query_range", params=params, timeout=httpx.Timeout(25.0))
    r.raise_for_status()
    return r.json()


async def _fill_job_from_prom(app: FastAPI, instance: Optional[str], job: Optional[str]) -> Optional[str]:
    if job or not instance:
        return job
    try:
        q = f'max by (job) (up{{instance="{instance}"}})'
        j = await prom_query(app, q)
        res = j.get("data", {}).get("result", [])
        if not res:
            return job
        metric = res[0].get("metric", {}) or {}
        return metric.get("job") or job
    except Exception:
        return job


def last_value(query_range_json: Dict[str, Any]) -> Optional[float]:
    try:
        res = query_range_json.get("data", {}).get("result", [])
        if not res:
            return None
        values = res[0].get("values") or []
        if not values:
            return None
        return float(values[-1][1])
    except Exception:
        return None


def _series_stats(matrix_json: Any) -> Dict[str, Any]:
    try:
        data = (matrix_json or {}).get("data", {})
        res = data.get("result", [])
        if not res:
            return {}
        values = res[0].get("values") or []
        if not values:
            return {}

        pts: List[Tuple[float, float]] = []
        for t, v in values:
            if v is None:
                continue
            try:
                pts.append((float(t), float(v)))
            except Exception:
                continue

        if not pts:
            return {}

        vs = [v for _, v in pts]
        vmin = min(vs)
        vmax = max(vs)
        vavg = sum(vs) / len(vs)
        peak_t = max(pts, key=lambda x: x[1])[0]
        min_t = min(pts, key=lambda x: x[1])[0]
        return {
            "min": vmin,
            "avg": vavg,
            "max": vmax,
            "first_ts": pts[0][0],
            "last_ts": pts[-1][0],
            "peak_ts": peak_t,
            "min_ts": min_t,
        }
    except Exception:
        return {}


def vector_to_toplist(query_json: Dict[str, Any]) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    try:
        for item in query_json.get("data", {}).get("result", []):
            metric = item.get("metric", {}) or {}
            val = item.get("value") or [None, None]
            value = float(val[1]) if val[1] is not None else None
            name = (
                metric.get("groupname")
                or metric.get("namegroup")
                or metric.get("comm")
                or metric.get("process")
                or "unknown"
            )
            out.append({"name": name, "value": value, "metric": metric})
    except Exception:
        return []
    return out


# ------------------------
# Generic context collection
# ------------------------
def _classify_alert(alertname: str) -> str:
    a = (alertname or "").lower()
    if any(x in a for x in ["cpu", "load"]):
        return "cpu"
    if any(x in a for x in ["mem", "memory", "ram", "oom"]):
        return "mem"
    if any(x in a for x in ["disk", "filesystem", "inode", "fs"]):
        return "disk"
    if any(x in a for x in ["down", "targetdown", "unreachable", "instancedown"]):
        return "down"
    if any(x in a for x in ["http", "5xx", "latency", "request"]):
        return "http"
    return "generic"


def _incident_key(fingerprint: Optional[str], alertname: str, job: Optional[str], instance: Optional[str]) -> str:
    if fingerprint:
        return fingerprint
    return f"{alertname}|{job or ''}|{instance or ''}"


def _root_cause_from_metrics(metrics: Dict[str, Any]) -> Dict[str, Any]:
    metrics = metrics or {}
    tp = (metrics.get("top_processes") or {})
    cpu_list = tp.get("cpu_top5_5m") or []
    mem_list = tp.get("mem_top5_rss") or []

    out: Dict[str, Any] = {"cpu": None, "mem": None}
    if cpu_list and isinstance(cpu_list[0], dict):
        out["cpu"] = {"groupname": cpu_list[0].get("name"), "cpu_sec_per_s": cpu_list[0].get("value")}
    if mem_list and isinstance(mem_list[0], dict):
        out["mem"] = {"groupname": mem_list[0].get("name"), "rss_bytes": mem_list[0].get("value")}
    return out


def _make_notes_from_window(metrics: Dict[str, Any]) -> List[str]:
    notes: List[str] = []
    if not isinstance(metrics, dict):
        return notes

    cpuw = metrics.get("cpu_pct_window") or {}
    memw = metrics.get("mem_avail_pct_window") or {}
    diskw = metrics.get("disk_free_pct_window") or {}

    if isinstance(cpuw, dict) and cpuw.get("max") is not None:
        notes.append(
            f"CPU окно: min={_fmt_num(cpuw.get('min'))}% avg={_fmt_num(cpuw.get('avg'))}% max={_fmt_num(cpuw.get('max'))}% (пик {_ts_ui(cpuw.get('peak_ts'))})."
        )
    if isinstance(memw, dict) and memw.get("min") is not None:
        notes.append(
            f"MemAvailable окно: min={_fmt_num(memw.get('min'))}% avg={_fmt_num(memw.get('avg'))}% max={_fmt_num(memw.get('max'))}% (минимум {_ts_ui(memw.get('min_ts'))})."
        )
    if isinstance(diskw, dict) and diskw.get("min") is not None:
        notes.append(
            f"Disk free окно: min={_fmt_num(diskw.get('min'))}% avg={_fmt_num(diskw.get('avg'))}% max={_fmt_num(diskw.get('max'))}%."
        )
    return notes


def _recommendations_from_annotations(ann: Dict[str, Any]) -> List[str]:
    """
    Priority:
      1) annotations.actions / annotations.recommendations (preferred)
      2) annotations.message / annotations.description (fallback)
    Supports:
      - multiline text (one item per line)
      - JSON list (["..",".."])
    """
    if not isinstance(ann, dict):
        return []

    preferred = ann.get("actions") or ann.get("recommendations")
    if preferred:
        return _split_reco_blob(preferred)

    fallback = ann.get("message") or ann.get("description") or ""
    if fallback:
        return _split_reco_blob(fallback)

    return []


def _split_reco_blob(blob: Any) -> List[str]:
    if isinstance(blob, list):
        out = [str(x).strip() for x in blob if str(x).strip()]
        return _dedup_keep_order(out)

    s = str(blob).strip()
    if not s:
        return []

    if s.startswith("[") and s.endswith("]"):
        try:
            arr = json.loads(s)
            if isinstance(arr, list):
                out = [str(x).strip() for x in arr if str(x).strip()]
                return _dedup_keep_order(out)
        except Exception:
            pass

    lines = []
    for ln in s.splitlines():
        x = ln.strip()
        if not x:
            continue
        x = x.lstrip("-•\t ")
        # also remove "1) " / "1. "
        x = x.lstrip("0123456789").lstrip("). ").strip()
        if x:
            lines.append(x)

    return _dedup_keep_order(lines)


def _dedup_keep_order(items: List[str]) -> List[str]:
    seen = set()
    out = []
    for x in items:
        if x not in seen:
            out.append(x)
            seen.add(x)
    return out


async def build_metrics_snapshot(
    app: FastAPI,
    instance_node_exporter: str,
    start: datetime,
    end: datetime,
    want_process_top: bool,
) -> Dict[str, Any]:
    cpu_q = f'100 - (avg(rate(node_cpu_seconds_total{{mode="idle", instance="{instance_node_exporter}"}}[5m])) * 100)'
    mem_q = (
        f'(node_memory_MemAvailable_bytes{{instance="{instance_node_exporter}"}} / '
        f'node_memory_MemTotal_bytes{{instance="{instance_node_exporter}"}}) * 100'
    )
    disk_q = (
        f'min((node_filesystem_avail_bytes{{instance="{instance_node_exporter}", fstype!~"tmpfs|overlay|squashfs"}} '
        f'/ node_filesystem_size_bytes{{instance="{instance_node_exporter}", fstype!~"tmpfs|overlay|squashfs"}}) * 100)'
    )

    cpu, mem, disk = await asyncio.gather(
        prom_query_range(app, cpu_q, start, end),
        prom_query_range(app, mem_q, start, end),
        prom_query_range(app, disk_q, start, end),
    )

    out: Dict[str, Any] = {
        "window_minutes": WINDOW_MINUTES,
        "instance_node_exporter": instance_node_exporter,
        "cpu_pct_last": last_value(cpu),
        "mem_avail_pct_last": last_value(mem),
        "disk_free_pct_last": last_value(disk),
        "cpu_pct_window": _series_stats(cpu),
        "mem_avail_pct_window": _series_stats(mem),
        "disk_free_pct_window": _series_stats(disk),
        "raw": {"cpu": cpu, "mem": mem, "disk": disk},
    }

    if want_process_top:
        proc_instance = _replace_port(instance_node_exporter, PROCESS_EXPORTER_PORT)
        out["process_exporter_instance"] = proc_instance
        out["top_processes"] = {}

        tasks = [
            (
                "cpu_top5_5m",
                f'topk(5, sum by (groupname) (rate(namedprocess_namegroup_cpu_seconds_total{{instance="{proc_instance}"}}[5m])))',
            ),
            (
                "mem_top5_rss",
                f'topk(5, sum by (groupname) (namedprocess_namegroup_memory_bytes{{instance="{proc_instance}"}}))',
            ),
        ]

        async def _run(name: str, q: str):
            try:
                j = await prom_query(app, q)
                return name, vector_to_toplist(j), None, q
            except Exception as e:
                return name, None, str(e), q

        results = await asyncio.gather(*[_run(n, q) for n, q in tasks])
        for name, data, err, q in results:
            if err:
                out["top_processes"][f"{name}_error"] = {"error": err, "query": q}
            else:
                out["top_processes"][name] = data

    return out


async def fetch_loki_excerpts(
    app: FastAPI,
    instance: Optional[str],
    job: Optional[str],
    start: datetime,
    end: datetime,
) -> Dict[str, Any]:
    queries: Dict[str, str] = {}
    if job and instance:
        queries["logs_job_instance"] = f'{{job="{job}", instance="{instance}"}}'
        queries["errors_job_instance"] = f'{{job="{job}", instance="{instance}"}} |~ "(?i)error|fail|panic|critical"'
    elif instance:
        queries["logs_instance"] = f'{{instance="{instance}"}}'
        queries["errors_instance"] = f'{{instance="{instance}"}} |~ "(?i)error|fail|panic|critical"'
    elif job:
        queries["logs_job"] = f'{{job="{job}"}}'
        queries["errors_job"] = f'{{job="{job}"}} |~ "(?i)error|fail|panic|critical"'
    else:
        queries["system"] = '{job="system"}'

    out: Dict[str, Any] = {}
    for k, q in queries.items():
        try:
            out[k] = await loki_query_range(app, q, start, end, limit=80)
        except Exception as e:
            out[k] = {"error": str(e), "query": q}
    return out


# ------------------------
# DB schema
# ------------------------
@app.on_event("startup")
async def startup() -> None:
    async with engine.begin() as conn:
        await conn.execute(text("""
            CREATE TABLE IF NOT EXISTS alert_events (
              id BIGSERIAL PRIMARY KEY,
              received_at TIMESTAMPTZ NOT NULL,
              status TEXT,
              alertname TEXT,
              job TEXT,
              instance TEXT,
              severity TEXT,
              fingerprint TEXT NULL,
              starts_at TIMESTAMPTZ NULL,
              ends_at TIMESTAMPTZ NULL,
              generator_url TEXT NULL,
              raw JSONB NOT NULL
            );
        """))

        await conn.execute(text("""
            CREATE TABLE IF NOT EXISTS incident_reports (
              id BIGSERIAL PRIMARY KEY,
              created_at TIMESTAMPTZ NOT NULL,
              alert_event_id BIGINT NULL,
              incident_key TEXT NULL,
              alertname TEXT,
              job TEXT,
              instance TEXT,
              window_minutes INT NOT NULL,
              metrics JSONB NOT NULL,
              loki_excerpt JSONB NOT NULL,
              analysis JSONB NULL
            );
        """))

        # Migrations (safe)
        await conn.execute(text("""ALTER TABLE alert_events ADD COLUMN IF NOT EXISTS fingerprint TEXT NULL;"""))
        await conn.execute(text("""ALTER TABLE alert_events ADD COLUMN IF NOT EXISTS starts_at TIMESTAMPTZ NULL;"""))
        await conn.execute(text("""ALTER TABLE alert_events ADD COLUMN IF NOT EXISTS ends_at TIMESTAMPTZ NULL;"""))
        await conn.execute(text("""ALTER TABLE alert_events ADD COLUMN IF NOT EXISTS generator_url TEXT NULL;"""))
        await conn.execute(text("""ALTER TABLE incident_reports ADD COLUMN IF NOT EXISTS incident_key TEXT NULL;"""))

        # Indexes
        await conn.execute(text("""CREATE INDEX IF NOT EXISTS idx_alert_events_received_at ON alert_events(received_at DESC);"""))
        await conn.execute(text("""CREATE INDEX IF NOT EXISTS idx_alert_events_fingerprint ON alert_events(fingerprint);"""))
        await conn.execute(text("""CREATE INDEX IF NOT EXISTS idx_alert_events_job ON alert_events(job);"""))
        await conn.execute(text("""CREATE INDEX IF NOT EXISTS idx_alert_events_instance ON alert_events(instance);"""))
        await conn.execute(text("""CREATE INDEX IF NOT EXISTS idx_alert_events_severity ON alert_events(severity);"""))

        await conn.execute(text("""CREATE INDEX IF NOT EXISTS idx_incident_reports_created_at ON incident_reports(created_at DESC);"""))
        await conn.execute(text("""CREATE INDEX IF NOT EXISTS idx_incident_reports_incident_key ON incident_reports(incident_key);"""))

        # Dedup safety (optional but recommended)
        await conn.execute(text("""
            CREATE UNIQUE INDEX IF NOT EXISTS ux_alert_events_dedup
              ON alert_events(fingerprint, starts_at, status)
              WHERE fingerprint IS NOT NULL AND starts_at IS NOT NULL AND status IS NOT NULL;
        """))


# ------------------------
# API
# ------------------------
@app.get("/health")
async def health() -> Dict[str, Any]:
    return {"ok": True}


async def _dedup_exists(fingerprint: Optional[str], starts_at: Optional[datetime], status: Optional[str]) -> bool:
    if not fingerprint or not starts_at or not status:
        return False
    async with engine.begin() as conn:
        r = await conn.execute(
            text("""
                SELECT 1
                FROM alert_events
                WHERE fingerprint = :fp
                  AND status = :status
                  AND starts_at = :starts_at
                LIMIT 1
            """),
            {"fp": fingerprint, "status": status, "starts_at": starts_at},
        )
        return r.first() is not None


@app.post("/webhook/alertmanager")
async def alertmanager_webhook(req: Request) -> Dict[str, Any]:
    raw_payload = await req.json()
    received_at = datetime.now(timezone.utc)

    try:
        payload = AlertmanagerPayload.model_validate(raw_payload)
    except ValidationError as e:
        return JSONResponse(
            content={"ok": False, "error": "invalid_payload", "details": e.errors()},
            status_code=400,
        )

    stored = 0
    reports = 0
    dedup_skipped = 0

    for a in payload.alerts:
        labels = a.labels.model_dump()
        ann = a.annotations.model_dump()

        status = (a.status or payload.status or "").lower() or None
        alertname = labels.get("alertname") or "unknown"
        job = labels.get("job")
        instance = labels.get("instance")
        severity = labels.get("severity")

        fingerprint = a.fingerprint
        starts_at = _parse_iso_to_dt(a.startsAt)
        ends_at = _parse_iso_to_dt(a.endsAt)

        if await _dedup_exists(fingerprint, starts_at, status):
            dedup_skipped += 1
            continue

        job = await _fill_job_from_prom(app, instance, job)
        incident_key = _incident_key(fingerprint, alertname, job, instance)

        async with engine.begin() as conn:
            r = await conn.execute(
                text("""
                    INSERT INTO alert_events(
                        received_at,status,alertname,job,instance,severity,
                        fingerprint, starts_at, ends_at, generator_url, raw
                    )
                    VALUES (
                        :received_at,:status,:alertname,:job,:instance,:severity,
                        :fingerprint, :starts_at, :ends_at, :generator_url, CAST(:raw AS jsonb)
                    )
                    RETURNING id
                """),
                {
                    "received_at": received_at,
                    "status": status,
                    "alertname": alertname,
                    "job": job,
                    "instance": instance,
                    "severity": severity,
                    "fingerprint": fingerprint,
                    "starts_at": starts_at,
                    "ends_at": ends_at,
                    "generator_url": a.generatorURL,
                    "raw": _json_dumps(a.model_dump()),
                },
            )
            alert_event_id = int(r.scalar())
            stored += 1

        end = received_at
        start = received_at - timedelta(minutes=WINDOW_MINUTES)

        want_process_top = _classify_alert(alertname) in ("cpu", "mem")

        async def _metrics_task():
            if not instance:
                return {}
            try:
                return await build_metrics_snapshot(app, instance, start, end, want_process_top=want_process_top)
            except Exception as e:
                return {"error": str(e), "instance": instance, "window_minutes": WINDOW_MINUTES}

        async def _loki_task():
            try:
                return await fetch_loki_excerpts(app, instance=instance, job=job, start=start, end=end)
            except Exception as e:
                return {"error": str(e)}

        metrics, loki_excerpt = await asyncio.gather(_metrics_task(), _loki_task())

        root = _root_cause_from_metrics(metrics) if metrics else {}
        notes = _make_notes_from_window(metrics)
        recs = _recommendations_from_annotations(ann)

        analysis = {
            "schema_version": 2,
            "alert_type": _classify_alert(alertname),
            "notes": notes,
            "recommendations": recs,
            "annotations": {
                "summary": ann.get("summary"),
                "description": ann.get("description"),
                "message": ann.get("message"),
            },
            "meta": {
                "incident_key": incident_key,
                "fingerprint": fingerprint,
                "startsAt": a.startsAt,
                "endsAt": a.endsAt,
                "status": status,
                "generatorURL": a.generatorURL,
                "groupKey": payload.groupKey,
                "receiver": payload.receiver,
            },
            "root": root,
        }

        async with engine.begin() as conn:
            await conn.execute(
                text("""
                    INSERT INTO incident_reports(
                        created_at, alert_event_id, incident_key, alertname, job, instance, window_minutes,
                        metrics, loki_excerpt, analysis
                    )
                    VALUES (
                        :created_at, :alert_event_id, :incident_key, :alertname, :job, :instance, :window_minutes,
                        CAST(:metrics AS jsonb), CAST(:loki_excerpt AS jsonb), CAST(:analysis AS jsonb)
                    )
                """),
                {
                    "created_at": received_at,
                    "alert_event_id": alert_event_id,
                    "incident_key": incident_key,
                    "alertname": alertname,
                    "job": job,
                    "instance": instance,
                    "window_minutes": WINDOW_MINUTES,
                    "metrics": _json_dumps(metrics),
                    "loki_excerpt": _json_dumps(loki_excerpt),
                    "analysis": _json_dumps(analysis),
                },
            )
            reports += 1

    return {"ok": True, "stored_alerts": stored, "created_reports": reports, "dedup_skipped": dedup_skipped}


@app.get("/reports/latest")
async def latest_report():
    async with engine.begin() as conn:
        r = await conn.execute(
            text("""
                SELECT id, created_at, alertname, job, instance, window_minutes
                FROM incident_reports
                ORDER BY id DESC
                LIMIT 1
            """)
        )
        row = r.mappings().first()
        if not row:
            return {"ok": True, "report": None}
        report = dict(row)
        report["created_at"] = report.get("created_at").isoformat() if report.get("created_at") else None
        return {"ok": True, "report": report}


@app.get("/reports/{report_id}")
async def get_report(report_id: int):
    async with engine.begin() as conn:
        r = await conn.execute(
            text("""
                SELECT id, created_at, alertname, job, instance, window_minutes, metrics, loki_excerpt, analysis, incident_key
                FROM incident_reports
                WHERE id = :id
            """),
            {"id": report_id},
        )
        row = r.mappings().first()
        if not row:
            return JSONResponse(content={"ok": False, "error": "not found"}, status_code=404)

        report = dict(row)
        report["created_at"] = report.get("created_at").isoformat() if report.get("created_at") else None
        report["metrics"] = _ensure_json(report.get("metrics"))
        report["loki_excerpt"] = _ensure_json(report.get("loki_excerpt"))
        report["analysis"] = _ensure_json(report.get("analysis"))
        return JSONResponse(content=jsonable_encoder({"ok": True, "report": report}))


def _toplist_md(items: List[Dict[str, Any]], unit: str) -> str:
    if not items:
        return "n/a\n"
    lines = []
    for i, it in enumerate(items, 1):
        lines.append(f"{i}. {it.get('name')} — {_fmt_num(it.get('value'), 6)} {unit}")
    return "\n".join(lines) + "\n"


@app.get("/reports/{report_id}/md", response_class=PlainTextResponse)
async def get_report_md(report_id: int) -> str:
    async with engine.begin() as conn:
        r = await conn.execute(
            text("""
                SELECT
                  r.id, r.created_at, r.alertname, r.job, r.instance, r.window_minutes, r.metrics, r.loki_excerpt, r.analysis, r.incident_key,
                  e.status AS event_status, e.starts_at, e.ends_at, e.fingerprint, e.generator_url, e.severity
                FROM incident_reports r
                LEFT JOIN alert_events e ON e.id = r.alert_event_id
                WHERE r.id = :id
            """),
            {"id": report_id},
        )
        row = r.mappings().first()
        if not row:
            return "not found"

    metrics = _ensure_json(row.get("metrics")) or {}
    analysis = _ensure_json(row.get("analysis")) or {}
    ann = (analysis.get("annotations") or {}) if isinstance(analysis, dict) else {}

    created = row.get("created_at")
    md: List[str] = []
    md.append(f"# Incident report #{row['id']}\n")
    md.append(f"- Report time (UTC): {created.isoformat() if created else 'n/a'}")
    md.append(f"- Incident key: {row.get('incident_key') or 'n/a'}")
    md.append(f"- Alert: {row.get('alertname')}")
    md.append(f"- Target: {row.get('instance')} (job={row.get('job')})")
    md.append(f"- Severity: {row.get('severity') or 'n/a'}")
    md.append(f"- Status: {row.get('event_status') or 'n/a'}")
    md.append(f"- StartsAt: {row.get('starts_at').isoformat() if row.get('starts_at') else 'n/a'}")
    md.append(f"- EndsAt: {row.get('ends_at').isoformat() if row.get('ends_at') else 'n/a'}")
    md.append(f"- Fingerprint: {row.get('fingerprint') or 'n/a'}")
    md.append(f"- GeneratorURL: {row.get('generator_url') or 'n/a'}")
    md.append(f"- Window: last {row.get('window_minutes')} minutes\n")

    if ann.get("summary"):
        md.append("## Summary")
        md.append(f"- {ann.get('summary')}\n")
    if ann.get("description") or ann.get("message"):
        md.append("## Description")
        md.append(f"{ann.get('description') or ann.get('message')}\n")

    cpuw = metrics.get("cpu_pct_window") or {}
    memw = metrics.get("mem_avail_pct_window") or {}
    diskw = metrics.get("disk_free_pct_window") or {}

    md.append("## Resource snapshot (window stats)")
    md.append(
        f"- CPU %: min={_fmt_num(cpuw.get('min'))} avg={_fmt_num(cpuw.get('avg'))} max={_fmt_num(cpuw.get('max'))} (peak {_ts_ui(cpuw.get('peak_ts'))})"
    )
    md.append(
        f"- MemAvail %: min={_fmt_num(memw.get('min'))} avg={_fmt_num(memw.get('avg'))} max={_fmt_num(memw.get('max'))} (min {_ts_ui(memw.get('min_ts'))})"
    )
    md.append(
        f"- Disk free %: min={_fmt_num(diskw.get('min'))} avg={_fmt_num(diskw.get('avg'))} max={_fmt_num(diskw.get('max'))}\n"
    )

    tp = metrics.get("top_processes") or {}
    top_cpu = tp.get("cpu_top5_5m") or []
    top_mem = tp.get("mem_top5_rss") or []
    if top_cpu:
        md.append("## Top CPU processes (rate over 5m)")
        md.append(_toplist_md(top_cpu, "cpu_sec/s"))
    if top_mem:
        md.append("## Top memory processes (RSS bytes)")
        md.append(_toplist_md(top_mem, "bytes"))

    recs = (analysis.get("recommendations") or []) if isinstance(analysis, dict) else []
    md.append("## Recommendations (from annotations.message/description)")
    if recs:
        for r0 in recs:
            md.append(f"- {r0}")
    else:
        md.append("- n/a")
    md.append("")
    return "\n".join(md) + "\n"


# ------------------------
# Excel export (per-report)
# ------------------------
@app.get("/reports/{report_id}/xlsx")
async def get_report_xlsx(report_id: int):
    async with engine.begin() as conn:
        r = await conn.execute(
            text("""
                SELECT
                  r.id, r.created_at, r.alertname, r.job, r.instance, r.window_minutes, r.metrics, r.analysis, r.incident_key,
                  e.status AS event_status, e.starts_at, e.ends_at, e.fingerprint, e.generator_url, e.severity
                FROM incident_reports r
                LEFT JOIN alert_events e ON e.id = r.alert_event_id
                WHERE r.id = :id
            """),
            {"id": report_id},
        )
        row = r.mappings().first()
        if not row:
            return JSONResponse(content={"ok": False, "error": "not found"}, status_code=404)

    metrics = _ensure_json(row.get("metrics")) or {}
    analysis = _ensure_json(row.get("analysis")) or {}
    ann = (analysis.get("annotations") or {}) if isinstance(analysis, dict) else {}

    created = row.get("created_at")
    df_summary = pd.DataFrame(
        [
            {
                "ReportID": row.get("id"),
                "CreatedUTC": created.isoformat() if created else None,
                "IncidentKey": row.get("incident_key"),
                "Alert": row.get("alertname"),
                "Job": row.get("job"),
                "Instance": row.get("instance"),
                "Severity": row.get("severity"),
                "Status": row.get("event_status"),
                "StartsAtUTC": row.get("starts_at").isoformat() if row.get("starts_at") else None,
                "EndsAtUTC": row.get("ends_at").isoformat() if row.get("ends_at") else None,
                "Fingerprint": row.get("fingerprint"),
                "GeneratorURL": row.get("generator_url"),
                "WindowMinutes": row.get("window_minutes"),
                "Summary": ann.get("summary"),
                "Description": ann.get("description") or ann.get("message"),
            }
        ]
    )

    cpuw = metrics.get("cpu_pct_window") or {}
    memw = metrics.get("mem_avail_pct_window") or {}
    diskw = metrics.get("disk_free_pct_window") or {}
    df_window = pd.DataFrame(
        [
            {"Metric": "CPU%", "Min": cpuw.get("min"), "Avg": cpuw.get("avg"), "Max": cpuw.get("max"), "Peak/MinTimeUTC": _ts_ui(cpuw.get("peak_ts"))},
            {"Metric": "MemAvailable%", "Min": memw.get("min"), "Avg": memw.get("avg"), "Max": memw.get("max"), "Peak/MinTimeUTC": _ts_ui(memw.get("min_ts"))},
            {"Metric": "DiskFree%", "Min": diskw.get("min"), "Avg": diskw.get("avg"), "Max": diskw.get("max"), "Peak/MinTimeUTC": "n/a"},
        ]
    )

    recs = (analysis.get("recommendations") or []) if isinstance(analysis, dict) else []
    df_recs = (
        pd.DataFrame([{"#": i + 1, "Recommendation": x} for i, x in enumerate(recs)])
        if recs else pd.DataFrame([{"#": 1, "Recommendation": "n/a"}])
    )

    buf = BytesIO()
    with pd.ExcelWriter(buf, engine="openpyxl") as writer:
        df_summary.to_excel(writer, sheet_name="Summary", index=False)
        df_window.to_excel(writer, sheet_name="WindowStats", index=False)
        df_recs.to_excel(writer, sheet_name="Recommendations", index=False)

        for sheet in writer.book.worksheets:
            for col_cells in sheet.columns:
                max_len = 0
                col = col_cells[0].column
                for cell in col_cells:
                    v = "" if cell.value is None else str(cell.value)
                    max_len = max(max_len, len(v))
                sheet.column_dimensions[get_column_letter(col)].width = min(max_len + 2, 70)

    data = buf.getvalue()
    filename = f"incident_report_{report_id}.xlsx"
    return Response(
        content=data,
        media_type="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


# ------------------------
# UI: Sections registry
# ------------------------
@dataclass(frozen=True)
class Section:
    id: str
    title: str
    kind: str


SECTION_REGISTRY: List[Section] = [
    Section(id="resource_snapshot", title="Resource snapshot", kind="resource"),
    Section(id="top_processes", title="Top processes (if available)", kind="process"),
    Section(id="logs", title="Logs (Loki excerpts)", kind="logs"),
]


def _extract_loki_lines(loki_json: Any, max_lines: int = 25) -> List[Dict[str, str]]:
    out: List[Dict[str, str]] = []
    try:
        data = (loki_json or {}).get("data", {})
        res = data.get("result", []) or []
        for stream in res:
            values = stream.get("values") or []
            for ts_ns, line in values:
                try:
                    ts = datetime.fromtimestamp(int(ts_ns) / 1_000_000_000, tz=timezone.utc)
                    out.append({"ts": _fmt_dt_ui(ts), "line": str(line)})
                except Exception:
                    out.append({"ts": "n/a", "line": str(line)})
        return out[:max_lines]
    except Exception:
        return []


# ------------------------
# UI (HTML/CSS/JS)
# ------------------------
UI_CSS = r"""
:root{
  --bg0:#070A12;
  --bg1:#0B1020;
  --card: rgba(255,255,255,.06);
  --stroke: rgba(255,255,255,.12);
  --text: rgba(255,255,255,.92);
  --muted: rgba(255,255,255,.65);
  --muted2: rgba(255,255,255,.45);
  --accent:#8B5CF6;
  --warn:#F59E0B;
  --crit:#EF4444;
  --ok:#22C55E;
  --shadow: 0 10px 30px rgba(0,0,0,.35);
  --radius: 18px;
  --mono: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, "Liberation Mono", "Courier New", monospace;
  --sans: ui-sans-serif, system-ui, -apple-system, Segoe UI, Roboto, Arial, sans-serif;
}
*{box-sizing:border-box}
html,body{height:100%}
body{
  margin:0;
  font-family: var(--sans);
  color:var(--text);
  background:
    radial-gradient(1000px 600px at 10% 10%, rgba(139,92,246,.25), transparent 60%),
    radial-gradient(900px 550px at 90% 15%, rgba(34,197,94,.18), transparent 60%),
    radial-gradient(1200px 700px at 50% 100%, rgba(59,130,246,.12), transparent 60%),
    linear-gradient(180deg, var(--bg0), var(--bg1));
}
a{color:inherit; text-decoration:none}
a:hover{opacity:.92}
.container{max-width:1250px; margin:0 auto; padding:22px 16px 48px}
.header{display:flex; align-items:center; justify-content:space-between; gap:12px; margin-bottom:18px}
.brand{display:flex; align-items:center; gap:12px}
.logo{
  width:42px; height:42px; border-radius:14px;
  background: linear-gradient(135deg, rgba(139,92,246,.95), rgba(34,197,94,.85));
  box-shadow: var(--shadow);
  display:flex; align-items:center; justify-content:center;
  border:1px solid rgba(255,255,255,.18);
}
.hgroup h1{font-size:18px; margin:0; letter-spacing:.2px}
.hgroup .sub{font-size:12px; color:var(--muted); margin-top:2px}
.header-actions{display:flex; gap:10px; flex-wrap:wrap; align-items:center; justify-content:flex-end}

.btn{
  display:inline-flex; align-items:center; gap:8px;
  padding:10px 12px;
  border-radius: 14px;
  border:1px solid var(--stroke);
  background: rgba(255,255,255,.06);
  box-shadow: 0 8px 24px rgba(0,0,0,.25);
  font-size:13px;
  cursor:pointer;
}
.btn:hover{background: rgba(255,255,255,.09)}
.btn.primary{
  border-color: rgba(139,92,246,.35);
  background: linear-gradient(135deg, rgba(139,92,246,.35), rgba(255,255,255,.05));
}

.card{
  background: var(--card);
  border:1px solid var(--stroke);
  border-radius: var(--radius);
  box-shadow: var(--shadow);
  overflow:hidden;
  backdrop-filter: blur(10px);
}
.card .card-h{
  display:flex; align-items:center; justify-content:space-between;
  padding:14px 14px;
  border-bottom:1px solid var(--stroke);
  background: rgba(255,255,255,.04);
}
.card .card-h .title{display:flex; align-items:center; gap:10px; font-weight:600; letter-spacing:.2px}
.card .card-b{padding:14px}

.table-wrap{overflow:auto}
table{width:100%; border-collapse:collapse; min-width: 1050px}
th,td{padding:8px 10px; border-bottom:1px solid rgba(255,255,255,.08); font-size:13px; vertical-align:top}
th{color:var(--muted); font-weight:600; text-align:left}
tbody tr:hover td{background: rgba(139,92,246,.06)}

thead th{
  position: sticky;
  top: 0;
  background: rgba(10, 14, 28, .92);
  backdrop-filter: blur(10px);
  z-index: 2;
}

.mono{font-family: var(--mono)}
.muted{color:var(--muted)}
.muted2{color:var(--muted2)}
.small{font-size:12px}

.badge{
  display:inline-flex; align-items:center; gap:6px;
  padding:5px 10px;
  border-radius: 999px;
  border:1px solid rgba(255,255,255,.14);
  background: rgba(255,255,255,.06);
  font-size:12px;
  color: rgba(255,255,255,.85);
}
.dot{width:8px; height:8px; border-radius:50%}
.badge.warn .dot{background: var(--warn)}
.badge.crit .dot{background: var(--crit)}
.badge.info .dot{background: rgba(139,92,246,.95)}
.badge.ok .dot{background: var(--ok)}

.controls{display:flex; gap:10px; flex-wrap:wrap; align-items:center}
.controls{
  position: sticky;
  top: 12px;
  z-index: 5;
  padding: 10px;
  border-radius: 18px;
  background: rgba(0,0,0,.22);
  border: 1px solid rgba(255,255,255,.10);
  backdrop-filter: blur(10px);
}
.input{
  flex:1; min-width: 260px;
  padding:10px 12px;
  border-radius: 14px;
  border:1px solid var(--stroke);
  background: rgba(0,0,0,.18);
  color:var(--text);
  outline:none;
}
.select{
  padding:10px 12px;
  border-radius: 14px;
  border:1px solid var(--stroke);
  background: rgba(0,0,0,.18);
  color:var(--text);
  outline:none;
}
.hr{height:1px; background: rgba(255,255,255,.10); margin:12px 0}
.pillrow{display:flex; flex-wrap:wrap; gap:8px}
.pill{
  border:1px solid rgba(255,255,255,.14);
  background: rgba(255,255,255,.05);
  padding:8px 10px;
  border-radius: 14px;
  font-size:12px;
}
.grid2{display:grid; grid-template-columns: 1fr 1fr; gap:14px}
@media (max-width: 980px){
  table{min-width: 980px}
  .grid2{grid-template-columns:1fr}
}
.footer{
  margin-top: 14px;
  font-size: 12px;
  color: var(--muted2);
  display:flex; justify-content:space-between; gap:10px; flex-wrap:wrap;
}
pre{
  margin:0;
  padding:12px;
  border-radius: 14px;
  border:1px solid rgba(255,255,255,.12);
  background: rgba(0,0,0,.18);
  overflow:auto;
}
"""

UI_JS = r"""document.addEventListener("DOMContentLoaded", ()=>{});"""


def _svg(icon: str) -> str:
    if icon == "bolt":
        return """<svg width="18" height="18" viewBox="0 0 24 24" fill="none">
          <path d="M13 2L3 14h8l-1 8 10-12h-8l1-8z" stroke="rgba(255,255,255,.9)" stroke-width="1.7" stroke-linejoin="round"/>
        </svg>"""
    if icon == "list":
        return """<svg width="18" height="18" viewBox="0 0 24 24" fill="none">
          <path d="M8 6h13M8 12h13M8 18h13" stroke="rgba(255,255,255,.9)" stroke-width="1.7" stroke-linecap="round"/>
          <path d="M4 6h.01M4 12h.01M4 18h.01" stroke="rgba(255,255,255,.9)" stroke-width="3" stroke-linecap="round"/>
        </svg>"""
    if icon == "doc":
        return """<svg width="18" height="18" viewBox="0 0 24 24" fill="none">
          <path d="M14 2H7a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h10a2 2 0 0 0 2-2V8l-5-6z" stroke="rgba(255,255,255,.9)" stroke-width="1.7" stroke-linejoin="round"/>
          <path d="M14 2v6h6" stroke="rgba(255,255,255,.9)" stroke-width="1.7" stroke-linejoin="round"/>
        </svg>"""
    if icon == "ext":
        return """<svg width="18" height="18" viewBox="0 0 24 24" fill="none">
          <path d="M14 3h7v7" stroke="rgba(255,255,255,.9)" stroke-width="1.7" stroke-linecap="round"/>
          <path d="M10 14L21 3" stroke="rgba(255,255,255,.9)" stroke-width="1.7" stroke-linecap="round"/>
          <path d="M21 14v6a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V6a2 2 0 0 1 2-2h6" stroke="rgba(255,255,255,.9)" stroke-width="1.7" stroke-linecap="round"/>
        </svg>"""
    return ""


def _badge(severity: Optional[str]) -> str:
    s = (severity or "").lower()
    cls = "info"
    if "crit" in s:
        cls = "crit"
    elif "warn" in s:
        cls = "warn"
    elif "info" in s:
        cls = "info"
    return f'<span class="badge {cls}"><span class="dot"></span>{_esc(severity or "info")}</span>'


def _status_badge(st: str) -> str:
    st = (st or "").lower()
    cls = "ok" if st == "closed" else "warn"
    label = "closed" if st == "closed" else "open"
    return f'<span class="badge {cls}"><span class="dot"></span>{_esc(label)}</span>'


def _html_page(title: str, body: str) -> str:
    tpl = jinja.from_string(
        """<!doctype html>
<html lang="ru">
<head>
  <meta charset="utf-8"/>
  <meta name="viewport" content="width=device-width, initial-scale=1"/>
  <title>{{ title }}</title>
  <style>{{ css }}</style>
</head>
<body>
  {{ body | safe }}
  <script>{{ js }}</script>
</body>
</html>"""
    )
    return tpl.render(title=title, css=UI_CSS, js=UI_JS, body=body)


# ------------------------
# UI: Home
# ------------------------
@app.get("/", response_class=HTMLResponse)
async def ui_home():
    body = jinja.from_string(
        """
<div class="container">
  <div class="header">
    <div class="brand">
      <div class="logo">{{ svg_bolt|safe }}</div>
      <div class="hgroup">
        <h1>IT-Monitor • Incident Center</h1>
        <div class="sub">Information Infrastructure Event Collection</div>
      </div>
    </div>
    <div class="header-actions">
      <a class="btn primary" href="/ui">{{ svg_list|safe }} Incidents</a>
      <a class="btn" href="/docs" target="_blank">{{ svg_ext|safe }} Swagger</a>
      <a class="btn" href="/health" target="_blank">{{ svg_ext|safe }} Health</a>
    </div>
  </div>

  <div class="card">
    <div class="card-h">
      <div class="title">{{ svg_doc|safe }} Quick links</div>
    </div>
<div class="card-b">
  <div class="pillrow">
    <a class="pill" href="URL" target="_blank">Link 1</a>
    <a class="pill" href="#" target="_blank">Link 2</a>
    <a class="pill" href="#" target="_blank">Link 3</a>
    <a class="pill" href="#" target="_blank">Link 4</a>
  </div>
</div>
    </div>
  </div>
</div>
"""
    ).render(svg_bolt=_svg("bolt"), svg_list=_svg("list"), svg_ext=_svg("ext"), svg_doc=_svg("doc"))
    return HTMLResponse(_html_page("IT-Monitor • Home", body))


# ------------------------
# UI: Incidents list (filters + pagination)
# ------------------------
@app.get("/ui", response_class=HTMLResponse)
async def ui_incidents(
    q: str = "",
    status: str = "",     
    job: str = "",
    severity: str = "",
    days: int = 7,
    page: int = 1,
):
    days = max(1, min(int(days), 90))
    page = max(1, int(page))
    size = 50

    now = datetime.now(timezone.utc)
    time_min = now - timedelta(days=days)

    eff_status = (status or "").lower().strip()
    eff_job = job or ""
    eff_sev = severity or ""
    eff_q = q or ""

    where: List[str] = ["le.last_event_at >= :time_min"]
    params: Dict[str, Any] = {"time_min": time_min}

    if eff_status in ("open", "closed"):
        where.append("le.derived_status = :status")
        params["status"] = eff_status

    if eff_job:
        where.append("COALESCE(le.job,'') = :job")
        params["job"] = eff_job

    if eff_sev:
        where.append("COALESCE(le.severity,'') = :sev")
        params["sev"] = eff_sev

    if eff_q.strip():
        where.append("""
            (
              le.incident_key ILIKE :q
              OR COALESCE(le.alertname,'') ILIKE :q
              OR COALESCE(le.job,'') ILIKE :q
              OR COALESCE(le.instance,'') ILIKE :q
              OR COALESCE(le.last_summary,'') ILIKE :q
              OR COALESCE(le.last_description,'') ILIKE :q
            )
        """)
        params["q"] = f"%{eff_q.strip()}%"

    where_sql = " AND ".join([f"({x})" for x in where]) if where else "TRUE"
    offset = (page - 1) * size

    async with engine.begin() as conn:
        opt = await conn.execute(
            text("""
                WITH base AS (
                  SELECT
                    COALESCE(fingerprint, alertname || '|' || COALESCE(job,'') || '|' || COALESCE(instance,'')) AS incident_key,
                    received_at, status, alertname, job, instance, severity, raw
                  FROM alert_events
                  WHERE received_at >= :time_min
                ),
                last_event AS (
                  SELECT DISTINCT ON (incident_key)
                    incident_key,
                    received_at AS last_event_at,
                    status AS last_event_status,
                    alertname, job, instance, severity,
                    (raw->'annotations'->>'summary') AS last_summary,
                    COALESCE(raw->'annotations'->>'description', raw->'annotations'->>'message') AS last_description
                  FROM base
                  ORDER BY incident_key, received_at DESC
                )
                SELECT
                  ARRAY(SELECT DISTINCT COALESCE(job,'') FROM last_event ORDER BY COALESCE(job,'')) AS jobs,
                  ARRAY(SELECT DISTINCT COALESCE(severity,'') FROM last_event ORDER BY COALESCE(severity,'')) AS sevs
            """),
            {"time_min": time_min},
        )
        opt_row = opt.mappings().first() or {}
        jobs = list(opt_row.get("jobs") or [])
        sevs = list(opt_row.get("sevs") or [])

    job_opts = [{"value": "", "label": "All jobs"}] + [{"value": v, "label": v if v else "(empty)"} for v in jobs]
    sev_opts = [{"value": "", "label": "All severity"}] + [{"value": v, "label": v if v else "(empty)"} for v in sevs]
    status_opts = [
        {"value": "", "label": "All status"},
        {"value": "open", "label": "open"},
        {"value": "closed", "label": "closed"},
    ]
    days_opts = [{"value": "1", "label": "1"}, {"value": "7", "label": "7"}, {"value": "30", "label": "30"}, {"value": "90", "label": "90"}]

    async with engine.begin() as conn:
        count_r = await conn.execute(
            text(f"""
                WITH base AS (
                  SELECT
                    COALESCE(fingerprint, alertname || '|' || COALESCE(job,'') || '|' || COALESCE(instance,'')) AS incident_key,
                    id, received_at, status, alertname, job, instance, severity, fingerprint, starts_at, ends_at, generator_url, raw
                  FROM alert_events
                  WHERE received_at >= :time_min
                ),
                last_event AS (
                  SELECT DISTINCT ON (incident_key)
                    incident_key,
                    id AS last_event_id,
                    received_at AS last_event_at,
                    status AS last_event_status,
                    alertname, job, instance, severity,
                    (raw->'annotations'->>'summary') AS last_summary,
                    COALESCE(raw->'annotations'->>'description', raw->'annotations'->>'message') AS last_description
                  FROM base
                  ORDER BY incident_key, received_at DESC, id DESC
                ),
                agg AS (
                  SELECT
                    b.incident_key,
                    COALESCE(
                      MIN(COALESCE(b.starts_at, b.received_at)) FILTER (WHERE lower(b.status)='firing'),
                      MIN(COALESCE(b.starts_at, b.received_at))
                    ) AS opened_at
                  FROM base b
                  GROUP BY b.incident_key
                ),
                last_report AS (
                  SELECT DISTINCT ON (incident_key)
                    incident_key,
                    id AS last_report_id,
                    created_at AS last_report_at
                  FROM incident_reports
                  WHERE incident_key IS NOT NULL
                  ORDER BY incident_key, id DESC
                ),
                le AS (
                  SELECT
                    le0.incident_key,
                    CASE WHEN lower(le0.last_event_status)='firing' THEN 'open' ELSE 'closed' END AS derived_status,
                    a.opened_at,
                    CASE WHEN lower(le0.last_event_status)='resolved' THEN le0.last_event_at ELSE NULL END AS closed_at,
                    le0.last_event_at,
                    le0.alertname, le0.job, le0.instance, le0.severity,
                    le0.last_summary, le0.last_description,
                    lr.last_report_id, lr.last_report_at
                  FROM last_event le0
                  JOIN agg a ON a.incident_key = le0.incident_key
                  LEFT JOIN last_report lr ON lr.incident_key = le0.incident_key
                )
                SELECT COUNT(1) AS cnt
                FROM le
                WHERE {where_sql}
            """),
            params,
        )
        total = int((count_r.mappings().first() or {}).get("cnt") or 0)

        r = await conn.execute(
            text(f"""
                WITH base AS (
                  SELECT
                    COALESCE(fingerprint, alertname || '|' || COALESCE(job,'') || '|' || COALESCE(instance,'')) AS incident_key,
                    id, received_at, status, alertname, job, instance, severity, fingerprint, starts_at, ends_at, generator_url, raw
                  FROM alert_events
                  WHERE received_at >= :time_min
                ),
                last_event AS (
                  SELECT DISTINCT ON (incident_key)
                    incident_key,
                    id AS last_event_id,
                    received_at AS last_event_at,
                    status AS last_event_status,
                    alertname, job, instance, severity,
                    (raw->'annotations'->>'summary') AS last_summary,
                    COALESCE(raw->'annotations'->>'description', raw->'annotations'->>'message') AS last_description
                  FROM base
                  ORDER BY incident_key, received_at DESC, id DESC
                ),
                agg AS (
                  SELECT
                    b.incident_key,
                    COALESCE(
                      MIN(COALESCE(b.starts_at, b.received_at)) FILTER (WHERE lower(b.status)='firing'),
                      MIN(COALESCE(b.starts_at, b.received_at))
                    ) AS opened_at
                  FROM base b
                  GROUP BY b.incident_key
                ),
                last_report AS (
                  SELECT DISTINCT ON (incident_key)
                    incident_key,
                    id AS last_report_id,
                    created_at AS last_report_at
                  FROM incident_reports
                  WHERE incident_key IS NOT NULL
                  ORDER BY incident_key, id DESC
                ),
                le AS (
                  SELECT
                    le0.incident_key,
                    CASE WHEN lower(le0.last_event_status)='firing' THEN 'open' ELSE 'closed' END AS derived_status,
                    a.opened_at,
                    CASE WHEN lower(le0.last_event_status)='resolved' THEN le0.last_event_at ELSE NULL END AS closed_at,
                    le0.last_event_at,
                    le0.alertname, le0.job, le0.instance, le0.severity,
                    le0.last_summary, le0.last_description,
                    lr.last_report_id, lr.last_report_at
                  FROM last_event le0
                  JOIN agg a ON a.incident_key = le0.incident_key
                  LEFT JOIN last_report lr ON lr.incident_key = le0.incident_key
                )
                SELECT *
                FROM le
                WHERE {where_sql}
                ORDER BY last_event_at DESC
                LIMIT :limit OFFSET :offset
            """),
            {**params, "limit": size, "offset": offset},
        )
        rows = [dict(x) for x in r.mappings().all()]

    pages = max(1, (total + size - 1) // size)

    def _url_with(**kwargs: Any) -> str:
        base = {
            "q": eff_q,
            "status": eff_status,
            "job": eff_job,
            "severity": eff_sev,
            "days": str(days),
            "page": str(page),
        }
        for k, v in kwargs.items():
            if v is None or str(v).strip() == "":
                base.pop(k, None)
            else:
                base[k] = str(v)
        clean = {k: v for k, v in base.items() if str(v).strip() != ""}
        qs = urlencode(clean, doseq=True)
        return f"/ui{('?' + qs) if qs else ''}"

    prev_url = _url_with(page=max(1, page - 1))
    next_url = _url_with(page=min(pages, page + 1))

    for r0 in rows:
        r0["opened_s"] = _fmt_dt_ui(r0.get("opened_at"))
        r0["closed_s"] = _fmt_dt_ui(r0.get("closed_at"))

    tpl = jinja.from_string(
        """
<div class="container">
  <div class="header">
    <div class="brand">
      <div class="logo">{{ svg_bolt|safe }}</div>
      <div class="hgroup">
        <h1>Incidents</h1>
        <div class="sub">Event audit</div>
      </div>
    </div>
    <div class="header-actions">
      <a class="btn" href="/">{{ svg_bolt|safe }} Home</a>
      <a class="btn" href="/docs" target="_blank">{{ svg_ext|safe }} Swagger</a>
    </div>
  </div>

  <div class="card">
    <div class="card-h">
      <div class="title">{{ svg_list|safe }} Incidents</div>
      <div class="muted2 small">Total {{ total }} • Page {{ page }}/{{ pages }} • Window {{ days }}d</div>
    </div>
    <div class="card-b">

      <form class="controls" method="get" action="/ui">
        <input name="q" class="input"
               placeholder="Search: alert / instance / job / summary / incident_key ..."
               value="{{ q|e }}"/>

        <select name="status" class="select">
          {% for o in status_opts %}
            <option value="{{ o.value|e }}" {% if o.value==status %}selected{% endif %}>{{ o.label|e }}</option>
          {% endfor %}
        </select>

        <select name="job" class="select">
          {% for o in job_opts %}
            <option value="{{ o.value|e }}" {% if o.value==job %}selected{% endif %}>{{ o.label|e }}</option>
          {% endfor %}
        </select>

        <select name="severity" class="select">
          {% for o in sev_opts %}
            <option value="{{ o.value|e }}" {% if o.value==severity %}selected{% endif %}>{{ o.label|e }}</option>
          {% endfor %}
        </select>

        <select name="days" class="select">
          {% for o in days_opts %}
            <option value="{{ o.value|e }}" {% if o.value==days %}selected{% endif %}>{{ o.label|e }}d</option>
          {% endfor %}
        </select>

        <button class="btn primary" type="submit">{{ svg_ext|safe }} Apply</button>
        <a class="btn" href="/ui">{{ svg_list|safe }} Reset</a>

        <input type="hidden" name="page" value="1"/>
      </form>

      <div class="hr"></div>

      <div class="table-wrap">
        <table>
          <thead>
            <tr>
              <th>Incident key</th>
              <th>Status</th>
              <th>Opened</th>
              <th>Closed</th>
              <th>Alert</th>
              <th>Job</th>
              <th>Instance</th>
              <th>Severity</th>
              <th>Summary</th>
              <th>Report</th>
            </tr>
          </thead>
          <tbody>
            {% if rows %}
              {% for r in rows %}
                <tr>
                  <td class="mono">{{ r.incident_key|e }}</td>
                  <td style="white-space:nowrap;">{{ status_badge(r.derived_status)|safe }}</td>
                  <td class="mono muted">{{ r.opened_s|e }}</td>
                  <td class="mono muted">{{ r.closed_s|e }}</td>
                  <td><span class="badge info"><span class="dot"></span>{{ (r.alertname or "unknown")|e }}</span></td>
                  <td class="mono">{{ (r.job or "—")|e }}</td>
                  <td class="mono">{{ (r.instance or "—")|e }}</td>
                  <td style="white-space:nowrap;">{{ badge(r.severity)|safe }}</td>
                  <td>
                    {% if r.last_summary %}<div>{{ r.last_summary|e }}</div>{% else %}<div class="muted">—</div>{% endif %}
                    {% if r.last_description %}<div class="muted2 small" style="margin-top:4px; white-space:pre-wrap;">{{ r.last_description|e }}</div>{% endif %}
                  </td>
                  <td style="white-space:nowrap;">
                    {% if r.last_report_id %}
                      <a class="btn" style="padding:7px 10px;" href="/ui/reports/{{ r.last_report_id }}">{{ svg_doc|safe }} Open</a>
                    {% else %}
                      <span class="muted2 small">—</span>
                    {% endif %}
                  </td>
                </tr>
              {% endfor %}
            {% else %}
              <tr><td colspan="10" style="padding:14px;">No incidents for selected filters</td></tr>
            {% endif %}
          </tbody>
        </table>
      </div>

      <div class="footer">
        <div class="pillrow">
          <a class="pill" href="{{ prev_url|e }}">← Prev</a>
          <a class="pill" href="{{ next_url|e }}">Next →</a>
        </div>
        <div class="mono muted2">{{ self_url|e }}</div>
      </div>
    </div>
  </div>
</div>
"""
    )

    body = tpl.render(
        svg_bolt=_svg("bolt"),
        svg_list=_svg("list"),
        svg_ext=_svg("ext"),
        svg_doc=_svg("doc"),
        badge=_badge,
        status_badge=_status_badge,
        rows=rows,
        total=total,
        page=page,
        pages=pages,
        q=eff_q,
        status=eff_status,
        job=eff_job,
        severity=eff_sev,
        days=str(days),
        job_opts=job_opts,
        sev_opts=sev_opts,
        status_opts=status_opts,
        days_opts=days_opts,
        prev_url=prev_url,
        next_url=next_url,
        self_url=_url_with(),
    )
    return HTMLResponse(_html_page("IT-Monitor • Incidents", body))


# ------------------------
# UI: Report view
# ------------------------

@app.get("/ui/reports/{report_id}", response_class=HTMLResponse)
async def ui_report_view(report_id: int):
    async with engine.begin() as conn:
        r = await conn.execute(
            text("""
                SELECT
                  r.id, r.created_at, r.alertname, r.job, r.instance, r.window_minutes,
                  r.metrics, r.loki_excerpt, r.analysis, r.incident_key,
                  e.severity, e.status AS event_status, e.starts_at, e.ends_at, e.fingerprint, e.generator_url
                FROM incident_reports r
                LEFT JOIN alert_events e ON e.id = r.alert_event_id
                WHERE r.id = :id
            """),
            {"id": report_id},
        )
        row = r.mappings().first()

    if not row:
        body = f"""
        <div class="container">
          <div class="card"><div class="card-b">
            <h2>Report #{report_id} not found</h2>
            <a class="btn primary" href="/ui">{_svg("list")} Back to list</a>
          </div></div>
        </div>
        """
        return HTMLResponse(_html_page("Report not found", body))

    created = _fmt_dt_ui(row.get("created_at"))
    alertname = row.get("alertname") or "unknown"
    job = row.get("job")
    instance = row.get("instance")
    severity = row.get("severity")
    event_status = row.get("event_status")
    starts_at = row.get("starts_at")
    ends_at = row.get("ends_at")
    fingerprint = row.get("fingerprint")
    generator_url = row.get("generator_url")
    incident_key = row.get("incident_key")

    metrics = _ensure_json(row.get("metrics")) or {}
    analysis = _ensure_json(row.get("analysis")) or {}
    loki_excerpt = _ensure_json(row.get("loki_excerpt")) or {}

    ann = (analysis.get("annotations") or {}) if isinstance(analysis, dict) else {}
    notes = (analysis.get("notes") or []) if isinstance(analysis, dict) else []
    recs = (analysis.get("recommendations") or []) if isinstance(analysis, dict) else []

    cpuw = metrics.get("cpu_pct_window") or {}
    memw = metrics.get("mem_avail_pct_window") or {}
    diskw = metrics.get("disk_free_pct_window") or {}

    tp = metrics.get("top_processes") or {}
    top_cpu = tp.get("cpu_top5_5m") or []
    top_mem = tp.get("mem_top5_rss") or []

    def _toplist(items: List[Dict[str, Any]], unit: str) -> str:
        if not items:
            return "<div class='muted'>n/a</div>"
        lis = []
        for it in items:
            lis.append(
                f"<li><b>{_esc(it.get('name'))}</b> — <span class='mono'>{_esc(_fmt_num(it.get('value'), 6))}</span> {unit}</li>"
            )
        return "<ol>" + "".join(lis) + "</ol>"

    logs_blocks: List[Dict[str, Any]] = []
    if isinstance(loki_excerpt, dict):
        for k, v in loki_excerpt.items():
            if isinstance(v, dict) and "error" in v:
                logs_blocks.append({"name": k, "error": v.get("error"), "lines": []})
            else:
                lines = _extract_loki_lines(v, max_lines=25)
                logs_blocks.append({"name": k, "error": None, "lines": lines})

    tpl = jinja.from_string(
        """
<div class="container">
  <div class="header">
    <div class="brand">
      <div class="logo">{{ svg_doc|safe }}</div>
      <div class="hgroup">
        <h1>Report #{{ rid }}</h1>
        <div class="sub">{{ alertname|e }} • {{ created|e }}</div>
      </div>
    </div>
    <div class="header-actions">
      <a class="btn primary" href="/ui">{{ svg_list|safe }} Incidents</a>
      <a class="btn" href="/reports/{{ rid }}/md" target="_blank">{{ svg_ext|safe }} Markdown</a>
      <a class="btn" href="/reports/{{ rid }}/xlsx" target="_blank">{{ svg_ext|safe }} XLSX</a>
      <a class="btn" href="/reports/{{ rid }}" target="_blank">{{ svg_ext|safe }} JSON</a>
    </div>
  </div>

  <div class="card">
    <div class="card-h">
      <div class="title">{{ svg_bolt|safe }} Overview</div>
      <div>{{ badge(severity)|safe }}</div>
    </div>

    <div class="card-b">
      <div class="pillrow">
        <span class="pill"><b>Incident key</b>: <span class="mono">{{ (incident_key or "—")|e }}</span></span>
        <span class="pill"><b>Status</b>: <span class="mono">{{ (event_status or "n/a")|e }}</span></span>
        <span class="pill"><b>StartsAt</b>: <span class="mono">{{ starts_s|e }}</span></span>
        <span class="pill"><b>EndsAt</b>: <span class="mono">{{ ends_s|e }}</span></span>
        </span>
      </div>

      <div class="hr"></div>

      <div class="pillrow">
        <span class="pill"><b>Alert</b>: {{ alertname|e }}</span>
        <span class="pill"><b>Job</b>: <span class="mono">{{ (job or "—")|e }}</span></span>
        <span class="pill"><b>Instance</b>: <span class="mono">{{ (instance or "—")|e }}</span></span>
      </div>

      <div class="hr"></div>

      <div class="grid2">
        <div class="card" style="background:rgba(255,255,255,.03); box-shadow:none;">
          <div class="card-h">
            <div class="title">{{ svg_doc|safe }} Alert message</div>
          </div>
          <div class="card-b">
            {% if ann.summary %}
              <div class="small muted">Summary</div>
              <div style="margin-bottom:10px;">{{ ann.summary|e }}</div>
            {% endif %}
            {% if ann.description or ann.message %}
              <div class="small muted">Description</div>
              <div style="white-space:pre-wrap;">{{ (ann.description or ann.message)|e }}</div>
            {% else %}
              <div class="muted">n/a</div>
            {% endif %}
          </div>
        </div>

        <div class="card" style="background:rgba(255,255,255,.03); box-shadow:none;">
          <div class="card-h">
            <div class="title">{{ svg_doc|safe }} Recommendations</div>
          </div>
          <div class="card-b">
            <div class="small muted">Derived from annotations.message/description</div>
            {% if recs %}
              <ol>
                {% for r in recs %}
                  <li>{{ r|e }}</li>
                {% endfor %}
              </ol>
            {% else %}
              <div class="muted">n/a</div>
            {% endif %}
          </div>
        </div>
      </div>

      <div class="hr"></div>

      <div class="card" style="background:rgba(255,255,255,.03); box-shadow:none;">
        <div class="card-h">
          <div class="title">{{ svg_list|safe }} Context sections</div>
          <div class="muted2 small">Rendered only if data exists</div>
        </div>
        <div class="card-b">

          {% if has_resource %}
            <div class="pillrow" style="margin-bottom:10px;">
              <span class="pill"><b>CPU%</b>: min <span class="mono">{{ cpu.min_s }}</span> • avg <span class="mono">{{ cpu.avg_s }}</span> • max <span class="mono">{{ cpu.max_s }}</span></span>
              <span class="pill"><b>CPU peak</b>: <span class="mono">{{ cpu.peak_s }}</span></span>
            </div>
            <div class="pillrow" style="margin-bottom:10px;">
              <span class="pill"><b>MemAvail%</b>: min <span class="mono">{{ mem.min_s }}</span> • avg <span class="mono">{{ mem.avg_s }}</span> • max <span class="mono">{{ mem.max_s }}</span></span>
              <span class="pill"><b>Mem min</b>: <span class="mono">{{ mem.min_ts_s }}</span></span>
            </div>
            <div class="pillrow">
              <span class="pill"><b>Disk free%</b>: min <span class="mono">{{ disk.min_s }}</span> • avg <span class="mono">{{ disk.avg_s }}</span> • max <span class="mono">{{ disk.max_s }}</span></span>
            </div>

            {% if notes %}
              <div class="hr"></div>
              <div class="small muted">Notes</div>
              <ul>
                {% for n in notes %}
                  <li>{{ n|e }}</li>
                {% endfor %}
              </ul>
            {% endif %}

            <div class="hr"></div>
          {% endif %}

          {% if has_process %}
            <div class="grid2">
              <div>
                <div class="small muted">Top CPU</div>
                {{ top_cpu_html|safe }}
              </div>
              <div>
                <div class="small muted">Top MEM</div>
                {{ top_mem_html|safe }}
              </div>
            </div>
            <div class="hr"></div>
          {% endif %}

          {% if logs_blocks %}
            <div class="small muted">Logs</div>
            {% for b in logs_blocks %}
              <div style="margin-top:10px;">
                <div class="pillrow" style="margin-bottom:8px;">
                  <span class="pill"><b>Stream</b>: <span class="mono">{{ b.name|e }}</span></span>
                  {% if b.error %}
                    <span class="pill"><b>Error</b>: <span class="mono">{{ b.error|e }}</span></span>
                  {% endif %}
                </div>
                {% if b.lines %}
                  <pre class="mono">{% for ln in b.lines %}{{ ln.ts|e }}  {{ ln.line|e }}
{% endfor %}</pre>
                {% else %}
                  <div class="muted2 small">n/a</div>
                {% endif %}
              </div>
            {% endfor %}
          {% else %}
            <div class="muted">No Loki context</div>
          {% endif %}
        </div>
      </div>

      <div class="footer">
        <div><a class="btn" href="/ui">{{ svg_list|safe }} Incidents</a></div>
        <div class="mono muted2">/ui/reports/{{ rid }}</div>
      </div>
    </div>
  </div>
</div>
"""
    )

    has_resource = any(isinstance(x, dict) and x for x in [cpuw, memw, diskw])
    has_process = bool(top_cpu) or bool(top_mem)

    body = tpl.render(
        rid=report_id,
        created=created,
        alertname=alertname,
        job=job,
        instance=instance,
        window=int(row.get("window_minutes") or WINDOW_MINUTES),
        severity=severity,
        event_status=event_status,
        starts_s=_fmt_dt_ui(starts_at),
        ends_s=_fmt_dt_ui(ends_at),
        fingerprint=fingerprint,
        generator_url=generator_url,
        incident_key=incident_key,
        ann=ann,
        recs=recs,
        notes=notes,
        has_resource=has_resource,
        has_process=has_process,
        cpu={
            "min_s": _fmt_num(cpuw.get("min")),
            "avg_s": _fmt_num(cpuw.get("avg")),
            "max_s": _fmt_num(cpuw.get("max")),
            "peak_s": _ts_ui(cpuw.get("peak_ts")),
        },
        mem={
            "min_s": _fmt_num(memw.get("min")),
            "avg_s": _fmt_num(memw.get("avg")),
            "max_s": _fmt_num(memw.get("max")),
            "min_ts_s": _ts_ui(memw.get("min_ts")),
        },
        disk={
            "min_s": _fmt_num(diskw.get("min")),
            "avg_s": _fmt_num(diskw.get("avg")),
            "max_s": _fmt_num(diskw.get("max")),
        },
        top_cpu_html=_toplist(top_cpu, "cpu_sec/s"),
        top_mem_html=_toplist(top_mem, "bytes"),
        logs_blocks=logs_blocks,
        svg_bolt=_svg("bolt"),
        svg_list=_svg("list"),
        svg_doc=_svg("doc"),
        svg_ext=_svg("ext"),
        badge=_badge,
    )
    return HTMLResponse(_html_page(f"Report #{report_id}", body))
