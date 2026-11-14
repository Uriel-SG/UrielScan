import json
import asyncio
from datetime import datetime, timezone, timedelta
from typing import Optional, Dict, Any, List
from apscheduler.schedulers.asyncio import AsyncIOScheduler
from apscheduler.triggers.cron import CronTrigger
from apscheduler.triggers.interval import IntervalTrigger
from backend.database import get_db_connection

scheduler = AsyncIOScheduler()


def init_scheduler() -> None:
    if not scheduler.running:
        scheduler.start()
        reload_schedules()


def shutdown_scheduler() -> None:
    if scheduler.running:
        scheduler.shutdown(wait=False)


def reload_schedules() -> None:
    # Clear existing dynamic jobs
    for job in scheduler.get_jobs():
        if job.id.startswith("sched_"):
            scheduler.remove_job(job.id)

    conn = get_db_connection()
    rows = conn.execute("SELECT * FROM schedules WHERE enabled = 1;").fetchall()
    conn.close()

    for r in rows:
        _add_schedule_job(dict(r))


def _add_schedule_job(sched: Dict[str, Any]) -> None:
    sched_id = sched["id"]
    job_id = f"sched_{sched_id}"
    freq = sched.get("frequency", "weekly").lower()
    time_str = sched.get("time_of_day") or "02:00"

    try:
        hour, minute = map(int, time_str.split(":"))
    except Exception:
        hour, minute = 2, 0

    trigger = None
    if freq == "daily":
        trigger = CronTrigger(hour=hour, minute=minute)
    elif freq == "weekly":
        day = (sched.get("day_of_week") or "mon").lower()
        trigger = CronTrigger(day_of_week=day, hour=hour, minute=minute)
    elif freq == "monthly":
        trigger = CronTrigger(day=1, hour=hour, minute=minute)
    elif freq == "cron" and sched.get("cron_expr"):
        parts = sched["cron_expr"].strip().split()
        if len(parts) == 5:
            trigger = CronTrigger(
                minute=parts[0], hour=parts[1], day=parts[2], month=parts[3], day_of_week=parts[4]
            )

    if not trigger:
        trigger = CronTrigger(hour=hour, minute=minute)

    # Calculate next run
    try:
        job = scheduler.add_job(
            _execute_scheduled_scan,
            trigger=trigger,
            id=job_id,
            args=[sched_id],
            replace_existing=True
        )
        next_run = job.next_run_time.isoformat() if job.next_run_time else None
        conn = get_db_connection()
        with conn:
            conn.execute("UPDATE schedules SET next_run = ? WHERE id = ?;", (next_run, sched_id))
        conn.close()
    except Exception:
        pass


async def _execute_scheduled_scan(schedule_id: int) -> None:
    from backend.scanners.orchestrator import start_scan_in_background

    conn = get_db_connection()
    sched = conn.execute("SELECT * FROM schedules WHERE id = ?;", (schedule_id,)).fetchone()
    if not sched or not sched["enabled"]:
        conn.close()
        return

    now_iso = datetime.now(timezone.utc).isoformat()
    scan_cfg = json.loads(sched["scan_config_json"] or "{}")
    profile = scan_cfg.get("profile", "full_purple")
    engines = scan_cfg.get("engines", ["native_net", "native_web", "nmap", "nuclei"])

    # Create new scan record
    scan_name = f"[Schedulato] {sched['name']} - {datetime.now().strftime('%Y-%m-%d %H:%M')}"
    with conn:
        cur = conn.execute("""
            INSERT INTO scans (org_id, name, targets, scan_profile, engines_json, config_json, status, progress, current_task, started_at)
            VALUES (?, ?, ?, ?, ?, ?, 'running', 0, 'Avvio schedulazione...', ?);
        """, (
            sched["org_id"],
            scan_name,
            sched["targets"],
            profile,
            json.dumps(engines),
            json.dumps(scan_cfg),
            now_iso
        ))
        new_scan_id = cur.lastrowid

        # Update schedule's last_run
        conn.execute("UPDATE schedules SET last_run = ? WHERE id = ?;", (now_iso, schedule_id))
    conn.close()

    # Launch scan orchestrator
    start_scan_in_background(new_scan_id)


async def trigger_schedule_now(schedule_id: int) -> int:
    from backend.scanners.orchestrator import start_scan_in_background

    conn = get_db_connection()
    sched = conn.execute("SELECT * FROM schedules WHERE id = ?;", (schedule_id,)).fetchone()
    if not sched:
        conn.close()
        raise ValueError(f"Schedulazione ID {schedule_id} non trovata.")

    now_iso = datetime.now(timezone.utc).isoformat()
    scan_cfg = json.loads(sched["scan_config_json"] or "{}")
    profile = scan_cfg.get("profile", "full_purple")
    engines = scan_cfg.get("engines", ["native_net", "native_web", "nmap", "nuclei"])

    scan_name = f"[Manuale Rapido] {sched['name']} - {datetime.now().strftime('%Y-%m-%d %H:%M')}"
    with conn:
        cur = conn.execute("""
            INSERT INTO scans (org_id, name, targets, scan_profile, engines_json, config_json, status, progress, current_task, started_at)
            VALUES (?, ?, ?, ?, ?, ?, 'running', 0, 'Avvio scansione immediata...', ?);
        """, (
            sched["org_id"],
            scan_name,
            sched["targets"],
            profile,
            json.dumps(engines),
            json.dumps(scan_cfg),
            now_iso
        ))
        new_scan_id = cur.lastrowid
        conn.execute("UPDATE schedules SET last_run = ? WHERE id = ?;", (now_iso, schedule_id))
    conn.close()

    start_scan_in_background(new_scan_id)
    return new_scan_id
