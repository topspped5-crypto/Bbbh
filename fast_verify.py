"""FAST payment verification (same design as the fast site's worker.py).
A background loop wakes every 0.5s (or instantly when a new order is created) and checks every PENDING order
in a small thread pool, so customers' status polls never wait on Gmail/Paytm and the site never freezes.
- FamPay: one job per merchant mailbox (all its pending orders share ONE Gmail check)
- Paytm : one job per order (orders are checked in parallel)
Verification rules are unchanged: it calls the existing core.refresh()."""
import os, time, threading
from datetime import timedelta
from concurrent.futures import ThreadPoolExecutor
from sqlalchemy import select

GAP = float(os.getenv("FAST_VERIFY_GAP", "1"))           # seconds between checks of the same job
POOL = ThreadPoolExecutor(max_workers=int(os.getenv("FAST_VERIFY_THREADS", "8")), thread_name_prefix="fast-verify")
_inflight, _last, _lk, _wake = set(), {}, threading.Lock(), threading.Event()
_started = False

def nudge():
    """Wake the checker immediately (called when a new order is created / a status page polls)."""
    _wake.set()

def _run(job, ids):
    from db import SessionLocal
    from models import Txn
    from core import refresh
    try:
        with SessionLocal() as db:
            for i in ids:
                try:
                    t = db.get(Txn, i)
                    if t and t.status in ("PENDING", "CREATED"): refresh(db, t)
                except Exception as e:
                    db.rollback(); print("fast-verify error:", e, flush=True)
    finally:
        with _lk: _inflight.discard(job); _last[job] = time.time()

def _loop():
    from db import SessionLocal
    from models import Txn, now
    while True:
        rows = []
        try:
            with SessionLocal() as db:   # +1 min so just-expired orders get marked EXPIRED right away
                rows = db.execute(select(Txn.id, Txn.user_id, Txn.gateway).where(
                    Txn.status.in_(("PENDING", "CREATED")), Txn.expires_at > now() - timedelta(minutes=1)
                ).order_by(Txn.id.desc()).limit(300)).all()
            jobs = {}
            for tid, uid, g in rows:
                jobs.setdefault(("fampay", uid) if g == "fampay" else (g, tid), []).append(tid)
            t0 = time.time()
            for job, ids in jobs.items():
                with _lk:
                    if job in _inflight or t0 - _last.get(job, 0) < GAP: continue
                    _inflight.add(job)
                POOL.submit(_run, job, ids)
            if len(_last) > 5000:
                with _lk:
                    for k in [k for k, v in _last.items() if t0 - v > 900]: _last.pop(k, None)
        except Exception as e:
            print("fast-verify loop error:", e, flush=True)
        _wake.wait(0.5 if rows else 3); _wake.clear()

def start():
    global _started
    if not _started:
        _started = True
        threading.Thread(target=_loop, daemon=True, name="fast-verify").start()
