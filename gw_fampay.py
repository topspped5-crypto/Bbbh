"""FamPay adapter (auto verification via the merchant's OWN Gmail, IMAP + App Password).
Flow: customer pays a UNIQUE amount (unique paise) -> FamPay/bank credit email lands in merchant Gmail
-> we read it and match amount + time. Safety: only mails with DKIM=pass and sender matching the filter count;
UTR is de-duplicated in core so one email can never confirm two orders. Tune SENDER/regex to a real mail sample."""
import imaplib, email, re, time, threading, hashlib
from email.utils import parsedate_to_datetime
from email.header import decode_header, make_header
from datetime import datetime, timezone, timedelta
from urllib.parse import quote

LABEL = "FamPay / FamApp"; AVAILABLE = True
FIELDS = [("shop", "Shop Name", False), ("upi", "UPI ID", False), ("gmail", "Gmail Address", False), ("app_password", "Gmail App Password (16 digits)", True)]
SENDER_DEFAULT = "fam"          # substring that must appear in the From header (change if the bank mail comes from another domain)
_CREDIT = re.compile(r"(received|credited|paid you|sent you|payment from)", re.I)
_DEBIT = re.compile(r"(debited|you paid|you sent|paid to|sent to)", re.I)
_AMT = re.compile(r"(?:₹|Rs\.?|INR)\s*([\d,]+(?:\.\d{1,2})?)", re.I)
_UTR = re.compile(r"\b(\d{12})\b")
_cache: dict = {}; _lock = threading.Lock()

def _text(msg):
    parts = []
    for p in (msg.walk() if msg.is_multipart() else [msg]):
        if p.get_content_type() in ("text/plain", "text/html"):
            try: s = p.get_payload(decode=True).decode(p.get_content_charset() or "utf-8", "ignore")
            except Exception: continue
            parts.append(re.sub(r"<[^>]+>", " ", s) if p.get_content_type() == "text/html" else s)
    return re.sub(r"\s+", " ", " ".join(parts))

def _parse(raw, sender_filter):
    msg = email.message_from_bytes(raw)
    frm = str(make_header(decode_header(msg.get("From", "")))).lower()
    subj = str(make_header(decode_header(msg.get("Subject", ""))))
    if sender_filter.lower() not in frm: return None
    body = subj + " " + _text(msg)
    if not _CREDIT.search(body) or _DEBIT.search(subj): return None
    m = _AMT.search(body)
    if not m: return None
    try: paise = round(float(m.group(1).replace(",", "")) * 100)
    except ValueError: return None
    try: ts = parsedate_to_datetime(msg.get("Date")); ts = ts if ts.tzinfo else ts.replace(tzinfo=timezone.utc)
    except Exception: return None
    auth = " ".join(msg.get_all("Authentication-Results") or []).lower()
    u = _UTR.search(body)
    mid = (msg.get("Message-ID") or raw[:200].decode("latin1"))
    return {"paise": paise, "ts": ts.astimezone(timezone.utc), "dkim": "dkim=pass" in auth, "key": hashlib.sha1(mid.encode()).hexdigest()[:24],
            "utr": u.group(1) if u else "MSG" + hashlib.sha1(mid.encode()).hexdigest()[:12].upper()}

def _login(cfg):
    M = imaplib.IMAP4_SSL("imap.gmail.com", timeout=20)
    M.login(cfg["gmail"], cfg["app_password"].replace(" ", "")); return M

# ---------- FAST mailbox reader (same idea as the fast site) ----------
# One Gmail connection per mailbox is kept OPEN and reused (no new login every check), and only NEW
# emails (by IMAP UID) are downloaded each time. Parsed credit emails are kept in memory for 1 day.
GAP = 0.8                          # at most one mailbox check per ~1 second
_conns: dict = {}; _box: dict = {}; _glocks: dict = {}; _fail: dict = {}

def _glock(key):
    with _lock: return _glocks.setdefault(key, threading.Lock())

def _drop(key):
    ent = _conns.pop(key, None)
    if ent:
        try: ent[0].logout()
        except Exception: pass

def _conn(cfg, key):
    ent = _conns.get(key)
    if ent:
        M, t = ent
        if time.time() - t < 20: return M        # fresh connection: no extra round trip
        try: M.noop(); return M                   # older: make sure it is still alive
        except Exception: _drop(key)
    M = _login(cfg); _conns[key] = [M, time.time()]; return M

def _fetch_new(M, key, sender):
    M.select("INBOX", readonly=True)
    try: uidv = (M.response("UIDVALIDITY")[1] or [None])[0]
    except Exception: uidv = None
    st = _box.get(key)
    if not st or st["uidv"] != uidv: st = _box[key] = {"uidv": uidv, "last": 0, "items": []}
    if st["last"]: typ, data = M.uid("SEARCH", None, "UID", f"{st['last'] + 1}:*")
    else: typ, data = M.uid("SEARCH", None, "SINCE", (datetime.now(timezone.utc) - timedelta(days=1)).strftime("%d-%b-%Y"))
    uids = sorted(int(x) for x in (data[0].split() if typ == "OK" and data and data[0] else []))
    uids = [u for u in uids if u > st["last"]][-80:]
    if uids:
        t, d = M.uid("FETCH", ",".join(map(str, uids)), "(BODY.PEEK[])")   # all new mails in ONE request
        for part in (d if t == "OK" and d else []):
            if isinstance(part, tuple) and part[1]:
                r = _parse(part[1], sender)
                if r and all(x["key"] != r["key"] for x in st["items"]): st["items"].append(r)
        st["last"] = max(uids)
    cutoff = datetime.now(timezone.utc) - timedelta(days=1)
    st["items"] = [r for r in st["items"] if r["ts"] >= cutoff]
    return list(st["items"])

def _scan(cfg):
    key = cfg["gmail"].lower()
    with _glock(key):                      # one check per mailbox at a time; others reuse its result
        c = _cache.get(key)
        if c and time.time() - c[0] < GAP: return c[1]
        f = _fail.get(key)
        if f and time.time() < f[1]: return c[1] if c else []      # short back-off after an error
        sender = cfg.get("sender") or SENDER_DEFAULT
        try:
            try: out = _fetch_new(_conn(cfg, key), key, sender)
            except (imaplib.IMAP4.abort, OSError):                 # connection dropped: reconnect once
                _drop(key); out = _fetch_new(_conn(cfg, key), key, sender)
            if key in _conns: _conns[key][1] = time.time()
        except Exception:
            _drop(key); n = (f[0] if f else 0) + 1; _fail[key] = (n, time.time() + min(60, n * 5)); raise
        _fail.pop(key, None); _cache[key] = (time.time(), out)
        return out

def create(cfg, env, pay_id, amount_paise):
    uri = f"upi://pay?pa={quote(cfg['upi'])}&pn={quote(cfg['shop'])}&am={amount_paise/100:.2f}&cu=INR&tn={quote('Order ' + pay_id[-8:])}"
    return {"qr_data": uri, "provider_ref": ""}

def status(cfg, env, pay_id, amount=None, since=None, used_keys=(), **kw):
    if not amount or not since: return {"state": "PENDING", "order_id": pay_id, "amount": 0, "txn_id": ""}
    since = (since if since.tzinfo else since.replace(tzinfo=timezone.utc)) - timedelta(seconds=30)
    for r in sorted(_scan(cfg), key=lambda x: x["ts"]):
        if r["key"] in used_keys: continue  # this email already confirmed another order - look at the next one
        if r["dkim"] and r["paise"] == amount and r["ts"] >= since:
            return {"state": "SUCCESS", "order_id": pay_id, "amount": amount, "txn_id": r["utr"], "key": r["key"]}
    return {"state": "PENDING", "order_id": pay_id, "amount": 0, "txn_id": ""}

def test(cfg, env):
    try: M = _login(cfg); M.select("INBOX", readonly=True); M.logout()
    except imaplib.IMAP4.error: return False, "Gmail login failed - check Gmail + 16-digit App Password (2-step verification must be ON, IMAP enabled)"
    except Exception as e: return False, f"Cannot reach Gmail: {str(e)[:120]}"
    return True, "Gmail connected (IMAP OK)"

def refund(*a, **k): raise RuntimeError("Refunds are manual for FamPay")
def refund_status(*a, **k): return {"state": "PENDING", "msg": "manual"}
