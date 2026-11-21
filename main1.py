"""
SaaS backend (Tier 2). Receives metadata only, serves the dashboard, finds anomalies.
Run:  pip install fastapi uvicorn   then   uvicorn main:app --reload   (or: python start.py)
"""
import os, statistics
from fastapi import FastAPI, Header, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse

app = FastAPI()
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])
API_KEY = os.environ.get("API_KEY", "demo-key")  # set a real secret in the hosting dashboard
store = {}  # payload_id -> payload. A dict key makes duplicates impossible.


@app.get("/")
def home():  # the dashboard is served from here: open http://localhost:8000
    return FileResponse(os.path.join(os.path.dirname(os.path.abspath(__file__)), "dashboard.html"))


@app.post("/ingest")
def ingest(p: dict, x_api_key: str = Header(default=None)):
    if x_api_key != API_KEY:  # collector authentication
        raise HTTPException(401, "invalid or missing API key")
    if "payload_id" not in p or "tenant_id" not in p:
        raise HTTPException(400, "payload_id and tenant_id are required")
    if p["payload_id"] in store:
        return {"status": "duplicate_ignored"}
    store[p["payload_id"]] = p
    return {"status": "ok"}


@app.get("/events")
def events():
    # ordered by event time, not arrival time
    return sorted(store.values(), key=lambda x: x["event_time_utc"])[-500:]


# ---- AIOps: baseline anomaly detection + correlation + explanation ----
ACTIONS = {
    "cpu": "Check which process is using the CPU and whether a deployment or job started.",
    "memory": "Look for a memory leak or a runaway process; consider restarting the service.",
    "disk": "Find large or growing files and clear logs or temp data.",
    "latency": "Check network path and upstream service health.",
    "packet_loss": "Check the link, cabling or router for faults.",
    "failed_logins": "Possible brute-force attempt: review the auth source and consider blocking it.",
}


@app.get("/incidents")
def incidents(tenant: str = "company-a"):
    evs = sorted((e for e in store.values() if e["tenant_id"] == tenant), key=lambda x: x["event_time_utc"])
    series = {}
    for e in evs:
        series.setdefault((e["source_id"], e["metric"]), []).append(e)
    flags = {}
    for (src, metric), pts in series.items():
        vals = [float(p["value"]) for p in pts]
        if len(vals) < 12:
            continue  # not enough history to know what normal is
        base, cur = vals[-31:-1], vals[-1]
        mean = statistics.mean(base)
        sd = max(statistics.pstdev(base), 0.05 * abs(mean), 1.0)  # floor stops tiny-noise false alarms
        z = (cur - mean) / sd
        if z >= 3:
            flags.setdefault(src, []).append(
                {"metric": metric, "value": cur, "baseline": round(mean, 1), "z": round(z, 1), "time": pts[-1]["event_time_utc"]})
    out = []
    for src, fl in flags.items():  # correlation: all anomalies on one source = ONE incident
        names = ", ".join(f["metric"] for f in fl)
        why = "; ".join(f"{f['metric']} is {f['value']} vs a normal of about {f['baseline']} ({f['z']} standard deviations high)" for f in fl)
        out.append({
            "source_id": src,
            "severity": "high" if len(fl) > 1 or max(f["z"] for f in fl) >= 6 else "medium",
            "title": f"Anomaly on {src}: {names}",
            "why_flagged": why + ("; several related signals moved together, so they are grouped as one incident." if len(fl) > 1 else "."),
            "signals": fl,
            "recommendation": " ".join(dict.fromkeys(ACTIONS.get(f["metric"], "Investigate.") for f in fl)),
            "time": max(f["time"] for f in fl),
        })
    return out
