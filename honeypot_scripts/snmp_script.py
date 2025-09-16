#!/usr/bin/env python3
import os, sys, time, json, random
RATE = float(os.getenv("RATE","5"))
AVG_SIZE = float(os.getenv("SIZE","500"))
ERR = float(os.getenv("ERR","0.05"))
DELAY = max(0.01, 1.0/(RATE+1e-6))  # inter-arrival proxy
LOGF = os.path.join(".", "log", "honeyd", "snmp.log")
def log(event, extra=None):
    try:
        with open(LOGF, "a") as f:
            f.write(json.dumps({"ts": time.time(), "event": event, **(extra or {})}) + "\n")
    except Exception:
        pass
def maybe_fail():
    return random.random() < ERR
def main():
    log("start", {"rate": RATE, "avg_size": AVG_SIZE, "err": ERR})

    sys.stdout.write("SNMP honeypot\n")
    sys.stdout.flush()
    log("snmp_resp", None)
    time.sleep(DELAY)

if __name__ == "__main__":
    main()
