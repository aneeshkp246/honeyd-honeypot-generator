#!/usr/bin/env python3
import os, sys, time, json, random
RATE = float(os.getenv("RATE","5"))
AVG_SIZE = float(os.getenv("SIZE","500"))
ERR = float(os.getenv("ERR","0.05"))
DELAY = max(0.01, 1.0/(RATE+1e-6))  # inter-arrival proxy
LOGF = os.path.join(".", "log", "honeyd", "smtp.log")
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

    sys.stdout.write("220 smtp honeypot\r\n")
    sys.stdout.flush()
    time.sleep(DELAY)
    sys.stdout.write("250 OK\r\n")
    sys.stdout.flush()
    log("smtp_ok", None)

if __name__ == "__main__":
    main()
