#!/usr/bin/env python3
import os, sys, time, json, random
RATE = float(os.getenv("RATE","5"))
AVG_SIZE = float(os.getenv("SIZE","500"))
ERR = float(os.getenv("ERR","0.05"))
DELAY = max(0.01, 1.0/(RATE+1e-6))  # inter-arrival proxy
LOGF = os.path.join(".", "log", "honeyd", "https.log")
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

    sys.stdout.write("HTTP/1.1 200 OK\r\nServer: tls-proxy\r\nContent-Length: 0\r\n\r\n")
    sys.stdout.flush()
    log("https_resp", {{"size": 0}})
    time.sleep(DELAY)

if __name__ == "__main__":
    main()
