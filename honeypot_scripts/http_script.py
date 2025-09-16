#!/usr/bin/env python3
import os, sys, time, json, random
RATE = float(os.getenv("RATE","5"))
AVG_SIZE = float(os.getenv("SIZE","500"))
ERR = float(os.getenv("ERR","0.05"))
DELAY = max(0.01, 1.0/(RATE+1e-6))  # inter-arrival proxy
LOGF = os.path.join(".", "log", "honeyd", "http.log")
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

    try:
        # Minimal HTTP 200 page
        body = "<html><body><h1>It works</h1></body></html>"
        if maybe_fail():
            sys.stdout.write("HTTP/1.1 500 Internal Server Error\r\nContent-Length: 0\r\n\r\n")
            log("http_500", {{"size": 0}})
        else:
            sys.stdout.write("HTTP/1.1 200 OK\r\nServer: mini\r\nContent-Type: text/html\r\nContent-Length: {}\r\n\r\n".format(len(body)))
            sys.stdout.write(body)
            log("http_200", {{"size": len(body)}})
        sys.stdout.flush()
        time.sleep(DELAY)
    except Exception as e:
        log("error", {{"err": str(e)}})

if __name__ == "__main__":
    main()
