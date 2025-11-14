#!/usr/bin/env python3
from http.server import BaseHTTPRequestHandler, HTTPServer
import argparse
from typing import Dict

IMDS_RESPONSES: Dict[str, str] = {
    "/latest/meta-data/": "ami-id\ninstance-id\niam/\nlocal-ipv4\npublic-ipv4\n",
    "/latest/meta-data/instance-id": "i-1234567890abcdef0",
    "/latest/meta-data/ami-id": "ami-0abc1234def567890",
    "/latest/meta-data/local-ipv4": "10.0.0.42",
    "/latest/meta-data/public-ipv4": "54.210.12.34",
    "/latest/meta-data/iam/": "info\nsecurity-credentials/\n",
    "/latest/meta-data/iam/info": '{"Code": "Success", "Message": "No role assigned"}',
    "/latest/meta-data/iam/security-credentials/": "example-role\n",
    "/latest/meta-data/iam/security-credentials/example-role": (
        "{\n"
        '  "Code": "Success",\n'
        '  "LastUpdated": "2024-01-01T00:00:00Z",\n'
        '  "Type": "AWS-HMAC",\n'
        '  "AccessKeyId": "ASIAEXAMPLE",\n'
        '  "SecretAccessKey": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYzEXAMPLEKEY",\n'
        '  "Token": "IQoJb3JpZ2luX2VjEI3//////////wEaCXVzLWVhc3QtMSJHMEUCIQDD",\n'
        '  "Expiration": "2024-01-01T06:00:00Z"\n'
        "}"
    ),
}


class InstanceMetadataRequestHandler(BaseHTTPRequestHandler):
    server_version = "IMDSSimulator/1.0"

    def do_GET(self) -> None:
        response = IMDS_RESPONSES.get(self.path)
        if response is None:
            self.send_error(404, "Not Found")
            return

        body = response.encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "text/plain; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format: str, *args) -> None:  # noqa: D401
        """Silence default logging."""
        return


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Simulate AWS Instance Metadata Service responses."
    )
    parser.add_argument("--host", default="127.0.0.1", help="Bind address (default: 127.0.0.1)")
    parser.add_argument("--port", type=int, default=8000, help="Port number (default: 8000)")
    args = parser.parse_args()

    server = HTTPServer((args.host, args.port), InstanceMetadataRequestHandler)
    print(f"IMDS simulator serving on http://{args.host}:{args.port}")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
        print("IMDS simulator stopped.")


if __name__ == "__main__":
    main()