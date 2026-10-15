"""
QRShield - Local Development Server
Provides a local HTTP server mirroring the AWS Lambda Function URL for offline testing.
Uses Python standard library (http.server) - no Flask/FastAPI required!
"""

from http.server import HTTPServer, BaseHTTPRequestHandler
import os
import sys

from lambda_function import lambda_handler

PORT = int(os.environ.get("PORT", 8000))


class QRShieldLocalHandler(BaseHTTPRequestHandler):

    def _send_lambda_response(self, response: dict):
        self.send_response(response["statusCode"])
        for header_key, header_val in response.get("headers", {}).items():
            self.send_header(header_key, header_val)
        self.end_headers()
        body = response.get("body", "")
        if body:
            self.wfile.write(body.encode("utf-8"))

    def do_OPTIONS(self):
        event = {
            "requestContext": {"http": {"method": "OPTIONS"}},
            "headers": dict(self.headers)
        }
        resp = lambda_handler(event, None)
        self._send_lambda_response(resp)

    def do_POST(self):
        content_length = int(self.headers.get("Content-Length", 0))
        body_bytes = self.rfile.read(content_length)
        body_str = body_bytes.decode("utf-8", errors="replace")

        event = {
            "requestContext": {
                "http": {
                    "method": "POST",
                    "sourceIp": self.client_address[0]
                }
            },
            "headers": dict(self.headers),
            "body": body_str
        }

        resp = lambda_handler(event, None)
        self._send_lambda_response(resp)

    def do_GET(self):
        # Health check endpoint - same route the deployed Lambda serves
        event = {
            "requestContext": {"http": {"method": "GET"}},
            "headers": dict(self.headers)
        }
        resp = lambda_handler(event, None)
        self._send_lambda_response(resp)

    def log_message(self, format, *args):
        # Standard formatting for request logs
        sys.stderr.write(f"[QRShield Local] {self.address_string()} - {format % args}\n")


def run():
    server_address = ("127.0.0.1", PORT)
    httpd = HTTPServer(server_address, QRShieldLocalHandler)
    print(f"[INFO] QRShield Local Backend running at http://127.0.0.1:{PORT}", flush=True)
    print("Press Ctrl+C to stop.", flush=True)
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\nShutting down local server.")
        httpd.server_close()


if __name__ == "__main__":
    run()
