import json
import socket
import subprocess
import sys
import threading
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import tunnelscope


class DeliveryTests(unittest.TestCase):
    def test_real_receiver_acknowledges_requested_sizes(self):
        process = subprocess.Popen(
            [sys.executable, str(Path(tunnelscope.__file__)), "receive", "--port", "0", "--max-packets", "3", "--idle-timeout", "3"],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
        )
        try:
            port = int(process.stdout.readline().strip().rsplit(":", 1)[1])
            report = tunnelscope.probe("127.0.0.1", port, [32, 1400, 8192], 1, 1)
            self.assertEqual([r["status"] for r in report["results"]], ["acknowledged"] * 3)
            self.assertEqual([r["payload_bytes"] for r in report["results"]], [32, 1400, 8192])
            self.assertEqual(json.loads(json.dumps(report))["schema_version"], 1)
            self.assertEqual(process.wait(timeout=4), 0)
        finally:
            if process.poll() is None:
                process.kill()
                process.wait()
            process.stdout.close()
            process.stderr.close()

    def test_unrelated_ack_is_not_counted_as_delivery(self):
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as server:
            server.bind(("127.0.0.1", 0))
            server.settimeout(3)
            def wrong_reply():
                _, peer = server.recvfrom(8192)
                server.sendto(tunnelscope.HEADER.pack(tunnelscope.ACK, b"x" * 16, 64), peer)
            worker = threading.Thread(target=wrong_reply)
            worker.start()
            try:
                report = tunnelscope.probe("127.0.0.1", server.getsockname()[1], [64], 1, 1)
                self.assertEqual(report["results"][0]["status"], "timeout")
            finally:
                worker.join(timeout=4)

    def test_probe_cli_rejects_excessive_payload(self):
        result = subprocess.run([sys.executable, str(Path(tunnelscope.__file__)), "probe", "127.0.0.1", "--sizes", "99999"], capture_output=True, text=True, timeout=5)
        self.assertEqual(result.returncode, 2)
        self.assertIn("32..8192", result.stderr)


if __name__ == "__main__":
    unittest.main()
