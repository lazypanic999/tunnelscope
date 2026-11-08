"""Source interface evidence must accept names representable by the OS."""

import ipaddress
import json
import os
from pathlib import Path
import socket
import struct
import subprocess
import sys
import tempfile
import unittest
import uuid
from unittest.mock import Mock, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from tunnelscope_core.network import SIOCGIFADDR, source_snapshot


@unittest.skipUnless(sys.platform.startswith("linux"), "Linux interface snapshot")
class SourceSnapshotTests(unittest.TestCase):
    def test_ipv6_snapshot_keeps_unicode_and_non_utf8_interface_names(self):
        for name in ("tünel0".encode("utf-8"), b"tunnel-\xff"):
            with self.subTest(interface=name), tempfile.TemporaryDirectory() as directory:
                path = Path(directory) / "if_inet6"
                address = "2001:db8::1"
                path.write_bytes(ipaddress.IPv6Address(address).packed.hex().encode("ascii")
                                 + b" 02 40 00 80 " + name + b"\n")
                original_open = open
                def proc_file(_path, *args, **kwargs):
                    return original_open(path, *args, **kwargs)
                sock = Mock(family=socket.AF_INET6)
                sock.getsockname.return_value = (address, 49152, 0, 0)
                sock.getsockopt.return_value = 1500
                with patch("builtins.open", side_effect=proc_file), \
                        patch("fcntl.ioctl", return_value=bytes(16) + struct.pack("I", 1420)):
                    snapshot = source_snapshot(sock)
                self.assertEqual(snapshot["interface"], os.fsdecode(name))
                self.assertEqual(snapshot["interface_mtu_bytes"], 1420)
                self.assertEqual(snapshot["kernel_route_mtu_bytes"], 1500)
                self.assertEqual(snapshot["ipv6"], address)

    def test_ipv4_snapshot_keeps_non_utf8_interface_names(self):
        name = os.fsdecode(b"tunnel-\xff")
        sock = Mock(family=socket.AF_INET)
        sock.getsockname.return_value = ("192.0.2.1", 49152)
        sock.getsockopt.return_value = 1500
        def ioctl(_descriptor, operation, _request):
            return (bytes(20) + socket.inet_aton("192.0.2.1") if operation == SIOCGIFADDR
                    else bytes(16) + struct.pack("I", 1420))
        with patch("socket.if_nameindex", return_value=[(2, name)]), patch("fcntl.ioctl", side_effect=ioctl):
            snapshot = source_snapshot(sock)
        self.assertEqual(snapshot["interface"], name)
        self.assertEqual(snapshot["interface_mtu_bytes"], 1420)

    @unittest.skipUnless(os.environ.get("TUNNELSCOPE_RUN_NETNS_TESTS") == "1", "opt-in privileged Linux namespace")
    def test_real_namespace_accepts_unicode_and_raw_byte_interface_names(self):
        namespace = "ts-name-" + uuid.uuid4().hex[:10]
        def ip(*args):
            return subprocess.run(["ip", *args], check=True, capture_output=True, timeout=10)
        ip("netns", "add", namespace)
        try:
            for index, name in enumerate(("tünel0", os.fsdecode(b"tunnel-\xff")), start=1):
                with self.subTest(interface=repr(name)):
                    ip("-n", namespace, "link", "add", name, "type", "dummy")
                    ip("-n", namespace, "link", "set", name, "mtu", "1420", "up")
                    ip("-n", namespace, "-6", "addr", "add", f"2001:db8:{index}::1/64", "dev", name, "nodad")
                    code = ("import json,socket,sys; from tunnelscope_core.network import source_snapshot; "
                            "s=socket.socket(socket.AF_INET6,socket.SOCK_DGRAM); "
                            "s.connect((sys.argv[1],9471)); print(json.dumps(source_snapshot(s))); s.close()")
                    result = ip("netns", "exec", namespace, sys.executable, "-c", code, f"2001:db8:{index}::2")
                    snapshot = json.loads(result.stdout)
                    self.assertEqual(snapshot["interface"], name)
                    self.assertEqual(snapshot["interface_mtu_bytes"], 1420)
        finally:
            ip("netns", "delete", namespace)


if __name__ == "__main__":
    unittest.main()
