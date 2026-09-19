#!/usr/bin/env python3
"""Non-mount CLI protocol tests against a local mock server."""
import json
from pathlib import Path
import socket
import struct
import subprocess
import sys
import tempfile
import threading


def main():
    binary = sys.argv[1]
    with tempfile.TemporaryDirectory(prefix="fuse-adaptive-cli-") as directory:
        path = str(Path(directory) / "control.sock")

        def run(arguments, response, expected=0):
            captured = []
            with socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET) as server:
                server.bind(path)
                server.listen(1)
                server.settimeout(5)

                def respond():
                    with server.accept()[0] as client:
                        captured.append(client.recv(4096))
                        client.sendall(response)

                thread = threading.Thread(target=respond)
                thread.start()
                result = subprocess.run(
                    [binary, "--socket", path, *arguments],
                    capture_output=True, text=True, timeout=7)
                thread.join(timeout=6)
                assert not thread.is_alive()
            Path(path).unlink()
            assert result.returncode == expected, result
            assert len(captured) == 1 and len(captured[0]) == 72
            return result.stdout, captured[0]

        output, request = run(["--json", "set-qd", "64"],
                              b'{"error":0,"transaction":42}\n')
        assert json.loads(output)["transaction"] == 42
        assert struct.unpack_from("=4I", request) == (1, 3, 64, 0)
        output, request = run(["status"], b'{"error":0,"queues":[]}\n')
        assert json.loads(output)["queues"] == []
        run(["set-qd", "8"], b'{"error":-16,"transaction":0}\n', 1)
        run(["workload"], b"invalid reply", 1)
        _, request = run(["configure", "--thresholds", "8192,65536,2097152",
                          "--window-ms", "250"], b'{"error":0,"pending":true}\n')
        assert struct.unpack_from("=I", request, 16)[0] == 250
        assert struct.unpack_from("=3Q", request, 48) == (8192, 65536, 2097152)
        for args in (["set-qd", "0"], ["set-qd", "-1"],
                     ["set-qd", "4294967296"], ["status", "extra"],
                     ["configure", "--thresholds", "1,2,-3"],
                     ["configure", "--thresholds", "1,2,18446744073709551616"],
                     ["configure", "--thresholds", "1,1,3"]):
            result = subprocess.run([binary, "--socket", path, *args],
                                    capture_output=True, timeout=3)
            assert result.returncode == 2, args
    print("PASS adaptive CLI framing, JSON, errors and arbitrary thresholds")


if __name__ == "__main__":
    main()
