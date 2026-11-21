"""Simple TCP relay. It forwards encrypted packets and does not decrypt them."""
import json
import socketserver
import threading

MAX_LINE = 1_000_000


class RelayHandler(socketserver.StreamRequestHandler):
    def handle(self):
        peer = f"{self.client_address[0]}:{self.client_address[1]}"
        lock = threading.Lock()
        with self.server.clients_lock:
            self.server.clients[self.request] = lock
        print(f"[+] Connected: {peer}")

        try:
            while True:
                line = self.rfile.readline(MAX_LINE + 1)
                if not line:
                    break
                if len(line) > MAX_LINE or not line.endswith(b"\n"):
                    print(f"[!] Rejected oversized/malformed packet from {peer}")
                    break
                try:
                    packet = json.loads(line.decode("utf-8"))
                    if not isinstance(packet, dict) or "envelope" not in packet:
                        continue
                    # Forward only the encrypted envelope and sender label.
                    clean_packet = {
                        "sender": str(packet.get("sender", "anonymous"))[:40],
                        "envelope": packet["envelope"],
                    }
                    outgoing = (json.dumps(clean_packet) + "\n").encode("utf-8")
                except (UnicodeDecodeError, json.JSONDecodeError, TypeError):
                    continue

                with self.server.clients_lock:
                    recipients = list(self.server.clients.items())
                for client_socket, send_lock in recipients:
                    if client_socket is self.request:
                        continue
                    try:
                        with send_lock:
                            client_socket.sendall(outgoing)
                    except OSError:
                        pass
        finally:
            with self.server.clients_lock:
                self.server.clients.pop(self.request, None)
            print(f"[-] Disconnected: {peer}")


class ThreadedRelay(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True

    def __init__(self, address, handler):
        super().__init__(address, handler)
        self.clients = {}
        self.clients_lock = threading.Lock()


if __name__ == "__main__":
    host = "0.0.0.0"
    port = 5000
    with ThreadedRelay((host, port), RelayHandler) as server:
        print(f"RC4 chat relay listening on {host}:{port}")
        print("Press Ctrl+C to stop.")
        try:
            server.serve_forever()
        except KeyboardInterrupt:
            print("\nStopping relay...")
