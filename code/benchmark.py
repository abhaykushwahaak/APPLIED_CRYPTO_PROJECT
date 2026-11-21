"""Performance evaluation for different message lengths:
encryption time, decryption time, relay latency, end-to-end latency, throughput."""
import csv
import json
import socket
import statistics
import threading
import time

from rc4_crypto import decrypt_message, encrypt_message
from server import RelayHandler, ThreadedRelay

PASSWORD = "benchmark-only-password"
SIZES = [16, 64, 256, 1024, 4096, 16384, 65536]  # message length in bytes
ROUNDS = 5  # PBKDF2 makes every message costly, so keep this small


def main():
    relay = ThreadedRelay(("127.0.0.1", 0), RelayHandler)
    port = relay.server_address[1]
    threading.Thread(target=relay.serve_forever, daemon=True).start()

    sender = socket.create_connection(("127.0.0.1", port))
    receiver = socket.create_connection(("127.0.0.1", port))
    reader = receiver.makefile("rb")
    time.sleep(0.5)  # let the relay register both clients

    print(f"{'Size(B)':>8} {'Enc(ms)':>9} {'Dec(ms)':>9} {'Relay(ms)':>10} "
          f"{'EndToEnd(ms)':>13} {'Throughput(KiB/s)':>18}")
    rows = []
    for size in SIZES:
        msg = "A" * size
        enc, dec, relay_t, total = [], [], [], []
        for _ in range(ROUNDS):
            t0 = time.perf_counter()
            envelope = encrypt_message(msg, PASSWORD)
            t1 = time.perf_counter()
            line = (json.dumps({"sender": "bench", "envelope": envelope}) + "\n").encode()
            sender.sendall(line)
            got = reader.readline()
            t2 = time.perf_counter()
            plain = decrypt_message(json.loads(got)["envelope"], PASSWORD)
            t3 = time.perf_counter()
            assert plain == msg
            enc.append(t1 - t0); relay_t.append(t2 - t1)
            dec.append(t3 - t2); total.append(t3 - t0)
        e, d, r, t = (statistics.mean(x) * 1000 for x in (enc, dec, relay_t, total))
        thr = size / (t / 1000) / 1024
        rows.append([size, e, d, r, t, thr])
        print(f"{size:>8} {e:>9.2f} {d:>9.2f} {r:>10.3f} {t:>13.2f} {thr:>18.2f}")

    sender.close(); receiver.close(); relay.shutdown(); relay.server_close()
    with open("benchmark_results.csv", "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["size_bytes", "encrypt_ms", "decrypt_ms", "relay_ms", "end_to_end_ms", "throughput_KiBps"])
        w.writerows(rows)
    print("\nSaved benchmark_results.csv (use it for graphs in your report).")
    print("Enc/Dec include PBKDF2 key derivation, so they are almost flat across sizes.")


if __name__ == "__main__":
    main()
