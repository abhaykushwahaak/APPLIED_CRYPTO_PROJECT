"""Security verification: eavesdropping, unauthorized access, tampering, replay, key attacks."""
import base64
import json
import socket
import threading
import time

from rc4_crypto import decrypt_message, encrypt_message
from server import RelayHandler, ThreadedRelay

PASSWORD = "correct horse battery staple"


def show(name, ok, note=""):
    print(f"[{'PASS' if ok else 'FAIL'}] {name} {note}")
    return ok


def rejects(envelope, password):
    try:
        decrypt_message(envelope, password)
        return False
    except ValueError:
        return True


def tamper(envelope, field):
    raw = bytearray(base64.b64decode(envelope[field]))
    raw[0] ^= 0x01
    bad = dict(envelope)
    bad[field] = base64.b64encode(bytes(raw)).decode()
    return bad


def main():
    results = []
    msg = "Transfer 5000 euros to account 12345"
    env1, env2 = encrypt_message(msg, PASSWORD), encrypt_message(msg, PASSWORD)

    print("\n1) EAVESDROPPING")
    wire = json.dumps(env1).encode()
    results.append(show("Plaintext not visible in captured packet", b"Transfer" not in wire))
    results.append(show("Same message gives different ciphertext each time", env1["ciphertext"] != env2["ciphertext"]))

    print("\n2) UNAUTHORIZED ACCESS (relay sniffer / wrong password)")
    relay = ThreadedRelay(("127.0.0.1", 0), RelayHandler)
    port = relay.server_address[1]
    threading.Thread(target=relay.serve_forever, daemon=True).start()
    alice = socket.create_connection(("127.0.0.1", port))
    intruder = socket.create_connection(("127.0.0.1", port))
    time.sleep(0.4)
    alice.sendall((json.dumps({"sender": "alice", "envelope": env1}) + "\n").encode())
    stolen = json.loads(intruder.makefile("rb").readline())["envelope"]
    results.append(show("Intruder on relay receives only ciphertext", msg not in json.dumps(stolen)))
    results.append(show("Intruder with wrong password cannot decrypt", rejects(stolen, "guess123")))
    alice.close(); intruder.close(); relay.shutdown(); relay.server_close()

    print("\n3) MESSAGE TAMPERING")
    for field in ("ciphertext", "salt", "tag"):
        results.append(show(f"Modified {field} detected", rejects(tamper(env1, field), PASSWORD)))
    results.append(show("Untouched message still decrypts", decrypt_message(env1, PASSWORD) == msg))

    print("\n4) KEY ATTACKS")
    weak_env = encrypt_message("hello", "sunshine")
    wordlist = ["123456", "password", "qwerty", "letmein", "sunshine"]
    t0 = time.perf_counter()
    cracked = next((w for w in wordlist if not rejects(weak_env, w)), None)
    results.append(show("Weak password found by dictionary attack (shows risk)",
                        cracked == "sunshine", f"-> {cracked!r} in {time.perf_counter()-t0:.2f}s"))
    results.append(show("Strong passphrase not in wordlist -> attack fails",
                        all(rejects(env1, w) for w in wordlist)))
    print("      PBKDF2 (150k iterations) slows each guess; still, use a long random password.")

    print("\n5) REPLAY (known limitation of this design)")
    try:
        replay_ok = decrypt_message(env1, PASSWORD) == msg
    except ValueError:
        replay_ok = False
    show("Replayed old packet is accepted (NOT prevented - listed in README)", replay_ok)

    print(f"\nSUMMARY: {sum(results)}/{len(results)} checks passed")


if __name__ == "__main__":
    main()
