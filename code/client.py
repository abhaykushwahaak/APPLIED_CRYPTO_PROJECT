"""Terminal chat client for the RC4 educational communication project."""
import getpass
import json
import socket
import threading

from rc4_crypto import encrypt_message, decrypt_message

DEFAULT_HOST = "127.0.0.1"
DEFAULT_PORT = 5000
MAX_LINE = 1_000_000


def receive_messages(sock, password, stop_event):
    stream = sock.makefile("rb")
    while not stop_event.is_set():
        try:
            line = stream.readline(MAX_LINE + 1)
            if not line:
                print("\n[!] Server closed the connection.")
                stop_event.set()
                break
            packet = json.loads(line.decode("utf-8"))
            sender = str(packet.get("sender", "unknown"))
            plaintext = decrypt_message(packet["envelope"], password)
            print(f"\n{sender}: {plaintext}\n> ", end="", flush=True)
        except (ValueError, KeyError, TypeError, AttributeError, json.JSONDecodeError) as exc:
            print(f"\n[!] Could not verify/decrypt a message: {exc}\n> ", end="", flush=True)
        except OSError:
            stop_event.set()
            break


def main():
    print("=== RC4 Secure Text Communication (coursework demo) ===")
    print("Use the same shared password on both clients.")
    host = input(f"Relay host [{DEFAULT_HOST}]: ").strip() or DEFAULT_HOST
    port_text = input(f"Relay port [{DEFAULT_PORT}]: ").strip() or str(DEFAULT_PORT)
    try:
        port = int(port_text)
        if not 1 <= port <= 65535:
            raise ValueError
    except ValueError:
        print("Invalid port.")
        return

    username = input("Your display name: ").strip()[:40] or "anonymous"
    password = getpass.getpass("Shared chat password: ")
    if not password:
        print("Password cannot be empty.")
        return

    try:
        sock = socket.create_connection((host, port), timeout=10)
        sock.settimeout(None)
    except OSError as exc:
        print(f"Could not connect to {host}:{port}: {exc}")
        return

    stop_event = threading.Event()
    receiver = threading.Thread(
        target=receive_messages, args=(sock, password, stop_event), daemon=True
    )
    receiver.start()
    print("\nConnected. Type a message and press Enter. Type /quit to exit.")
    try:
        while not stop_event.is_set():
            message = input("> ")
            if message.strip().lower() == "/quit":
                break
            if not message:
                continue
            packet = {
                "sender": username,
                "envelope": encrypt_message(message, password),
            }
            sock.sendall((json.dumps(packet) + "\n").encode("utf-8"))
    except (KeyboardInterrupt, EOFError):
        pass
    except OSError as exc:
        print(f"Network error: {exc}")
    finally:
        stop_event.set()
        try:
            sock.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass
        sock.close()
        print("Disconnected.")


if __name__ == "__main__":
    main()
