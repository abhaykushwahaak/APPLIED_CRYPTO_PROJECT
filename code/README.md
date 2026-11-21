# Project 4 — RC4-Based Secure Text Communication System

## 1. Project overview
A Python terminal chat application in which two or more clients exchange text through a TCP relay. Each client encrypts messages before sending them. The relay forwards encrypted JSON packets and does not receive the plaintext.

The coursework implementation uses RC4 for the stream-cipher demonstration, PBKDF2-HMAC-SHA256 to derive per-message keys from a shared password, and HMAC-SHA256 to detect message modification or an incorrect password.

**Important security note:** RC4 is obsolete and has known statistical weaknesses. Adding HMAC does not make RC4 suitable for real-world secure messaging. This project is an educational implementation only. For a real application, use a modern authenticated-encryption scheme such as AES-GCM or ChaCha20-Poly1305 over TLS.

## 2. Requirements
- Python 3.10 or newer
- Windows, macOS, or Linux
- Internet access once, to install PyCryptodome
- Two terminal windows for testing two chat users

## 3. Files
- `server.py` — TCP relay server; forwards encrypted packets
- `client.py` — chat client; encrypts outgoing messages and decrypts incoming messages
- `rc4_crypto.py` — RC4 encryption, PBKDF2 key derivation, HMAC verification
- `benchmark.py` — local encryption/decryption timing and throughput
- `test_rc4.py` — unit tests
- `security_tests.py` — eavesdropping, unauthorized access, tampering, key-attack and replay checks
- `requirements.txt` — dependency list

## 4. Installation (Windows)
1. Install Python 3.10+ from https://www.python.org/downloads/.
2. During installation, tick **Add Python to PATH**.
3. Create or extract this project folder.
4. Open Command Prompt in the project folder.
5. Create a virtual environment:
   ```bat
   py -m venv .venv
   ```
6. Activate it:
   ```bat
   .venv\Scripts\activate
   ```
7. Install the dependency:
   ```bat
   python -m pip install --upgrade pip
   pip install -r requirements.txt
   ```

## 5. Run the application
### Terminal 1 — start the relay
```bat
python server.py
```
Keep this terminal open. It listens on port 5000.

### Terminal 2 — first user
```bat
python client.py
```
For a single-computer test, press Enter for the relay host (`127.0.0.1`) and port (`5000`). Enter a display name and a shared password.

### Terminal 3 — second user
Run `python client.py` again. Use the same host, port, and exact same shared password, but a different display name.

Type a message in either client. The other client should see the decrypted message. Type `/quit` to leave.

### Testing across two computers on the same network
- Run the server on one computer.
- Find that computer's LAN IP address.
- On both clients, enter that LAN IP as the relay host.
- Allow TCP port 5000 through the server computer's firewall only on a trusted private network.
- Both clients must use the same shared password.
- Do not expose this educational server to the public internet.

## 6. Run tests
With the virtual environment active:
```bat
python -m unittest -v
python security_tests.py
```
The tests check a standard RC4 test vector, successful encryption/decryption, rejection of a wrong password, and detection of a modified message.

## 7. Performance evaluation
Run:
```bat
python benchmark.py
```
The program reports average local encryption/decryption time (including password-based key derivation) and approximate throughput. For a network latency observation, run the relay and two clients, send several messages, and record the time between sending and display at the receiving client. Results depend on CPU, message length, and network conditions.

## 8. How the system works
1. The sender creates a random 16-byte salt for each message.
2. PBKDF2-HMAC-SHA256 derives separate encryption and authentication keys from the shared password and salt.
3. RC4 encrypts the UTF-8 message.
4. HMAC-SHA256 authenticates the salt and ciphertext.
5. The sender sends a JSON packet containing the sender label and encrypted envelope.
6. The relay forwards the packet without decrypting it.
7. The receiver derives the same keys, verifies HMAC first, and only then decrypts the ciphertext.

## 9. Security evaluation
| Threat / property | Result in this coursework design |
|---|---|
| Passive eavesdropping on relay traffic | Plaintext is not sent to the relay; RC4 itself is obsolete and weak |
| Message tampering | HMAC verification detects modification |
| Wrong shared password | HMAC verification fails |
| Replay of an old valid packet | Not prevented by this basic version |
| Key sharing / key theft | Users must share the password securely; a stolen password compromises messages |
| Traffic analysis | Sender labels, timing, and packet sizes remain visible to the relay |

## 10. Limitations and future improvements
- Replace RC4 with AES-GCM or ChaCha20-Poly1305 for real security.
- Add user authentication and secure key exchange instead of manually sharing one password.
- Add replay protection using message counters or unique message identifiers.
- Use TLS to protect client-to-relay network connections.
- Add a graphical interface, message history, and delivery acknowledgements.

## 11. Conclusion
The project demonstrates stream-cipher encryption, password-based key derivation, message authentication, and socket-based communication. It also shows why encryption alone is not enough: integrity checks are needed to detect tampering. RC4 is included to meet the coursework topic, not as a recommendation for modern secure communication.
