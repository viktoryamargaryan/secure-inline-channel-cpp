# Secure Inline TCP Channel (Linux / C++)

A lab prototype for the one-way path:

```text
PC1 -> Device1 -> Device2 -> PC2
```

Device1 and Device2 are Linux routers. Device1 intercepts selected forwarded IPv4/TCP packets and encrypts only the TCP application payload with AES-256-GCM. Device2 verifies the GCM tag, decrypts the payload, removes the per-packet crypto metadata, recalculates IPv4/TCP checksums, and forwards the restored packet to PC2.

## Important packet-format clarification

AES-GCM decryption requires the receiver to know the 96-bit nonce. Since the requested data path has no UDP encapsulation and no separate IP/TCP custom header, this prototype carries the nonce as the first 12 bytes of the modified TCP payload:

```text
Original:  [IP header][TCP header][plaintext]
On link:   [same IP header][same TCP header][12-byte nonce][ciphertext][16-byte GCM tag]
At PC2:    [same IP header][same TCP header][plaintext]
```

The IP and TCP headers are preserved in meaning; IPv4 total length and the IP/TCP checksums are recalculated because the payload length changes. If the assignment forbids even a 12-byte nonce inside the TCP payload, then the requirements are not implementable as written: the receiver has no way to recover a fresh nonce for each packet without carrying it or deriving it from a guaranteed-unique visible field. Do not silently assume TCP sequence numbers are unique packet nonces; retransmissions can reuse sequence numbers.

## Scope of this prototype

- Protects only the selected **PC1 -> PC2** TCP direction and destination port (default 5001).
- Uses an authenticated X25519 Diffie-Hellman handshake over a separate TCP control connection (default port 9000).
- Uses a pre-shared 32-byte key (PSK) to authenticate the ephemeral DH public keys and prevent a simple man-in-the-middle attack. Copy the same PSK to both devices securely, outside this channel.
- Derives an AES-256-GCM session key using HKDF-SHA256.
- Uses a 96-bit nonce made from a random 32-bit session prefix plus a monotonically increasing 64-bit counter. The counter never repeats within a session; the program refuses to continue if it is exhausted. A fresh DH handshake creates a fresh key for a new session.
- Authenticates a canonicalized copy of the IP/TCP headers as GCM additional authenticated data (AAD). Length/checksum fields and TTL are zeroed for AAD because they change during forwarding/rewrite.
- Drops packets with invalid GCM tags.

This is an educational prototype, not a production VPN or a drop-in secure transport. It accepts one handshake per process run. It does not support IPv6, TCP fragmentation edge cases, bidirectional payload encryption, NAT between the devices, failover, replay-window policy, or high availability. The lab uses MTU 2000 on host-facing links and 2100 on the Device1-to-Device2 link to leave room for the 28 bytes added per protected segment. A real deployment needs a deliberate MTU/MSS strategy and broader testing. The control handshake is not automatically encrypted as an application channel; it is protected by the PSK-authenticated handshake and used only to establish the data key.

## 1. Dependencies (Ubuntu/Debian)

```bash
sudo apt update
sudo apt install -y build-essential cmake pkg-config libssl-dev \
  libnetfilter-queue-dev iproute2 iptables tcpdump netcat-openbsd
```

## 2. Build

```bash
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build -j
```

The binary is `build/secure_inline`.

## 3. Create a lab with four Linux network namespaces

Run from the project directory:

```bash
sudo ./scripts/setup_lab.sh
```

The script creates:

| Namespace | Interface / address | Role |
|---|---|---|
| `pc1` | `eth0: 10.0.1.2/24` | Sender host |
| `device1` | `eth0: 10.0.1.1/24`, `eth1: 10.0.2.1/24` | Encrypting inline router |
| `device2` | `eth0: 10.0.2.2/24`, `eth1: 10.0.3.1/24` | Decrypting inline router |
| `pc2` | `eth0: 10.0.3.2/24` | Receiver host |

Check ordinary routing before enabling packet processing:

```bash
sudo ip netns exec pc1 ping -c 2 10.0.3.2
```

## 4. Create and copy a PSK

```bash
./scripts/create_psk.sh psk.hex
```

For the single-machine namespace lab, one file is enough. In a real two-device deployment, transfer the same file to both devices using a secure out-of-band method and restrict its permissions (`chmod 600 psk.hex`). Never commit the real PSK to GitHub. Commit only a placeholder such as `psk.hex.example`.

## 5. Start Device2 first

Terminal 1:

```bash
sudo ip netns exec device2 ./build/secure_inline \
  --role receiver --listen 10.0.2.2 --control-port 9000 \
  --psk ./psk.hex --src 10.0.1.2 --dst 10.0.3.2 --dport 5001
```

The process waits for Device1's authenticated handshake.

## 6. Start Device1

Terminal 2:

```bash
sudo ip netns exec device1 ./build/secure_inline \
  --role sender --peer 10.0.2.2 --control-port 9000 \
  --psk ./psk.hex --src 10.0.1.2 --dst 10.0.3.2 --dport 5001
```

Both terminals should report that the authenticated session was established and that their NFQUEUE handler is `READY`.

## 7. Enable NFQUEUE rules only after both programs say READY

Terminal 3:

```bash
sudo ./scripts/enable_queue.sh
```

This ordering is intentional. The script also marks the selected flow `NOTRACK` in the Linux raw table: because the on-link TCP payload temporarily grows by 28 bytes while TCP sequence numbers remain unchanged, conntrack must not interpret that intermediate representation as an ordinary end-to-end TCP stream. Do not use `--queue-bypass`: if the userspace process is absent, protected traffic should not silently pass in plaintext.

## 8. Send a test TCP message

Terminal 4: start a TCP listener on PC2:

```bash
sudo ip netns exec pc2 nc -l 5001
```

Terminal 5: send from PC1:

```bash
printf 'Hello from PC1 - this should be encrypted between the devices!\n' | \
  sudo ip netns exec pc1 nc -N 10.0.3.2 5001
```

The PC2 terminal should display the original readable message.

## 9. Verify the protected segment with tcpdump/Wireshark

Capture on the Device1-to-Device2 link (encrypted payload should be visible):

```bash
sudo ip netns exec device1 tcpdump -ni eth1 -s 0 -X 'tcp port 5001'
```

Capture on Device2's PC2-facing interface (decrypted payload should be visible):

```bash
sudo ip netns exec device2 tcpdump -ni eth1 -s 0 -X 'tcp port 5001'
```

You can also open Wireshark on the corresponding veth interface if you run the lab in a VM with GUI support. On the middle link, the TCP payload begins with 12 nonce bytes and ends with a 16-byte GCM tag; the bytes between them should not contain the original readable message. On the PC2-facing link, the original payload should be readable.

## 10. Cleanup

Stop the two `secure_inline` processes with Ctrl+C, then run:

```bash
sudo ./scripts/disable_queue.sh
sudo ./scripts/cleanup_lab.sh
```

## Troubleshooting

- `nfq_open()` / `nfq_create_queue()` fails: run as root, install `libnetfilter-queue-dev`, ensure the kernel NFQUEUE module is available, and confirm no other process owns queue 0 in that namespace.
- Handshake fails: start Device2 first; ensure both sides use the same PSK; check that Device1 can reach `10.0.2.2:9000`.
- Traffic hangs: ensure both programs show `READY` before adding NFQUEUE rules. Check that the rules exist with `ip netns exec device1 iptables -vnL FORWARD` and the same on Device2.
- GCM authentication fails: verify that no NAT, TCP proxy, or packet mangling occurs between the two devices. Check that both processes belong to the same handshake session.
- Large packets fail: this lab sets MTU 2000. A real network needs MSS clamping or another explicit strategy to account for the 28-byte per-packet overhead.

## GitHub safety

Recommended files to commit:

- `CMakeLists.txt`
- `README.md`
- `src/main.cpp`
- `scripts/*.sh`
- `.gitignore`

Do **not** commit `psk.hex`, private keys, packet captures containing real user data, or other secrets. Add `psk.hex` to `.gitignore`.
