# Security Design

This document describes the threat model, the protocol that protects chat and voice traffic, and its known limitations.

## Why this exists

The [course submission](https://github.com/sterlouk/secure-udp-chat-voip/tree/course-submission) sent chat text and raw PCM audio as **plaintext UDP datagrams**, and it accepted any packet that reached its ports. Anyone on the same network (shared Wi-Fi, a compromised router, anything on the path) could:

- **Eavesdrop:** read every message and play back the call audio with Wireshark.
- **Inject:** send text or audio that appears to come from the peer. UDP source addresses are trivially spoofed, and the app performed no checks.
- **Replay:** capture packets and resend them later.

## Threat model

| Attacker | Capability | In scope |
|---|---|---|
| Passive eavesdropper | Sees all packets between the peers | ✅ |
| Active network attacker | Can inject, modify, drop, reorder, replay and reflect packets; can spoof source IPs | ✅ |
| Attacker who knows the passphrase | Is, by definition, a legitimate peer | ❌ |
| Malware on a peer's machine | Can read the screen, mic and memory | ❌ |
| Traffic analysis | Learns *who* talks to whom and *when* | ❌ (see limitations) |

**Goals:** confidentiality and integrity of every chat message and audio frame, authentication of the sender as "someone who knows the passphrase", and rejection of replayed, reflected or stale packets.

## Protocol

### Key derivation

Both peers enter the same passphrase, of at least 12 characters. It is stretched into a 256-bit AES key:

```
key = PBKDF2-HMAC-SHA256(passphrase, salt = "cn2-chat-voip/v1", iterations = 600,000, length = 256 bits)
```

600,000 iterations follows the [OWASP recommendation](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html#pbkdf2) for PBKDF2-HMAC-SHA256. The passphrase `char[]` is zeroed after derivation and never stored or sent.

### Packet format

Every chat message and every 32 ms audio frame is sent as one datagram:

```
+---------+------+-----------+----------+--------------+----------+----------------------+
| version | type | sender id | sequence | timestamp ms |  nonce   | ciphertext + GCM tag |
|   1 B   | 1 B  |    8 B    |   8 B    |     8 B      |  12 B    |      n + 16 B        |
+---------+------+-----------+----------+--------------+----------+----------------------+
 \_______________ header: authenticated (AAD) but not encrypted _/
```

- **AES-256-GCM** encrypts the payload and authenticates both the payload and the header. Changing any bit anywhere in the packet makes the tag check fail.
- **Nonce:** 96 random bits from `SecureRandom`, fresh for every packet.
- **Sender id:** 64 random bits chosen once per run, which identifies the session.
- **Sequence:** a counter per sender and per type (chat/voice).
- **Overhead:** 54 bytes per packet.

### Receive checks

Packets are checked in this order. Every check before decryption is read-only, so a packet that fails authentication cannot change any receiver state.

| Check | Rejects | Defends against |
|---|---|---|
| Length ≥ 54 B, `version == 1` | `MALFORMED` | Garbage / fuzzing |
| `type` matches the port (chat vs voice) | `WRONG_TYPE` | Cross-protocol confusion |
| `sender id ≠ my own` | `REFLECTED` | Reflection: an attacker bouncing my packets back at me |
| `|now − timestamp| ≤ 60 s` | `STALE` | Replaying old captures |
| Sequence not already seen (64-packet sliding window per sender and type, as in IPsec/DTLS) | `REPLAYED` | Replay within the 60 s window; reordering is tolerated |
| AES-GCM tag verifies | `AUTH_FAILED` | Tampering, forgery, wrong passphrase |

Rejected packets are counted and reported in the UI. The chat warning is rate-limited to one notice every 5 seconds, so a flood can't spam the window.

### Verification

[`SecureChannelTest`](src/test/java/com/cn2/communication/SecureChannelTest.java) covers each row above:

- every single-bit flip in a packet is rejected;
- a wrong passphrase, a replay, a reflection, a type confusion, a stale timestamp and a truncated packet are each rejected;
- a forged packet claiming a huge sequence number does not lock out legitimate traffic;
- a round trip over real UDP sockets works.

## Known limitations

These are trade-offs I chose for a two-person, no-dependency app. Each one notes what a production system would do instead.

1. **Pre-shared passphrase, so no forward secrecy.** Anyone who later learns the passphrase can decrypt previously recorded traffic. *Production:* an authenticated ephemeral key exchange (X25519 ECDH) with a short authentication string the users compare out-of-band, as in ZRTP and Signal.
2. **Offline guessing of weak passphrases.** One captured packet is enough to test guesses offline. PBKDF2 at 600k iterations makes each guess expensive, but a short or common passphrase can still be cracked. The salt is fixed, because the peers have no channel to agree on a random one, so precomputed tables built for this app would work against every user. *Production:* a PAKE (e.g. CPace/OPAQUE), or the key exchange above.
3. **Same key in both directions.** Safe here because nonces are random and the sender id is authenticated. Per-direction keys derived with HKDF would be cleaner.
4. **Replay after a receiver restart.** Replay windows live in memory. If a receiver restarts, packets captured in the previous 60 seconds can be replayed once. The timestamp check bounds this to 60 s.
5. **Clocks must agree within 60 seconds.** Otherwise all packets are rejected as `STALE`.
6. **Metadata is visible:**
   - IP addresses and ports;
   - packet timing;
   - chat message lengths;
   - when someone is muted, because no packets are sent.

   Audio frames are a constant size, so speech content does not leak through packet length (unlike variable-bitrate codecs).
7. **Denial of service.** UDP can be flooded, and nothing rate-limits the receiver. Bad packets are rejected cheaply, but a flood can still saturate the link.
8. **Random-nonce bound.** With 96-bit random nonces, NIST recommends at most 2³² packets per key. At ~31 voice packets/s that is about 4 years of continuous talk, far beyond any session.

## Reporting

This is a portfolio project. If you spot a flaw in the design, please open an issue.
