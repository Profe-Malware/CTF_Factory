# ChumBucket

**A network-forensics CTF challenge forge.**

ChumBucket chums the water with realistic background traffic and decoy flags,
then hides the real catch inside a `.pcap` for your players to fish out. It
generates capture files for blue-team / DFIR challenges — controlled volumes of
plausible traffic per protocol, a flag hidden by one of several techniques (or
buried inside a simulated attack), and an answer key that documents the exact
solve path.

> ChumBucket produces capture **files** for analysis puzzles. It does not send
> anything on a network.

Part of the [CTF Factory](../) suite.

---

## Why

Hand-building a packet-capture challenge is slow, and the result usually looks
fake — one packet with content surrounded by empty noise, so players solve it by
spotting the odd packet instead of doing real forensics. Worse, a bare artifact
can often be dropped straight into an LLM and solved in seconds.

ChumBucket fixes that: one command produces a believable capture where the flag
is hard because it's genuinely *hidden*, not because everything else is
conspicuously empty.

---

## Requirements

- Python 3.10+
- [`scapy`](https://scapy.net/) — `pip install scapy`
- Optional: [`rich`](https://github.com/Textualize/rich) for the styled banner,
  menu, and progress bar — `pip install rich` (degrades gracefully without it)

## Install

```bash
git clone https://github.com/Profe-Malware/CTF_Factory.git
cd CTF_Factory/chumbucket
pip install scapy rich
```

## Usage

Run it interactively (a guided builder walks you through every choice):

```bash
python chumbucket.py
```

Or drive it with flags for scripting a whole competition:

```bash
# A Kerberoasting scenario, reproducible via a fixed seed
python chumbucket.py --scenario kerberoast --flag "spn_hunter" --seed 1337 -o ad_round1

# DNS exfil with a Base32 + XOR layer
python chumbucket.py --method dns --encode base32 --xor s3cret --flag "you_found_me" -o dns_round1
```

Each run drops a `.pcap` and its answer key into their own folder under
`ChumOutput/`.

---

## What it produces

**Realistic traffic** — full TCP handshakes with proper options and window
sizes, HTTP request/response with real headers and gzip-compressed bodies,
TLS-looking sessions, DNS query/answer pairs, ICMP, ARP, and DHCP — all between a
consistent set of hosts (clients, gateway, resolver, servers) with proper MACs
and sequence numbers.

**Hidden-flag methods** (pure data puzzles):
- `dns` — encoded flag scattered across DNS subdomain labels (exfil)
- `split-tcp` / `split-icmp` — flag split across payloads, reassembled by index
- `http` — flag buried in an HTTP session cookie

**Attack scenarios** (recognize the attack, then extract the flag):
Kerberoasting, plaintext FTP/Telnet/HTTP-Basic credentials, ARP spoofing, port
scanning, brute force, C2 beaconing, rogue DHCP, SSDP/UPnP abuse, DNS-over-HTTPS
beaconing, DGA beaconing, malware download chains, ransomware notes, and
pastebin dead-drop exfil.

**Encodings & obfuscation** — `hex`, `base64`, `base32`, `base58`, `urlencode`,
plus an optional `--xor` layer. DNS-carrier challenges automatically coerce to a
label-safe encoding.

**Decoy flags** — themed red herrings (`spongebob`, `cyber`, `mixed`, or your own
`custom` word list) so a lazy `strings` sweep returns wrong answers.

---

## The answer key

Every challenge writes a sidecar answer key containing:

- a **player briefing** — the scenario context you can hand to competitors
- the **intended solve path**, step by step
- the exact **decode steps** to recover the flag
- the exact **frame numbers** where the flag lives, for quick verification in
  Wireshark

## Self-check

Before handing you anything, ChumBucket **re-solves its own capture** following
the documented path and confirms it recovers the exact flag you asked for. If it
can't, it tells you loudly — so you never ship an unsolvable challenge.

## Reproducibility

Pass `--seed` and you get the identical challenge every time — easy to share,
regrade, or hand to a co-author.

---

## A note on fidelity

ChumBucket's protocol payloads are **recognizable and solvable** rather than
byte-perfect. Synthetic crypto/credential material (Kerberos tickets, TLS
records, etc.) is realistic enough for forensics puzzles but will not pass the
strictest protocol validators. That's by design — the goal is fair, solvable
challenges, not a protocol simulator.

---

## License

Released under the MIT License. See [LICENSE](../LICENSE).

*Created by Profe Malware.*
