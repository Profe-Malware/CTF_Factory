# CTF Factory

**A growing suite of tools for generating realistic Capture-the-Flag artifacts.**

CTF Factory is a workshop for people who *build* CTF challenges — educators,
red teamers, and competition designers. Each tool in the suite automates the
tedious part of challenge creation: producing a realistic artifact with a flag
genuinely hidden inside, so players have to demonstrate a real skill to recover
it instead of running `strings` and moving on.

The long-term goal is a one-stop shop for challenge authoring — point-and-shoot
generators for a whole range of artifact types, each verified solvable before it
ships.

---

## Tools

| Tool | Artifact | Status |
|------|----------|--------|
| [**ChumBucket**](chumbucket/) | Network-forensics packet captures (`.pcap`) | Active |
| *more on the way* | — | Planned |

### ChumBucket
Generates realistic network-forensics challenges — a `.pcap` full of believable
traffic with a flag hidden inside, surrounded by decoy flags and a documented
answer key. Supports pure data-hiding puzzles (DNS exfil, stream reassembly,
encoded payloads) and recognizable attack scenarios (Kerberoasting, C2
beaconing, ARP spoofing, DGA lookups, ransomware, and more). Every challenge is
re-solved automatically to confirm the flag is recoverable before you ship it.

➡️ **[See the ChumBucket README for full usage.](chumbucket/README.md)**

---

## Philosophy

- **Automated by default, customizable when you need it.** Each tool works out
  of the box with sensible defaults, and exposes options for authors who want
  fine control.
- **Realistic, not just present.** An artifact should be hard because the flag
  is genuinely hidden — not because everything around it is obviously fake.
- **Verifiable.** Tools check their own output, so you never hand out a
  challenge that can't be solved.

---

## Status

CTF Factory is in active development. ChumBucket is usable today for building
real challenges; additional tools are planned. Feedback, issues, and ideas are
welcome.

## License

Released under the MIT License. See [LICENSE](LICENSE).

---

*Created by Profe Malware.*
