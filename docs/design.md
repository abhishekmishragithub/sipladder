# Design decision: TypeScript, worker, SVG

Decision date: 2026-10-24. No production dependencies; Vite/TypeScript are build tools.

## Research and name

The working name remains **sipladder**: descriptive and easy to remember. A read-only web search for the exact name did not identify an exact-name project. A read-only npm registry lookup returned 404 for `sipladder` at the time of this run. This is not exhaustive registry, trademark, domain, or GitHub organization clearance. Do those checks before announcing it. No names were registered.

The premise that no browser alternative exists is inaccurate: [SIP Flow](https://www.sipflow.dev/) advertises local capture parsing and SIP ladders. The useful focus here is a small, inspectable static tool, conservative diagnoses, identity-free ticket export, and enforced network restrictions. No marketing claim of being first or unique is appropriate.

Primary references used:

- [RFC 3261](https://www.rfc-editor.org/rfc/rfc3261): SIP framing, Content-Length in octets, compact header aliases, transactions, digest challenges. A real SIP dialog uses Call-ID and tags; v1 intentionally groups by Call-ID as requested, so forks and proxy legs share one conversation.
- [IETF pcapng specification](https://www.ietf.org/archive/id/draft-ietf-opsawg-pcapng-01.html): section byte order, interface-local link types, enhanced packet blocks, interface timestamp resolution and offset.
- [IANA capture link types](https://www.iana.org/assignments/pcap): Ethernet, raw IP, Linux SLL and SLL2 identifiers.
- [pcap-parser Rust API](https://docs.rs/pcap-parser/latest/pcap_parser/pcap/index.html): a viable container decoder, but transport reassembly, SIP and UI models still require application code.
- [Pyodide loading documentation](https://pyodide.org/en/stable/usage/loading-packages.html): Python requires a separate runtime and package loading. No Python runtime is justified for this application.

## Options and evidence

| Choice     | Advantages                                                                  | Costs                                                                     | Decision                                 |
| ---------- | --------------------------------------------------------------------------- | ------------------------------------------------------------------------- | ---------------------------------------- |
| TypeScript | Native typed arrays, one model, inspectable source, no runtime dependencies | We own bounds checking and transport logic                                | Chosen                                   |
| Rust/WASM  | Strong binary tooling; pcap-parser supports both containers                 | Separate toolchain, WASM artifact, still need TCP/SIP logic and UI bridge | Reconsider only with measured bottleneck |
| Pyodide    | Python conference narrative, existing Python ecosystem                      | Download/startup/runtime overhead; no Python-specific benefit here        | Rejected for v1                          |

A local synthetic 4.1 MB / 16,000-message parser run took about 57 ms initially (machine-specific, not a general performance guarantee). Production JS initially totaled about 24 KB uncompressed before worker inlining. This is no evidence that WASM is needed. The parser benchmark is repeatable through `npm test`. No claim is made that a comparable Rust or Python implementation was benchmarked.

## Pipeline and contracts

The main thread reads one File into an ArrayBuffer and transfers ownership to a module worker. The worker walks capture records without copying packet payloads, parses network layers, reassembles fragmented IP datagrams and directional TCP streams, frames SIP by byte Content-Length, then groups conversations and computes summaries. The UI receives SIP strings, observations and warnings, never RTP payloads. There is no audio decoding or playback. Worker progress is emitted every 10,000 packets. Transaction diagnoses use a single-pass index rather than rescanning every request. New files terminate the previous worker; a generation token prevents late reads replacing newer captures.

The 256 MiB input guard bounds the file read; individual SIP messages are limited to 4 MiB. These are usability limits, not hostile-file memory guarantees. Payload arrays and decoded messages can consume several times the capture size. Each ladder/table renders at most 100 messages at once. Arrow-key navigation crosses pages. Diagnoses show at most 50 entries per view.

Classic pcap supports both byte orders and micro/nanosecond timestamps. Pcapng supports multiple sections/interfaces, section byte order, enhanced packet blocks, decimal/binary timestamp resolution and signed timestamp offset. Unsupported Simple Packet Blocks (no timestamp), obsolete Packet Blocks, unknown interfaces/link types, and malformed lengths are surfaced as warnings. Ethernet VLAN tags, SLL/SLL2, raw IPv4/IPv6, IPv6 extension headers, UDP and TCP are decoded. Incomplete IP fragment sets are warned about and never passed to SIP. Overlapping IP fragments are rejected. Conflicting TCP overlap bytes reject the ambiguous stream. TCP segments are ordered using relative 32-bit sequence arithmetic (connections spanning more than 2 GiB of sequence space are outside v1's limit); retransmitted bytes are de-duplicated and gaps break framing. SYN resets connection incarnations. Stream state is scoped to a capture interface, preventing cross-interface tuple collisions; a connection split across interfaces will not reassemble.

SIP start lines are detected on any port. Headers are case-insensitive, compact aliases and folding supported. TCP requires Content-Length; missing/invalid lengths are skipped with a warning. Missing body/header bytes remain incomplete. Binary bodies are framed correctly but displayed as UTF-8 replacement text. TLS, WebSocket framing, gzip captures, IPsec, IPv6 jumbograms and multipart SDP are not decoded.

## Analysis is evidence, not certainty

Results are answered (INVITE 2xx observed), cancelled (CANCEL plus INVITE 487), rejected (INVITE failure excluding authentication challenges), timeout (INVITE with no final outcome), or observed (no INVITE). Timeout means capture evidence, not proof a timer expired. Captures can start/end mid-call. Setup is matching INVITE transaction → 2xx, including endpoint and Via branch matching; authenticated retries have their own transaction setup time. Per-request diagnoses use CSeq, branch and reversed endpoints, so responses on another proxy hop don't satisfy a request.

SDP analysis uses the first audio offer and first INVITE 2xx answer. It reports compatible advertised answer codecs; this is not proof of the codec actually sent. Multiple audio media sections, late offers in 200/ACK, early-media answers, renegotiation and forks need further analysis. RTP is a structurally plausible version-2 packet matched to both SDP addresses/ports, common payload type and observed call interval. Bidirectional presence is evidence of packets, not audible speech. One-direction presence is explicitly qualified: NAT, asymmetric captures and sendonly/recvonly SDP can explain it. No RTP observation is not proof of no audio. RTCP is excluded. NAT/ICE/SRTP media cannot be fully assessed by this method.

## Privacy boundary

Production HTML includes `default-src 'none'`, `connect-src 'none'`, `worker-src blob:`, `script-src 'self'`, `style-src 'self'`, `img-src 'self' data:`, `font-src 'none'`, `object-src 'none'`, `base-uri 'none'` and `form-action 'none'`. Only the initial bundled static assets load from the host. The self-contained parser is bundled as a blob worker so it inherits the document CSP; a separately fetched worker would need its own CSP response header. No asset requests occur when opening a capture. See [MDN worker CSP inheritance](https://developer.mozilla.org/en-US/docs/Web/API/Web_Workers_API/Using_web_workers#content_security_policy) and [Vite inline workers](https://vite.dev/guide/features.html#web-workers). There is no application fetch, upload, analytics, font CDN, service worker, or persistence. Captured strings are inserted using textContent, never HTML. Self-hosting on a dedicated origin is recommended; CSP is defense in depth, not a defense against a compromised host/browser or extensions. The development server's HMR WebSocket is deliberately blocked by this production policy; use a rebuild/preview for strict CSP verification.

Export is stricter than masking URI users: an allowlist emits numbered endpoints, relative times, methods/status numbers, validated CSeq, result/setup/RTP. It excludes all raw headers (including auth challenges and credentials), URI users, IPs, display names, Call-ID, Via branches, SDP, free-text reason phrases and diagnoses. The raw inspector remains local and unsanitized. Clipboard export is an explicit user action; fallback text can be selected manually. Clear removes displayed capture references and stops the worker; it does not promise secure browser-memory erasure.

## Hosting

`base: './'` permits a GitHub Pages repository subpath. The build is static `dist/`; there is no server component. A manual-only Pages workflow is provided, with no push trigger. No remote, PR, deployment or publishing was performed in this run. HTTP headers on a controlled host can additionally apply frame-ancestors, which cannot be enforced by a CSP meta tag.
