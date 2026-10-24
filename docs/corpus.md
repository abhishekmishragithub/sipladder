# Capture corpus

All checked-in captures are deterministic synthetic packets using documentation-range addresses and example.test identities. None contains customer traffic, credentials, or actual call audio. Golden text is reviewed and checked into `tests/golden/`; tests read binary captures, not just fixture constructors.

```
npm run fixtures                 # regenerate binary captures only
npm run fixtures -- --update-golden  # deliberate golden update; review the diff
npm test
```

Cases: answered with SDP and bidirectional RTP-shaped packets, rejected, eight unanswered INVITEs, CANCEL/487, digest challenge/retry, reordered/retransmitted TCP segmented mid-header, incomplete fragmented UDP, and pcapng with two link layers and different timestamp resolutions. Additional unit fixtures exercise VLAN, SLL2, IPv6 extension headers, big endian/nanosecond timestamps, compact/folded headers, UTF-8 body lengths, gaps and malformed lengths.

## Real SIPp capture (human-run recipe)

Install [SIPp](https://sipp.readthedocs.io/en/latest/) and tcpdump using your OS package manager. Use three terminals. Everything below is loopback-only; no registration or external service is needed.

```
# Terminal 1 — Linux (Ethernet/SLL link types are supported)
sudo tcpdump -i any -s 0 -U -w sipp-answered.pcap 'udp and (port 5060 or port 5062)'

# Terminal 2
sipp -sn uas -i 127.0.0.1 -p 5060 -m 1

# Terminal 3
sipp -sn uac 127.0.0.1:5060 -i 127.0.0.1 -p 5062 -s bob -m 1 -d 3000
```

Stop tcpdump with Ctrl-C after the call completes. For TCP add `-t t1` to both SIPp commands and change the capture filter to `tcp and (port 5060 or port 5062)`. These built-in scenarios exercise SIP; they do not guarantee RTP. For media testing use PJSUA below or SIPp's documented PCAP playback scenarios. To create a retransmission/timeout capture, stop the UAS before initiating the call and capture the UAC retries. To create rejection/cancellation, use an explicit scenario returning 486 or sending CANCEL after 180.

## PJSUA capture, including RTP

Use [PJSUA](https://www.pjsip.org/pjsip/docs/html/page_pjsip_samples_pjsua.htm). Disable STUN and TCP, bind loopback, use null audio and disable silence suppression. Record a short, entirely local call:

```
# Terminal 1, Linux
sudo tcpdump -i any -s 0 -U -w pjsua-answered.pcap 'udp and (port 5060 or port 5062 or portrange 4000-4001 or portrange 5000-5001)'

# Terminal 2 — answering endpoint
pjsua --bound-addr=127.0.0.1 --ip-addr=127.0.0.1 --local-port=5060 --rtp-port=5000 --no-tcp --disable-stun --null-audio --no-vad --auto-answer=200 --duration=5

# Terminal 3 — caller
pjsua --bound-addr=127.0.0.1 --ip-addr=127.0.0.1 --local-port=5062 --rtp-port=4000 --no-tcp --disable-stun --null-audio --no-vad --duration=5 sip:bob@127.0.0.1:5060
```

Null audio produces silent media, sufficient for RTP presence testing. For an audible test add a known local WAV on the answering endpoint with `--play-file=tone.wav --auto-play`; never use private recordings. Quit the endpoints after BYE/200, then stop tcpdump. On macOS use `-i lo0` (BSD loopback is supported); actual capture requires BPF access. These real capture recipes were documented but **not executed successfully in this run**: SIPp is absent, and tcpdump was denied access to `/dev/bpf0` by the sandbox. PJSUA is installed, but no privileged capture or external calls were attempted.

## Adding a real regression

Review the capture for local-only content, then place it in `tests/corpus/`. Add an explicit test verifying expected message count, result, SDP and RTP observations; generate and critically review its sanitized golden. Compare the ladder with Wireshark/tshark on the same local file. Do not check in arbitrary downloaded captures or production pcaps.
