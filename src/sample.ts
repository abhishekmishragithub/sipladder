// Synthetic documentation-range endpoints only. Also used by deterministic tests.
const enc = new TextEncoder();
export const addressA = "192.0.2.10",
  addressB = "192.0.2.20";
export function message(
  start: string,
  cseq: string,
  body = "",
  extra = "",
  callId = "sample-call@local",
  branch = "z9hG4bK-demo",
): string {
  return `${start}\r\nVia: SIP/2.0/UDP ${addressA}:5060;branch=${branch}\r\nFrom: "Alice" <sip:alice@example.test>;tag=a\r\nTo: <sip:bob@example.test>\r\nCall-ID: ${callId}\r\nCSeq: ${cseq}\r\n${extra}${body ? "Content-Type: application/sdp\r\n" : ""}Content-Length: ${enc.encode(body).length}\r\n\r\n${body}`;
}
export function session(ip: string, port: number) {
  return `v=0\r\no=- 1 1 IN IP4 ${ip}\r\ns=Example call\r\nc=IN IP4 ${ip}\r\nt=0 0\r\nm=audio ${port} RTP/AVP 0 101\r\na=rtpmap:0 PCMU/8000\r\na=rtpmap:101 telephone-event/8000\r\n`;
}
export function udp(
  payload: string | Uint8Array,
  reverse = false,
  srcPort = 5060,
  dstPort = 5060,
) {
  const body = typeof payload === "string" ? enc.encode(payload) : payload;
  const p = new Uint8Array(20 + 8 + body.length),
    v = new DataView(p.buffer);
  p[0] = 0x45;
  v.setUint16(2, p.length);
  p[8] = 64;
  p[9] = 17;
  p.set((reverse ? addressB : addressA).split(".").map(Number), 12);
  p.set((reverse ? addressA : addressB).split(".").map(Number), 16);
  v.setUint16(20, srcPort);
  v.setUint16(22, dstPort);
  v.setUint16(24, body.length + 8);
  p.set(body, 28);
  return p;
}
export function tcp(
  payload: string | Uint8Array,
  seq: number,
  reverse = false,
) {
  const body = typeof payload === "string" ? enc.encode(payload) : payload,
    p = udp(new Uint8Array(12 + body.length), reverse),
    v = new DataView(p.buffer);
  p[9] = 6;
  v.setUint32(24, seq);
  p[32] = 0x50;
  p[33] = 0x18;
  p.set(body, 40);
  return p;
}
export function pcap(
  packets: Uint8Array[],
  times = packets.map((_, i) => 1700000000 + i * 0.1),
  link = 101,
  little = true,
  nano = false,
): ArrayBuffer {
  const b = new Uint8Array(24 + packets.reduce((n, p) => n + 16 + p.length, 0)),
    v = new DataView(b.buffer);
  v.setUint32(0, nano ? 0xa1b23c4d : 0xa1b2c3d4, little);
  v.setUint16(4, 2, little);
  v.setUint16(6, 4, little);
  v.setUint32(16, 65535, little);
  v.setUint32(20, link, little);
  let o = 24;
  packets.forEach((p, i) => {
    v.setUint32(o, Math.floor(times[i]), little);
    v.setUint32(o + 4, Math.round((times[i] % 1) * (nano ? 1e9 : 1e6)), little);
    v.setUint32(o + 8, p.length, little);
    v.setUint32(o + 12, p.length, little);
    b.set(p, o + 16);
    o += 16 + p.length;
  });
  return b.buffer;
}
export function demoCapture(): ArrayBuffer {
  const packets = [
    udp(
      message(
        "INVITE sip:bob@example.test SIP/2.0",
        "1 INVITE",
        session(addressA, 4000),
      ),
    ),
    udp(message("SIP/2.0 100 Trying", "1 INVITE"), true),
    udp(message("SIP/2.0 180 Ringing", "1 INVITE"), true),
    udp(message("SIP/2.0 200 OK", "1 INVITE", session(addressB, 5000)), true),
    udp(message("ACK sip:bob@example.test SIP/2.0", "1 ACK")),
  ];
  const rtp = new Uint8Array(24);
  rtp[0] = 0x80;
  rtp[1] = 0;
  packets.push(
    udp(rtp, false, 4000, 5000),
    udp(rtp, true, 5000, 4000),
    udp(message("BYE sip:bob@example.test SIP/2.0", "2 BYE")),
    udp(message("SIP/2.0 200 OK", "2 BYE"), true),
  );
  return pcap(
    packets,
    [
      1700000000, 1700000000.02, 1700000000.12, 1700000000.48, 1700000000.5,
      1700000001, 1700000001.02, 1700000005, 1700000005.02,
    ],
  );
}
