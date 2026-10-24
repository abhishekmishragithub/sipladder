import {
  message,
  udp,
  tcp,
  pcap,
  demoCapture,
  session,
  addressA,
  addressB,
} from "../src/sample";
export { message, udp, tcp, pcap, demoCapture, session, addressA, addressB };
const enc = new TextEncoder();
export function pcapng(packets: Uint8Array[], little = true): ArrayBuffer {
  const blocks: Uint8Array[] = [];
  const block = (
    type: number,
    len: number,
    fill: (v: DataView, b: Uint8Array) => void,
  ) => {
    const b = new Uint8Array(len),
      v = new DataView(b.buffer);
    v.setUint32(0, type, little);
    v.setUint32(4, len, little);
    v.setUint32(len - 4, len, little);
    fill(v, b);
    blocks.push(b);
  };
  block(0x0a0d0d0a, 28, (v) => {
    v.setUint32(8, 0x1a2b3c4d, little);
    v.setUint16(12, 1, little);
    v.setBigInt64(16, -1n, little);
  });
  // Two interfaces with different link types and timestamp units.
  for (const [link, res] of [
    [101, 6],
    [113, 0x8a],
  ])
    block(1, 32, (v, b) => {
      v.setUint16(8, link, little);
      v.setUint32(12, 65535, little);
      v.setUint16(16, 9, little);
      v.setUint16(18, 1, little);
      b[20] = res;
    });
  packets.forEach((p, i) => {
    const id = i % 2,
      data = id ? sll(p) : p;
    const stamp = id ? 1024 * (10 + i) : 1e6 * (10 + i);
    block(6, 32 + Math.ceil(data.length / 4) * 4, (v, b) => {
      v.setUint32(8, id, little);
      v.setUint32(16, stamp, little);
      v.setUint32(20, data.length, little);
      v.setUint32(24, data.length, little);
      b.set(data, 28);
    });
  });
  const b = new Uint8Array(blocks.reduce((n, b) => n + b.length, 0));
  let o = 0;
  for (const block of blocks) {
    b.set(block, o);
    o += block.length;
  }
  return b.buffer;
}
export function ethernet(p: Uint8Array, vlan = false) {
  const b = new Uint8Array(p.length + (vlan ? 18 : 14));
  b[12] = vlan ? 0x81 : 8;
  if (vlan) b[16] = 8;
  b.set(p, vlan ? 18 : 14);
  return b;
}
export function sll(p: Uint8Array, v2 = false) {
  const b = new Uint8Array(p.length + (v2 ? 20 : 16));
  b[v2 ? 0 : 14] = 8;
  b.set(p, v2 ? 20 : 16);
  return b;
}
export function ipv6(p: Uint8Array, extension = false) {
  const b = new Uint8Array(40 + (extension ? 8 : 0) + p.length - 20),
    v = new DataView(b.buffer);
  b[0] = 0x60;
  v.setUint16(4, b.length - 40);
  b[6] = extension ? 0 : p[9];
  b[7] = 64;
  b[8] = 0x20;
  b[9] = 1;
  b[23] = 1;
  b[24] = 0x20;
  b[25] = 1;
  b[39] = 2;
  if (extension) b[40] = p[9];
  b.set(p.subarray(20), extension ? 48 : 40);
  return b;
}
export function fragments(p: Uint8Array) {
  return [0, 1].map((i) => {
    const body = i === 0 ? p.subarray(20, 68) : p.subarray(68),
      b = new Uint8Array(20 + body.length);
    b.set(p.subarray(0, 20));
    b.set(body, 20);
    const v = new DataView(b.buffer);
    v.setUint16(2, b.length);
    v.setUint16(4, 42);
    v.setUint16(6, i === 0 ? 0x2000 : 6);
    return b;
  });
}
export const cases: Record<string, () => ArrayBuffer> = {
  answered: demoCapture,
  rejected: () =>
    pcap([
      udp(message("INVITE sip:bob@example.test SIP/2.0", "1 INVITE")),
      udp(message("SIP/2.0 486 Busy Here", "1 INVITE"), true),
    ]),
  timeout: () =>
    pcap(
      Array.from({ length: 8 }, () =>
        udp(message("INVITE sip:bob@example.test SIP/2.0", "1 INVITE")),
      ),
    ),
  cancelled: () =>
    pcap([
      udp(message("INVITE sip:bob@example.test SIP/2.0", "1 INVITE")),
      udp(message("CANCEL sip:bob@example.test SIP/2.0", "1 CANCEL")),
      udp(message("SIP/2.0 200 OK", "1 CANCEL"), true),
      udp(message("SIP/2.0 487 Request Terminated", "1 INVITE"), true),
    ]),
  digest: () =>
    pcap([
      udp(message("INVITE sip:bob@example.test SIP/2.0", "1 INVITE")),
      udp(
        message(
          "SIP/2.0 407 Proxy Authentication Required",
          "1 INVITE",
          "",
          'Proxy-Authenticate: Digest realm="secret", nonce="secret"\r\n',
        ),
        true,
      ),
      udp(
        message(
          "INVITE sip:bob@example.test SIP/2.0",
          "2 INVITE",
          "",
          'Proxy-Authorization: Digest username="alice", response="secret"\r\n',
          "sample-call@local",
          "z9hG4bK-second",
        ),
      ),
      udp(
        message(
          "SIP/2.0 200 OK",
          "2 INVITE",
          "",
          "",
          "sample-call@local",
          "z9hG4bK-second",
        ),
        true,
      ),
    ]),
  "tcp-segmented": () => {
    const b = enc.encode(
      message(
        "INVITE sip:bob@example.test SIP/2.0",
        "1 INVITE",
        session(addressA, 4000),
      ),
    );
    return pcap([
      tcp(b.subarray(17, 131), 1017),
      tcp(b.subarray(0, 17), 1000),
      tcp(b.subarray(131), 1131),
      tcp(b.subarray(17, 131), 1017),
    ]);
  },
  "fragment-incomplete": () =>
    pcap(
      fragments(
        udp(message("INVITE sip:bob@example.test SIP/2.0", "1 INVITE")),
      ).slice(0, 1),
    ),
  "multi-interface": () =>
    pcapng([
      udp(message("INVITE sip:bob@example.test SIP/2.0", "1 INVITE")),
      udp(message("SIP/2.0 200 OK", "1 INVITE"), true),
    ]),
};
