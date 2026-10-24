import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { parseCapture } from "../src/parser";
import { groupDialogs, sanitizedLadder } from "../src/dialogs";
import {
  cases,
  message,
  udp,
  tcp,
  pcap,
  pcapng,
  ethernet,
  sll,
  ipv6,
  fragments,
  demoCapture,
  session,
  addressA,
  addressB,
} from "./fixtures";
const invite = () => message("INVITE sip:bob@example.test SIP/2.0", "1 INVITE");
for (const [name] of Object.entries(cases))
  test(`golden ladder: ${name}`, () => {
    const bytes = readFileSync(
      `tests/corpus/${name}.${name === "multi-interface" ? "pcapng" : "pcap"}`,
    );
    const capture = parseCapture(
      bytes.buffer.slice(bytes.byteOffset, bytes.byteOffset + bytes.byteLength),
    );
    assert.equal(
      groupDialogs(capture).map(sanitizedLadder).join("\n\n") + "\n",
      readFileSync(`tests/golden/${name}.txt`, "utf8"),
    );
  });
for (const little of [true, false])
  for (const nano of [true, false])
    test(`pcap endian=${little} nanosecond=${nano}`, () => {
      const c = parseCapture(
        pcap([udp(invite())], [100.125], 101, little, nano),
      );
      assert.equal(c.messages.length, 1);
      assert.equal(c.messages[0].time, 100.125);
    });
for (const little of [true, false])
  test(`pcapng interfaces and tsresol endian=${little}`, () => {
    const c = parseCapture(pcapng([udp(invite()), udp(invite())], little));
    assert.equal(c.messages.length, 2);
    assert.deepEqual(
      c.messages.map((m) => m.time),
      [10, 11],
    );
  });
for (const [link, wrap] of [
  [1, ethernet],
  [113, sll],
  [276, (b: Uint8Array) => sll(b, true)],
  [101, (b: Uint8Array) => b],
] as const)
  test(`link ${link}`, () =>
    assert.equal(
      parseCapture(pcap([wrap(udp(invite()))], [1], link)).messages.length,
      1,
    ));
test("VLAN and IPv6 extension header", () => {
  assert.equal(
    parseCapture(pcap([ethernet(udp(invite()), true)], [1], 1)).messages.length,
    1,
  );
  const c = parseCapture(pcap([ipv6(udp(invite()), true)]));
  assert.equal(c.messages[0].src.ip, "2001:0:0:0:0:0:0:1");
});
test("SIP on arbitrary UDP/TCP ports", () => {
  const c = parseCapture(pcap([udp(invite(), false, 12000, 32000)]));
  assert.equal(c.messages[0].dst.port, 32000);
});
test("UDP fragments assemble out of order, missing fragments produce warning", () => {
  const f = fragments(udp(invite()));
  assert.equal(parseCapture(pcap(f.reverse())).messages.length, 1);
  const c = parseCapture(cases["fragment-incomplete"]());
  assert.equal(c.messages.length, 0);
  assert.match(c.warnings.join(), /incomplete IP fragment/);
});
test("TCP out of order, overlap, retransmission and sequence wrap", () => {
  const text = invite(),
    bytes = new TextEncoder().encode(text);
  const c = parseCapture(
    pcap([
      tcp(bytes.subarray(20), 4),
      tcp(bytes.subarray(0, 40), 0xfffffff0),
      tcp(bytes.subarray(0, 40), 0xfffffff0),
    ]),
  );
  assert.equal(c.messages.length, 1);
  assert.equal(c.messages[0].raw, text);
});
test("TCP multiple messages, split UTF8 body counts octets", () => {
  const text = message(
    "MESSAGE sip:bob@example.test SIP/2.0",
    "1 MESSAGE",
    "é😊",
  );
  const b = new TextEncoder().encode(text + invite());
  const c = parseCapture(
    pcap([
      tcp(b.subarray(0, b.length - 10), 1),
      tcp(b.subarray(b.length - 10), 1 + b.length - 10),
    ]),
  );
  assert.equal(c.messages.length, 2);
  assert.equal(c.messages[0].body, "é😊");
});
test("TCP gap never fabricates complete SIP", () => {
  const b = new TextEncoder().encode(invite());
  const c = parseCapture(
    pcap([tcp(b.subarray(0, 70), 1), tcp(b.subarray(80), 81)]),
  );
  assert.equal(c.messages.length, 0);
  assert.match(c.warnings.join(), /gap/);
});
test("TCP body truncated and missing length", () => {
  let c = parseCapture(
    pcap([
      tcp(invite() + "", 1),
      tcp(
        message(
          "MESSAGE sip:bob@example.test SIP/2.0",
          "2 MESSAGE",
          "abcdef",
        ).slice(0, -2),
        1000,
      ),
    ]),
  );
  assert.match(c.warnings.join(), /Truncated SIP body/);
  c = parseCapture(
    pcap([tcp(invite().replace(/Content-Length: 0\r\n/, ""), 1)]),
  );
  assert.equal(c.messages.length, 0);
  assert.match(c.warnings.join(), /without Content-Length/);
});
test("compact and folded headers", () => {
  const text = invite()
    .replace("Call-ID:", "i:")
    .replace("Content-Length:", "l:")
    .replace("CSeq: 1 INVITE", "CSeq: 1\r\n INVITE");
  const c = parseCapture(pcap([udp(text)]));
  assert.equal(c.messages[0].cseq, "1 INVITE");
});
test("malformed files rejected or warned without bounds errors", () => {
  assert.throws(() => parseCapture(new ArrayBuffer(3)), /too short/);
  assert.throws(() => parseCapture(new ArrayBuffer(100)), /Not a supported/);
  const b = pcap([udp(invite())]);
  assert.match(parseCapture(b.slice(0, -5)).warnings.join(), /Truncated/);
  const ng = pcapng([udp(invite())]);
  new DataView(ng).setUint32(32, 0xffffffff, true);
  assert.match(parseCapture(ng).warnings.join(), /block length/);
});
test("full call summary and RTP both directions", () => {
  const d = groupDialogs(parseCapture(demoCapture()))[0];
  assert.equal(d.result, "answered");
  assert.ok(Math.abs(d.setup! - 0.48) < 0.00001);
  assert.equal(d.codec, "PCMU/8000");
  assert.equal(d.rtp, "both directions");
});
test("one-way RTP matches SDP addresses, ports and payloads", () => {
  const rtp = new Uint8Array(20);
  rtp[0] = 128;
  const base = [
    udp(
      message(
        "INVITE sip:bob@example.test SIP/2.0",
        "1 INVITE",
        session(addressA, 4000),
      ),
    ),
    udp(message("SIP/2.0 200 OK", "1 INVITE", session(addressB, 5000)), true),
  ];
  let d = groupDialogs(
    parseCapture(pcap([...base, udp(rtp, false, 4000, 5000)])),
  )[0];
  assert.equal(d.rtp, "offerer → answerer only");
  assert.match(d.diagnoses.join(), /Possible one-way/);
  d = groupDialogs(
    parseCapture(pcap([...base, udp(rtp, false, 4001, 5000)])),
  )[0];
  assert.equal(d.rtp, "not observed");
});
test("407 digest and CANCEL diagnoses", () => {
  assert.match(
    groupDialogs(parseCapture(cases.digest()))[0].diagnoses.join(),
    /407 proxy challenge/,
  );
  assert.equal(
    groupDialogs(parseCapture(cases.cancelled()))[0].result,
    "cancelled",
  );
  assert.match(
    groupDialogs(parseCapture(cases.timeout()))[0].diagnoses.join(),
    /retransmitted 7x/,
  );
});
test("response on another hop does not hide unanswered request", () => {
  const req = udp(invite());
  const response = udp(
    message("SIP/2.0 100 Trying", "1 INVITE"),
    true,
    5090,
    5060,
  );
  const d = groupDialogs(parseCapture(pcap([req, response])))[0];
  assert.match(d.diagnoses.join(), /no response observed/);
});
test("sanitized export allowlist excludes auth, URI users, identifiers, SDP and injected headers", () => {
  const raw = message(
    "INVITE sip:secret@example.test SIP/2.0",
    "1 INVITE",
    session(addressA, 4000),
    "Authorization: Digest secret\r\nProxy-Authorization: secret\r\nX-Secret: private\r\n",
    "secretCall",
  );
  const text = sanitizedLadder(groupDialogs(parseCapture(pcap([udp(raw)])))[0]);
  for (const value of [
    "secret",
    "alice",
    "bob",
    "192.0.2",
    "example.test",
    "Authorization",
    "SDP\r\n",
    "private",
  ])
    assert.ok(!text.includes(value), value);
  assert.match(text, /endpoint 1 -> endpoint 2/);
});
test("multi-megabyte capture benchmark", () => {
  const packet = udp(invite()),
    count = 16000;
  const start = performance.now();
  const c = parseCapture(pcap(Array(count).fill(packet)));
  assert.equal(c.messages.length, count);
  console.log(
    `Parsed ${((packet.length * count) / 1e6).toFixed(1)} MB / ${count} SIP packets in ${(performance.now() - start).toFixed(0)}ms`,
  );
});
test("BSD loopback IPv4 and IPv6", () => {
  for (const [family, packet] of [
    [2, udp(invite())],
    [30, ipv6(udp(invite()))],
  ] as const) {
    const b = new Uint8Array(packet.length + 4);
    new DataView(b.buffer).setUint32(0, family, true);
    b.set(packet, 4);
    assert.equal(parseCapture(pcap([b], [1], 0)).messages.length, 1);
  }
});
test("TCP message timestamp follows first byte across coalesced frames", () => {
  const first = invite(),
    second = message("OPTIONS sip:bob@example.test SIP/2.0", "2 OPTIONS");
  const b1 = new TextEncoder().encode(first.slice(0, -2)),
    b2 = new TextEncoder().encode(first.slice(-2) + second.slice(0, 80)),
    b3 = new TextEncoder().encode(second.slice(80));
  const c = parseCapture(
    pcap(
      [tcp(b1, 1), tcp(b2, 1 + b1.length), tcp(b3, 1 + b1.length + b2.length)],
      [1, 2, 3],
    ),
  );
  assert.deepEqual(
    c.messages.map((m) => m.time),
    [1, 2],
  );
});
test("conflicting TCP overlap rejects ambiguous stream", () => {
  const b = new TextEncoder().encode(invite()),
    altered = b.slice();
  altered[12] ^= 1;
  const c = parseCapture(pcap([tcp(b, 1), tcp(altered, 1)]));
  assert.equal(c.messages.length, 0);
  assert.match(c.warnings.join(), /Conflicting TCP/);
});
test("TCP retransmission preserves original timestamp", () => {
  const b = new TextEncoder().encode(invite());
  const c = parseCapture(pcap([tcp(b, 1), tcp(b, 1)], [1, 4]));
  assert.equal(c.messages[0].time, 1);
});
test("sanitized response rejects URI embedded in malformed CSeq method", () => {
  const d = groupDialogs(
    parseCapture(
      pcap([
        udp(
          message("SIP/2.0 200 Secret Reason", "1 sip:private@example.test"),
          true,
        ),
      ]),
    ),
  )[0];
  const text = sanitizedLadder(d);
  assert.ok(!text.includes("private"));
  assert.ok(!text.includes("Secret Reason"));
  assert.match(text, /redacted/);
});
test("many distinct transactions analyze without quadratic scans", () => {
  const c = parseCapture(
    pcap(
      Array.from({ length: 5000 }, (_, i) =>
        udp(message("OPTIONS sip:bob@example.test SIP/2.0", `${i} OPTIONS`)),
      ),
    ),
  );
  const d = groupDialogs(c)[0];
  assert.equal(d.diagnoses.length, 5000);
});
test("digest diagnosis requires a later authenticated retry, not preemptive auth", () => {
  const c = parseCapture(
    pcap([
      udp(
        message(
          "INVITE sip:bob@example.test SIP/2.0",
          "1 INVITE",
          "",
          'Proxy-Authorization: Digest response="secret"\r\n',
        ),
      ),
      udp(
        message("SIP/2.0 407 Proxy Authentication Required", "1 INVITE"),
        true,
      ),
    ]),
  );
  assert.ok(
    !groupDialogs(c)[0].diagnoses.some((x) => x.includes("digest flow")),
  );
});
test("unrelated CANCEL does not misclassify INVITE 487", () => {
  const c = parseCapture(
    pcap([
      udp(invite()),
      udp(
        message(
          "CANCEL sip:bob@example.test SIP/2.0",
          "8 CANCEL",
          "",
          "",
          "sample-call@local",
          "different",
        ),
      ),
      udp(message("SIP/2.0 487 Request Terminated", "1 INVITE"), true),
    ]),
  );
  assert.equal(groupDialogs(c)[0].result, "rejected");
});
