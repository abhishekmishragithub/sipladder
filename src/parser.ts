import type { Capture, Endpoint, SipMessage } from "./types";
const decoder = new TextDecoder();
const ascii = new TextDecoder("latin1");
const MAX_MESSAGE = 4 * 1024 * 1024;
interface Packet {
  time: number;
  data: Uint8Array;
  link: number;
  scope: string;
}
interface Segment {
  seq: number;
  data: Uint8Array;
  time: number;
  src: Endpoint;
  dst: Endpoint;
  scope: string;
}
const startPattern =
  /^(?:SIP\/2\.0 [1-6]\d\d(?: |$)|[A-Z][A-Z0-9.!%*_+`'~-]*\s+\S+\s+SIP\/2\.0\r?\n)/;
const join = (a: Uint8Array, b: Uint8Array) => {
  const c = new Uint8Array(a.length + b.length);
  c.set(a);
  c.set(b, a.length);
  return c;
};
export function parseCapture(
  buffer: ArrayBuffer,
  progress?: (n: number) => void,
): Capture {
  const bytes = new Uint8Array(buffer),
    view = new DataView(buffer);
  const result: Capture = { messages: [], media: [], warnings: [], packets: 0 };
  const warn = (s: string) => {
    if (!result.warnings.includes(s)) result.warnings.push(s);
  };
  const streams = new Map<string, Segment[]>();
  const fragments = new Map<
    string,
    {
      parts: Map<number, Uint8Array>;
      end?: number;
      time: number;
      proto: number;
      src: string;
      dst: string;
      scope: string;
    }
  >();
  const safe = (o: number, n: number) =>
    o >= 0 && n >= 0 && o + n <= bytes.length;
  function sip(
    data: Uint8Array,
    time: number,
    src: Endpoint,
    dst: Endpoint,
    transport: "UDP" | "TCP",
    partial = false,
  ): number {
    const text = ascii.decode(data);
    if (!startPattern.test(text)) return 0;
    const end = text.indexOf("\r\n\r\n");
    if (end < 0) {
      if (partial) warn("Incomplete SIP headers at capture boundary.");
      return 0;
    }
    const head = text.slice(0, end),
      lines = head.replace(/\r\n[ \t]+/g, " ").split("\r\n");
    const headers: Record<string, string> = Object.create(null);
    const aliases: Record<string, string> = {
      i: "call-id",
      l: "content-length",
      c: "content-type",
      f: "from",
      t: "to",
      v: "via",
      m: "contact",
    };
    for (const line of lines.slice(1)) {
      const k = line.indexOf(":");
      if (k > 0) {
        const name = line.slice(0, k).trim().toLowerCase();
        const key = Object.hasOwn(aliases, name) ? aliases[name] : name;
        headers[key] = headers[key]
          ? headers[key] + ", " + line.slice(k + 1).trim()
          : line.slice(k + 1).trim();
      }
    }
    const length = headers["content-length"];
    if (transport === "TCP" && length === undefined) {
      warn("TCP SIP without Content-Length skipped: framing is ambiguous.");
      return -1;
    }
    if (length !== undefined && !/^\d+$/.test(length)) {
      warn("Invalid SIP Content-Length skipped.");
      return -1;
    }
    const bodyLength =
      length === undefined ? data.length - end - 4 : Number(length);
    if (bodyLength > MAX_MESSAGE) {
      warn("SIP message exceeds 4 MiB limit.");
      return -1;
    }
    const total = end + 4 + bodyLength;
    if (data.length < total) {
      if (partial) warn("Truncated SIP body at capture boundary.");
      return 0;
    }
    const start = lines[0],
      status = start.startsWith("SIP/")
        ? Number(start.split(" ")[1])
        : undefined;
    if (!headers["call-id"]) {
      warn("SIP message missing Call-ID skipped.");
      return total;
    }
    result.messages.push({
      id: 0,
      time,
      src,
      dst,
      transport,
      start,
      status,
      method: status
        ? ((headers.cseq ?? "").split(/\s+/)[1] ?? "")
        : start.split(" ")[0],
      callId: headers["call-id"],
      cseq: headers.cseq ?? "?",
      branch: headers.via?.match(/branch=([^;,\s]+)/i)?.[1] ?? "",
      headers,
      raw: decoder.decode(data.subarray(0, total)),
      body: decoder.decode(data.subarray(end + 4, total)),
    });
    return total;
  }
  function transport(
    data: Uint8Array,
    proto: number,
    time: number,
    srcIp: string,
    dstIp: string,
    scope: string,
  ) {
    if (data.length < 8) return;
    const d = new DataView(data.buffer, data.byteOffset, data.byteLength);
    const src = { ip: srcIp, port: d.getUint16(0) },
      dst = { ip: dstIp, port: d.getUint16(2) };
    if (proto === 17) {
      const len = d.getUint16(4);
      if (len < 8 || len > data.length) {
        warn("Truncated UDP datagram skipped.");
        return;
      }
      const body = data.subarray(8, len);
      const consumed = sip(body, time, src, dst, "UDP", true);
      if (
        !consumed &&
        body.length >= 12 &&
        body[0] >>> 6 === 2 &&
        (body[1] < 192 || body[1] > 223)
      ) {
        const cc = body[0] & 15,
          ext = !!(body[0] & 16);
        let header = 12 + cc * 4;
        if (ext) {
          if (body.length < header + 4) return;
          header +=
            4 +
            new DataView(
              body.buffer,
              body.byteOffset + header + 2,
              2,
            ).getUint16(0) *
              4;
        }
        const padding = body[0] & 32 ? body[body.length - 1] : 0;
        if (
          header < body.length &&
          (!(body[0] & 32) || (padding > 0 && padding <= body.length - header))
        )
          result.media.push({ time, src, dst, payloadType: body[1] & 127 });
      }
    } else if (proto === 6 && data.length >= 20) {
      const off = (data[12] >>> 4) * 4;
      if (off < 20 || off > data.length) return;
      const key = `${scope}|${srcIp}:${src.port}>${dstIp}:${dst.port}`;
      if (data[13] & 2) {
        // A SYN starts a fresh connection incarnation on a reused tuple.
        const old = streams.get(key);
        if (old?.length) processStream(old);
        streams.set(key, []);
      }
      if (data.length > off) {
        const segs = streams.get(key) ?? [];
        segs.push({
          seq: (d.getUint32(4) + (data[13] & 2 ? 1 : 0)) >>> 0,
          data: data.subarray(off),
          time,
          src,
          dst,
          scope,
        });
        streams.set(key, segs);
      }
    }
  }
  function fragment(
    data: Uint8Array,
    key: string,
    offset: number,
    more: boolean,
    proto: number,
    time: number,
    src: string,
    dst: string,
    scope: string,
  ) {
    let f = fragments.get(key);
    if (!f) {
      f = { parts: new Map(), time, proto, src, dst, scope };
      fragments.set(key, f);
    }
    if (offset + data.length > 65535) {
      warn("Oversized IP fragment set skipped.");
      return;
    }
    if (more && data.length % 8) {
      warn("Invalid IP fragment length skipped.");
      return;
    }
    // Reject ambiguous overlapping fragments rather than inventing transport bytes.
    for (const [o, p] of f.parts) {
      if (
        o === offset &&
        p.length === data.length &&
        p.every((v, i) => v === data[i])
      )
        return;
      if (offset < o + p.length && o < offset + data.length) {
        fragments.delete(key);
        warn("Overlapping IP fragments skipped.");
        return;
      }
    }
    f.parts.set(offset, data);
    if (!more) f.end = offset + data.length;
    if (f.end !== undefined) {
      const parts = [...f.parts].sort((a, b) => a[0] - b[0]);
      let n = 0;
      for (const [o, p] of parts) {
        if (o !== n) return;
        n += p.length;
      }
      if (n === f.end) {
        const full = new Uint8Array(n);
        for (const [o, p] of parts) full.set(p, o);
        transport(full, proto, f.time, src, dst, scope);
        fragments.delete(key);
      }
    }
  }
  function packet(p: Packet) {
    result.packets++;
    if (result.packets % 10000 === 0) progress?.(result.packets);
    let b = p.data,
      type = 0;
    const u16 = (o: number) => (b[o] << 8) | b[o + 1];
    if (p.link === 1) {
      if (b.length < 14) return;
      type = u16(12);
      let o = 14;
      while (type === 0x8100 || type === 0x88a8) {
        if (b.length < o + 4) return;
        type = u16(o + 2);
        o += 4;
      }
      b = b.subarray(o);
    } else if (p.link === 113) {
      if (b.length < 16) return;
      type = u16(14);
      b = b.subarray(16);
    } else if (p.link === 276) {
      if (b.length < 20) return;
      type = u16(0);
      b = b.subarray(20);
    } else if (p.link === 0 || p.link === 108) {
      if (b.length < 4) return;
      const d = new DataView(b.buffer, b.byteOffset, 4);
      const family =
        p.link === 108
          ? d.getUint32(0)
          : Math.min(d.getUint32(0), d.getUint32(0, true));
      if (family === 2) type = 0x800;
      else if ([10, 24, 28, 30].includes(family)) type = 0x86dd;
      else return;
      b = b.subarray(4);
    } else if ([101, 12, 228, 229].includes(p.link)) {
      type = b[0] >>> 4 === 4 ? 0x800 : 0x86dd;
    } else {
      warn(`Unsupported link type ${p.link}; packets skipped.`);
      return;
    }
    if (!b.length) return;
    if (type === 0x800 && b[0] >>> 4 === 4) {
      if (b.length < 20) return;
      const h = (b[0] & 15) * 4,
        len = (b[2] << 8) | b[3];
      if (h < 20 || len < h || len > b.length) {
        warn("Truncated or invalid IPv4 packet skipped.");
        return;
      }
      const src = [...b.subarray(12, 16)].join("."),
        dst = [...b.subarray(16, 20)].join("."),
        flags = (b[6] << 8) | b[7];
      if (flags & 0x3fff)
        fragment(
          b.subarray(h, len),
          `${p.scope}|${src}>${dst}|${b[9]}|${(b[4] << 8) | b[5]}`,
          (flags & 8191) * 8,
          !!(flags & 8192),
          b[9],
          p.time,
          src,
          dst,
          p.scope,
        );
      else transport(b.subarray(h, len), b[9], p.time, src, dst, p.scope);
    } else if (type === 0x86dd && b[0] >>> 4 === 6) {
      if (b.length < 40) return;
      const len = 40 + ((b[4] << 8) | b[5]);
      if (len > b.length) {
        warn("Truncated IPv6 packet skipped.");
        return;
      }
      const ip = (o: number) =>
        Array.from({ length: 8 }, (_, i) =>
          ((b[o + i * 2] << 8) | b[o + i * 2 + 1]).toString(16),
        ).join(":");
      const src = ip(8),
        dst = ip(24);
      let next = b[6],
        o = 40,
        steps = 0;
      while ([0, 43, 60, 51, 44].includes(next)) {
        if (++steps > 16 || o + 8 > len) {
          warn("Invalid IPv6 extension chain skipped.");
          return;
        }
        const n = b[o];
        if (next === 44) {
          const f = (b[o + 2] << 8) | b[o + 3];
          const id = new DataView(b.buffer, b.byteOffset + o + 4, 4).getUint32(
            0,
          );
          fragment(
            b.subarray(o + 8, len),
            `${p.scope}|${src}>${dst}|${id}`,
            f & 0xfff8,
            !!(f & 1),
            n,
            p.time,
            src,
            dst,
            p.scope,
          );
          return;
        }
        const size = next === 51 ? (b[o + 1] + 2) * 4 : (b[o + 1] + 1) * 8;
        o += size;
        next = n;
        if (o > len) return;
      }
      transport(b.subarray(o, len), next, p.time, src, dst, p.scope);
    }
  }
  function processStream(segs: Segment[]) {
    if (!segs.length) return;
    const anchor = segs[0].seq;
    const rel = (s: Segment) => (s.seq - anchor) | 0;
    segs.sort((a, b) => rel(a) - rel(b) || a.time - b.time);
    // Normalize to non-overlapping spans before producing any messages. Reject
    // inconsistent retransmissions: choosing bytes would hide capture ambiguity.
    const spans: Segment[] = [];
    let covered = -Infinity;
    for (const segment of segs) {
      const start = rel(segment),
        end = start + segment.data.length;
      for (let i = spans.length - 1; i >= 0; i--) {
        const previous = spans[i],
          previousStart = rel(previous);
        const previousEnd = previousStart + previous.data.length;
        if (previousEnd <= start) break;
        const from = Math.max(start, previousStart),
          to = Math.min(end, previousEnd);
        for (let byte = from; byte < to; byte++) {
          if (
            segment.data[byte - start] !== previous.data[byte - previousStart]
          ) {
            warn(
              "Conflicting TCP retransmission bytes; ambiguous stream skipped.",
            );
            return;
          }
        }
      }
      const skip = Math.max(0, covered - start);
      if (skip >= segment.data.length) continue;
      spans.push({
        ...segment,
        seq: (segment.seq + skip) >>> 0,
        data: segment.data.subarray(skip),
      });
      covered = end;
    }
    segs = spans;
    let pending = new Uint8Array(0),
      next = rel(segs[0]),
      meta = segs[0],
      pendingStart = next,
      metaIndex = 0;
    function drain(final = false) {
      while (pending.length) {
        while (pending.length >= 2 && pending[0] === 13 && pending[1] === 10) {
          pending = pending.subarray(2);
          pendingStart += 2;
        }
        if (!pending.length) break;
        if (
          !startPattern.test(
            ascii.decode(pending.subarray(0, Math.min(pending.length, 2048))),
          )
        ) {
          if (final)
            warn(
              "TCP bytes without a complete SIP start-line skipped (capture may start mid-stream).",
            );
          break;
        }
        while (
          metaIndex + 1 < segs.length &&
          rel(segs[metaIndex + 1]) <= pendingStart
        )
          metaIndex++;
        meta = segs[metaIndex];
        const used = sip(pending, meta.time, meta.src, meta.dst, "TCP", final);
        if (used <= 0) {
          if (used < 0) pending = new Uint8Array(0);
          break;
        }
        pending = pending.subarray(used);
        pendingStart += used;
      }
    }
    for (const s of segs) {
      let pos = rel(s);
      if (pos > next) {
        drain(true);
        warn("TCP stream has a capture gap; incomplete message skipped.");
        pending = new Uint8Array(0);
        next = pos;
      }
      const skip = Math.max(0, next - pos);
      if (skip >= s.data.length) continue;
      if (!pending.length) {
        meta = s;
        pendingStart = pos + skip;
      }
      pending = join(pending, s.data.subarray(skip));
      next = pos + s.data.length;
      if (pending.length > MAX_MESSAGE + 65536) {
        warn("TCP buffered message exceeds limit; skipped.");
        pending = new Uint8Array(0);
      } else drain();
    }
    drain(true);
  }
  if (bytes.length < 4)
    throw Error("File is too short to be a packet capture.");
  if (view.getUint32(0) === 0x0a0d0d0a) {
    let o = 0,
      le = true,
      section = 0;
    let interfaces: { link: number; resolution: number; offset: number }[] = [];
    while (o < bytes.length) {
      if (!safe(o, 12)) {
        warn("Truncated pcapng block.");
        break;
      }
      const sectionHeader = view.getUint32(o) === 0x0a0d0d0a;
      if (sectionHeader) {
        if (!safe(o, 28)) throw Error("Truncated pcapng section.");
        const bom = view.getUint32(o + 8);
        if (bom !== 0x1a2b3c4d && bom !== 0x4d3c2b1a)
          throw Error("Invalid pcapng byte order.");
        le = bom === 0x4d3c2b1a;
        interfaces = [];
        section++;
      }
      const type = view.getUint32(o, le),
        len = view.getUint32(o + 4, le);
      if (
        len < 12 ||
        len % 4 ||
        !safe(o, len) ||
        view.getUint32(o + len - 4, le) !== len
      ) {
        warn("Invalid or truncated pcapng block length.");
        break;
      }
      if (type === 1 && len >= 20) {
        let resolution = 1e-6,
          offset = 0;
        for (let q = o + 16; q + 4 <= o + len - 4;) {
          const code = view.getUint16(q, le),
            n = view.getUint16(q + 2, le);
          if (code === 0) break;
          if (q + 4 + n > o + len - 4) {
            warn("Invalid pcapng interface option.");
            break;
          }
          if (code === 9 && n === 1) {
            const r = bytes[q + 4];
            resolution = r & 128 ? 2 ** -(r & 127) : 10 ** -r;
          }
          if (code === 14 && n === 8)
            offset = Number(view.getBigInt64(q + 4, le));
          q += 4 + Math.ceil(n / 4) * 4;
        }
        interfaces.push({
          link: view.getUint16(o + 8, le),
          resolution,
          offset,
        });
      } else if (type === 6 && len >= 32) {
        const id = view.getUint32(o + 8, le),
          iface = interfaces[id],
          cap = view.getUint32(o + 20, le);
        if (!iface) warn("pcapng packet refers to an unknown interface.");
        else if (cap > len - 32) warn("Invalid pcapng captured length.");
        else {
          const t =
            (Number(view.getUint32(o + 12, le)) * 4294967296 +
              view.getUint32(o + 16, le)) *
              iface.resolution +
            iface.offset;
          packet({
            data: bytes.subarray(o + 28, o + 28 + cap),
            time: t,
            link: iface.link,
            scope: `${section}:${id}`,
          });
        }
      } else if (type === 3)
        warn("pcapng Simple Packet Blocks lack timestamps and are skipped.");
      else if (type === 2)
        warn("Obsolete pcapng Packet Blocks are unsupported.");
      o += len;
    }
  } else {
    const magic = view.getUint32(0);
    const le = magic === 0xd4c3b2a1 || magic === 0x4d3cb2a1,
      nano = magic === 0xa1b23c4d || magic === 0x4d3cb2a1;
    if (![0xa1b2c3d4, 0xd4c3b2a1, 0xa1b23c4d, 0x4d3cb2a1].includes(magic))
      throw Error("Not a supported pcap or pcapng file.");
    if (!safe(0, 24)) throw Error("Truncated pcap header.");
    if (view.getUint16(4, le) !== 2 || view.getUint16(6, le) !== 4)
      throw Error("Unsupported pcap version.");
    const link = view.getUint32(20, le) & 0xffff;
    for (let o = 24; o < bytes.length;) {
      if (!safe(o, 16)) {
        warn("Truncated pcap packet header.");
        break;
      }
      const n = view.getUint32(o + 8, le);
      if (!safe(o + 16, n)) {
        warn("Truncated pcap packet data.");
        break;
      }
      packet({
        time:
          view.getUint32(o, le) +
          view.getUint32(o + 4, le) / (nano ? 1e9 : 1e6),
        data: bytes.subarray(o + 16, o + 16 + n),
        link,
        scope: "pcap",
      });
      o += 16 + n;
    }
  }
  for (const segs of streams.values()) processStream(segs);
  if (fragments.size)
    warn(
      `${fragments.size} incomplete IP fragment set(s); SIP may be missing (capture truncated or fragments absent).`,
    );
  result.messages.sort((a, b) => a.time - b.time).forEach((m, i) => (m.id = i));
  progress?.(result.packets);
  return result;
}
