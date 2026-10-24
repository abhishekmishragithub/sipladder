import { endpoint, type Capture, type Dialog, type SipMessage } from "./types";
interface Sdp {
  address: string;
  port: number;
  formats: string[];
  codecs: Record<string, string>;
  direction: string;
}
function sdp(m: SipMessage): Sdp | undefined {
  if (!/^application\/sdp(?:;|$)/i.test(m.headers["content-type"] ?? ""))
    return;
  const lines = m.body.split(/\r?\n/);
  let address = "",
    port = 0,
    formats: string[] = [],
    audio = false,
    direction = "sendrecv";
  const codecs: Record<string, string> = {
    "0": "PCMU/8000",
    "8": "PCMA/8000",
    "9": "G722/8000",
    "18": "G729/8000",
  };
  for (const l of lines) {
    if (l.startsWith("m=")) {
      if (audio) break;
      const match = l.match(/^m=audio (\d+)(?:\/\d+)? RTP\/[A-Z/]+ (.+)/);
      audio = !!match;
      if (match) {
        port = Number(match[1]);
        formats = match[2].trim().split(/\s+/);
      }
    } else if (l.startsWith("c=") && (!port || audio)) {
      address = l.split(/\s+/)[2]?.split("/")[0] ?? "";
    } else if (audio && l.startsWith("a=rtpmap:")) {
      const match = l.match(/^a=rtpmap:(\d+) (\S+)/);
      if (match) codecs[match[1]] = match[2];
    } else if (/^a=(sendonly|recvonly|inactive|sendrecv)$/.test(l))
      direction = l.slice(2);
  }
  if (port && address) return { address, port, formats, codecs, direction };
}
const normalizeIp = (ip: string) => {
  if (!ip.includes(":")) return ip;
  const halves = ip.toLowerCase().split("::");
  const left = halves[0].split(":").filter(Boolean),
    right = (halves[1] ?? "").split(":").filter(Boolean);
  return [
    ...left,
    ...Array(
      halves.length > 1 ? Math.max(0, 8 - left.length - right.length) : 0,
    ).fill("0"),
    ...right,
  ]
    .map((x) => parseInt(x, 16).toString(16))
    .join(":");
};
function transaction(a: SipMessage, b: SipMessage) {
  return (
    a.cseq === b.cseq &&
    a.branch === b.branch &&
    endpoint(a.src) === endpoint(b.dst) &&
    endpoint(a.dst) === endpoint(b.src)
  );
}
export function groupDialogs(capture: Capture): Dialog[] {
  const groups = new Map<string, SipMessage[]>();
  for (const m of capture.messages) {
    const ms = groups.get(m.callId) ?? [];
    ms.push(m);
    groups.set(m.callId, ms);
  }
  return [...groups].map(([id, messages]) => {
    const invites = messages.filter((m) => !m.status && m.method === "INVITE");
    const first = invites[0];
    const answers = messages.filter(
      (m) =>
        m.status && m.status >= 200 && m.status < 300 && m.method === "INVITE",
    );
    const answer = answers[0];
    const cancel = messages.some(
      (request) =>
        !request.status &&
        request.method === "CANCEL" &&
        messages.some(
          (response) =>
            response.status === 487 &&
            response.method === "INVITE" &&
            request.cseq.split(/\s+/)[0] === response.cseq.split(/\s+/)[0] &&
            request.branch === response.branch &&
            endpoint(request.src) === endpoint(response.dst) &&
            endpoint(request.dst) === endpoint(response.src),
        ),
    );
    const failures = messages.filter(
      (m) =>
        m.method === "INVITE" &&
        (m.status ?? 0) >= 300 &&
        ![401, 407].includes(m.status!),
    );
    const result = answer
      ? "answered"
      : cancel
        ? "cancelled"
        : failures.length
          ? "rejected"
          : first
            ? "timeout"
            : "observed";
    const diagnoses: string[] = [];
    const challengedRetry = (status: number, header: string) =>
      messages.some(
        (challenge) =>
          challenge.status === status &&
          challenge.method === "INVITE" &&
          invites.some(
            (retry) =>
              !!retry.headers[header] &&
              retry.time >= challenge.time &&
              Number(retry.cseq.split(/\s+/)[0]) >
                Number(challenge.cseq.split(/\s+/)[0]) &&
              endpoint(retry.src) === endpoint(challenge.dst) &&
              endpoint(retry.dst) === endpoint(challenge.src),
          ),
      );
    if (challengedRetry(407, "proxy-authorization"))
      diagnoses.push(
        "407 proxy challenge followed by an authenticated INVITE (digest flow).",
      );
    if (challengedRetry(401, "authorization"))
      diagnoses.push(
        "401 challenge followed by an authenticated INVITE (digest flow).",
      );
    if (cancel)
      diagnoses.push(
        "CANCEL / 487: the INVITE was cancelled before it completed.",
      );
    const transactions = new Map<
      string,
      { request?: SipMessage; attempts: number; responses: SipMessage[] }
    >();
    for (const message of messages) {
      const key = JSON.stringify([
        message.cseq,
        message.branch,
        endpoint(message.status ? message.dst : message.src),
        endpoint(message.status ? message.src : message.dst),
      ]);
      const entry = transactions.get(key) ?? { attempts: 0, responses: [] };
      if (message.status) entry.responses.push(message);
      else {
        entry.request ??= message;
        entry.attempts++;
      }
      transactions.set(key, entry);
    }
    for (const { request, attempts, responses } of transactions.values()) {
      if (!request || request.method === "ACK") continue;
      if (!responses.length)
        diagnoses.push(
          `${request.method}${attempts > 1 ? ` retransmitted ${attempts - 1}x` : ""}, no response observed — destination may be unreachable, packets dropped, or capture incomplete.`,
        );
      else if (!responses.some((m) => m.status! >= 200))
        diagnoses.push(
          `${request.method}: provisional response only; no final response observed.`,
        );
    }
    const offer = first ? sdp(first) : undefined,
      accepted = answer ? sdp(answer) : undefined;
    const common =
      accepted?.formats.filter((f) => !offer || offer.formats.includes(f)) ??
      [];
    const codec =
      common
        .map((f) => accepted?.codecs[f] ?? `payload ${f}`)
        .filter((x) => !x.toLowerCase().startsWith("telephone-event"))
        .join(", ") || "not established";
    let rtp = "not observed";
    // Match both advertised media endpoints, payload types, and the observed call interval.
    if (offer && accepted) {
      const end =
        messages.find((m) => m.method === "BYE" && !m.status)?.time ?? Infinity;
      const match = (e: { ip: string; port: number }, s: Sdp) =>
        normalizeIp(e.ip) === normalizeIp(s.address) && e.port === s.port;
      let forward = 0,
        reverse = 0;
      for (const p of capture.media) {
        if (
          p.time < (first?.time ?? 0) ||
          p.time > end ||
          !common.includes(String(p.payloadType))
        )
          continue;
        if (match(p.src, offer) && match(p.dst, accepted)) forward++;
        if (match(p.src, accepted) && match(p.dst, offer)) reverse++;
      }
      rtp =
        forward && reverse
          ? "both directions"
          : forward
            ? "offerer → answerer only"
            : reverse
              ? "answerer → offerer only"
              : "not observed";
      if (!!forward !== !!reverse)
        diagnoses.push(
          `Possible one-way audio: RTP observed ${rtp}. Capture placement, NAT, or SDP direction may explain this.`,
        );
      if (offer.direction !== "sendrecv" || accepted.direction !== "sendrecv")
        diagnoses.push(
          `SDP direction: offer ${offer.direction}, answer ${accepted.direction}.`,
        );
    }
    const matchingInvite = answer
      ? invites.find((m) => transaction(m, answer))
      : undefined;
    return {
      id,
      messages,
      result,
      setup:
        answer && matchingInvite
          ? answer.time - matchingInvite.time
          : undefined,
      codec,
      rtp,
      diagnoses,
    };
  });
}
// Export an allowlist only. Raw SIP, Call-ID, Via branches, display names, auth,
// custom headers, and SDP never enter the ticket text.
export function sanitizedLadder(d: Dialog): string {
  const endpoints = [
    ...new Set(d.messages.flatMap((m) => [endpoint(m.src), endpoint(m.dst)])),
  ];
  const name = (e: Parameters<typeof endpoint>[0]) =>
    `endpoint ${endpoints.indexOf(endpoint(e)) + 1}`;
  const safeMethod = (m: SipMessage) =>
    /^[A-Z][A-Z0-9.!%*_+`'~-]{0,31}$/.test(m.method) ? m.method : "[redacted]";
  return [
    `SIP ladder (sanitized; identities, addresses, headers and SDP omitted)`,
    `Result: ${d.result}`,
    `Setup: ${d.setup === undefined ? "unknown" : d.setup.toFixed(3) + "s"}`,
    `RTP: ${d.rtp}`,
    ...d.messages.map(
      (m) =>
        `+${(m.time - d.messages[0].time).toFixed(3)}s | ${name(m.src)} -> ${name(m.dst)} | ${m.status ? `${m.status} (${safeMethod(m)})` : safeMethod(m)} | CSeq ${/^\d+\s+[A-Z]+$/.test(m.cseq) ? m.cseq : "[redacted]"}`,
    ),
  ].join("\n");
}
