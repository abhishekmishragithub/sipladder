export interface Endpoint {
  ip: string;
  port: number;
}
export interface SipMessage {
  id: number;
  time: number;
  src: Endpoint;
  dst: Endpoint;
  transport: "UDP" | "TCP";
  start: string;
  method: string;
  status?: number;
  callId: string;
  cseq: string;
  branch: string;
  headers: Record<string, string>;
  raw: string;
  body: string;
}
export interface MediaPacket {
  time: number;
  src: Endpoint;
  dst: Endpoint;
  payloadType: number;
}
export interface Capture {
  messages: SipMessage[];
  media: MediaPacket[];
  warnings: string[];
  packets: number;
}
export interface Dialog {
  id: string;
  messages: SipMessage[];
  result: string;
  setup?: number;
  codec: string;
  rtp: string;
  diagnoses: string[];
}
export const endpoint = (e: Endpoint) =>
  `${e.ip.includes(":") ? `[${e.ip}]` : e.ip}:${e.port}`;
