import "./style.css";
import { demoCapture } from "./sample";
import ParserWorker from "./worker?worker&inline";
import { endpoint, type Dialog, type SipMessage } from "./types";
import { sanitizedLadder } from "./dialogs";
const $ = <T extends HTMLElement = HTMLElement>(id: string) =>
  document.getElementById(id) as T;
let worker: Worker | undefined,
  dialogs: Dialog[] = [],
  active = 0,
  selected = 0,
  table = false,
  generation = 0,
  page = 0;
const node = <K extends keyof HTMLElementTagNameMap>(
  tag: K,
  text?: string,
  className?: string,
) => {
  const n = document.createElement(tag);
  if (text !== undefined) n.textContent = text;
  if (className) n.className = className;
  return n;
};
const color = (m: SipMessage) =>
  m.status
    ? m.status < 200
      ? "provisional"
      : m.status < 300
        ? "success"
        : m.status < 400
          ? "redirect"
          : "failure"
    : "request";
function clear() {
  generation++;
  worker?.terminate();
  worker = undefined;
  dialogs = [];
  for (const id of [
    "dialogs",
    "summary",
    "ladder",
    "table",
    "diagnoses",
    "warnings",
    "detail-content",
    "pagination",
    "filename",
    "capture-info",
  ])
    $(id).replaceChildren();
  $("workspace").hidden = true;
  $("intro").hidden = false;
  $("status").textContent = "Capture cleared from the workspace.";
  ($("file") as HTMLInputElement).value = "";
  $("error").hidden = true;
}
async function open(file: File) {
  const run = ++generation;
  worker?.terminate();
  dialogs = [];
  for (const id of [
    "dialogs",
    "summary",
    "ladder",
    "table",
    "diagnoses",
    "warnings",
    "detail-content",
    "pagination",
  ])
    $(id).replaceChildren();
  $("filename").textContent = "";
  $("capture-info").textContent = "";
  $("workspace").hidden = true;
  $("intro").hidden = false;
  $("error").hidden = true;
  $("status").textContent = `Reading ${file.name} locally…`;
  if (file.size > 256 * 1024 * 1024) {
    $("error").textContent =
      "This version supports captures up to 256 MiB. Split larger files locally with editcap.";
    $("error").hidden = false;
    $("status").textContent = "";
    return;
  }
  try {
    const data = await file.arrayBuffer();
    if (run !== generation) return;
    worker = new ParserWorker();
    worker.onerror = () =>
      fail("The parsing worker stopped unexpectedly. Try a smaller capture.");
    const fail = (message: string) => {
      if (run !== generation) return;
      $("status").textContent = "";
      $("error").textContent = message;
      $("error").hidden = false;
      worker?.terminate();
    };
    worker.onmessage = (e) => {
      if (run !== generation) return;
      const r = e.data;
      if (r.type === "progress") {
        $("status").textContent =
          `Parsing locally · ${r.packets.toLocaleString()} packets…`;
        return;
      }
      if (r.type === "error") {
        fail(r.error);
        return;
      }
      dialogs = r.dialogs;
      active = 0;
      selected = 0;
      page = 0;
      $("intro").hidden = true;
      $("workspace").hidden = false;
      $("filename").textContent = file.name;
      $("capture-info").textContent =
        `${r.packets.toLocaleString()} packets · ${dialogs.reduce((n, d) => n + d.messages.length, 0)} SIP messages · ${dialogs.length} conversations`;
      $("warnings").replaceChildren(
        ...r.warnings.map((w: string) => node("p", w, "warning")),
      );
      $("status").textContent = dialogs.length
        ? "Capture ready. Everything was processed locally."
        : "No complete SIP messages found. Encrypted SIP (TLS) cannot be decoded.";
      render();
      worker?.terminate();
      worker = undefined;
    };
    worker.postMessage(data, [data]);
  } catch (e) {
    if (run !== generation) return;
    $("error").textContent = e instanceof Error ? e.message : String(e);
    $("error").hidden = false;
    $("status").textContent = "";
  }
}
function render() {
  $("call-count").textContent = String(dialogs.length);
  $("dialogs").replaceChildren(
    ...dialogs.map((d, i) => {
      const b = node(
        "button",
        undefined,
        `dialog-card ${i === active ? "active" : ""}`,
      );
      b.setAttribute("aria-pressed", String(i === active));
      b.append(
        node("span", `CALL ${String(i + 1).padStart(2, "0")}`, "eyebrow"),
        node("strong", d.id),
        node("span", `${d.result} · ${d.messages.length} messages`, "muted"),
      );
      b.onclick = () => {
        active = i;
        selected = 0;
        page = 0;
        render();
      };
      return b;
    }),
  );
  const d = dialogs[active];
  if (!d) {
    $("summary").replaceChildren(
      node("p", "No SIP conversations in this capture."),
    );
    return;
  }
  $("summary").replaceChildren(
    node(
      "div",
      `CONVERSATION ${String(active + 1).padStart(2, "0")}`,
      "eyebrow",
    ),
    node("h2", d.id),
  );
  const chips = node("div", undefined, "chips");
  for (const [label, value] of [
    ["Result", d.result],
    [
      "Setup",
      d.setup === undefined ? "unknown" : `${(d.setup * 1000).toFixed(0)} ms`,
    ],
    ["SDP answer codecs", d.codec],
    ["RTP observed", d.rtp],
  ]) {
    const chip = node("div", undefined, "chip");
    chip.append(node("span", label), node("strong", value));
    chips.append(chip);
  }
  $("summary").append(chips);
  $("diagnoses").replaceChildren(
    ...d.diagnoses.slice(0, 50).map((x) => node("p", x, "diagnosis")),
  );
  if (d.diagnoses.length > 50)
    $("diagnoses").append(
      node(
        "p",
        `${d.diagnoses.length - 50} more diagnoses; select smaller captures for detailed analysis.`,
        "muted",
      ),
    );
  renderLadder(d);
  renderTable(d);
  renderPager(d);
  showMessage(selected);
  $("ladder").hidden = table;
  $("table").hidden = !table;
  $("svg-view").setAttribute("aria-pressed", String(!table));
  $("table-view").setAttribute("aria-pressed", String(table));
}
function renderLadder(d: Dialog) {
  const endpoints = [
    ...new Set(d.messages.flatMap((m) => [endpoint(m.src), endpoint(m.dst)])),
  ];
  const width = Math.max(660, endpoints.length * 220),
    height = 92 + Math.min(100, d.messages.length - page * 100) * 58;
  const ns = "http://www.w3.org/2000/svg";
  const svg = document.createElementNS(ns, "svg");
  svg.setAttribute("viewBox", `0 0 ${width} ${height}`);
  svg.setAttribute("width", String(width));
  svg.setAttribute("height", String(height));
  svg.setAttribute("aria-label", "SIP message sequence");
  const el = (
    tag: string,
    attrs: Record<string, string | number>,
    text?: string,
  ) => {
    const n = document.createElementNS(ns, tag);
    for (const [k, v] of Object.entries(attrs)) n.setAttribute(k, String(v));
    if (text) n.textContent = text;
    return n;
  };
  const x = (e: string) =>
    100 +
    (endpoints.indexOf(e) * (width - 200)) / Math.max(1, endpoints.length - 1);
  for (const e of endpoints) {
    svg.append(
      el(
        "text",
        { x: x(e), y: 24, "text-anchor": "middle", class: "endpoint" },
        e,
      ),
      el("line", {
        x1: x(e),
        x2: x(e),
        y1: 44,
        y2: height - 12,
        class: "lifeline",
      }),
    );
  }
  d.messages.slice(page * 100, (page + 1) * 100).forEach((m, local) => {
    const i = page * 100 + local,
      y = 76 + local * 58,
      a = x(endpoint(m.src)),
      b = x(endpoint(m.dst)),
      direction = b >= a ? 1 : -1;
    const g = el("g", {
      class: `message ${color(m)}`,
      "data-message": i,
      role: "button",
      tabindex: 0,
      "aria-label": `${i + 1}. ${m.start}, ${endpoint(m.src)} to ${endpoint(m.dst)}, ${(m.time - d.messages[0].time).toFixed(3)} seconds`,
    });
    svg.append(
      el("line", { x1: 8, x2: 20, y1: y, y2: y, class: "timing-tick" }),
      el(
        "text",
        { x: 24, y: y + 3, class: "timing-label" },
        `+${(m.time - d.messages[0].time).toFixed(3)}`,
      ),
    );
    g.append(
      el("rect", {
        x: 8,
        y: y - 26,
        width: width - 16,
        height: 54,
        rx: 2,
        class: "row-hit",
      }),
      el("line", { x1: a, y1: y, x2: b, y2: y, class: "arrow" }),
      el("path", {
        d: `M ${b - direction * 8} ${y - 4} L ${b} ${y} L ${b - direction * 8} ${y + 4}`,
        class: "arrowhead",
      }),
      el(
        "text",
        {
          x: (a + b) / 2,
          y: y - 9,
          "text-anchor": "middle",
          class: "message-label",
        },
        m.status ? m.start.slice(8) : m.method,
      ),
      el(
        "text",
        {
          x: (a + b) / 2,
          y: y + 17,
          "text-anchor": "middle",
          class: "message-meta",
        },
        `+${(m.time - d.messages[0].time).toFixed(3)}s · CSeq ${m.cseq} · ${m.transport}`,
      ),
    );
    g.addEventListener("click", () => showMessage(i));
    g.addEventListener("keydown", (e) => {
      if (
        (e as KeyboardEvent).key === "Enter" ||
        (e as KeyboardEvent).key === " "
      ) {
        e.preventDefault();
        showMessage(i);
      }
    });
    svg.append(g);
  });
  $("ladder").replaceChildren(svg);
}
function renderTable(d: Dialog) {
  const t = node("table"),
    caption = node("caption", "SIP messages in capture order");
  t.append(caption);
  const head = node("thead"),
    hr = node("tr");
  for (const s of ["Time", "From", "To", "Message", "CSeq", "Inspect"])
    hr.append(node("th", s));
  head.append(hr);
  t.append(head);
  const body = node("tbody");
  d.messages.slice(page * 100, (page + 1) * 100).forEach((m, local) => {
    const i = page * 100 + local,
      row = node("tr");
    for (const s of [
      `+${(m.time - d.messages[0].time).toFixed(3)}s`,
      endpoint(m.src),
      endpoint(m.dst),
      m.start,
      m.cseq,
    ])
      row.append(node("td", s));
    const td = node("td"),
      button = node("button", "Inspect");
    button.onclick = () => showMessage(i);
    td.append(button);
    row.append(td);
    body.append(row);
  });
  t.append(body);
  $("table").replaceChildren(t);
}
function renderPager(d: Dialog) {
  const root = $("pagination");
  root.replaceChildren();
  if (d.messages.length <= 100) return;
  const prev = node("button", "← Previous"),
    next = node("button", "Next →");
  prev.disabled = page === 0;
  next.disabled = (page + 1) * 100 >= d.messages.length;
  prev.onclick = () => {
    page--;
    selected = page * 100;
    render();
  };
  next.onclick = () => {
    page++;
    selected = page * 100;
    render();
  };
  root.append(
    prev,
    node(
      "span",
      `Messages ${page * 100 + 1}–${Math.min((page + 1) * 100, d.messages.length)} of ${d.messages.length}`,
    ),
    next,
  );
}
function showMessage(i: number) {
  const d = dialogs[active],
    m = d?.messages[i];
  if (!m) return;
  selected = i;
  if (Math.floor(i / 100) !== page) {
    page = Math.floor(i / 100);
    renderLadder(d);
    renderTable(d);
    renderPager(d);
  }
  document.querySelectorAll("[data-message]").forEach((g) => {
    const yes = Number(g.getAttribute("data-message")) === i;
    g.classList.toggle("selected", yes);
    g.setAttribute("aria-pressed", String(yes));
  });
  $("detail-content").replaceChildren(
    node("span", `${i + 1} / ${d.messages.length} · ${m.transport}`, "eyebrow"),
    node("h3", m.start),
    node("p", `${endpoint(m.src)} → ${endpoint(m.dst)}`, "muted"),
    node("pre", m.raw),
  );
}
$("ladder").addEventListener("keydown", (e) => {
  if (e.key === "ArrowDown" || e.key === "ArrowUp") {
    e.preventDefault();
    showMessage(
      Math.max(
        0,
        Math.min(
          dialogs[active].messages.length - 1,
          selected + (e.key === "ArrowDown" ? 1 : -1),
        ),
      ),
    );
    document
      .querySelector(`[data-message="${selected}"]`)
      ?.scrollIntoView({ block: "nearest" });
  }
});
$("file").onchange = () => {
  const f = ($("file") as HTMLInputElement).files?.[0];
  if (f) void open(f);
};
for (const event of ["dragenter", "dragover"])
  document.addEventListener(event, (e) => {
    e.preventDefault();
    $("dropzone").classList.add("dragging");
  });
document.addEventListener("dragleave", (e) => {
  if (!(e as DragEvent).relatedTarget)
    $("dropzone").classList.remove("dragging");
});
document.addEventListener("drop", (e) => {
  e.preventDefault();
  $("dropzone").classList.remove("dragging");
  const f = e.dataTransfer?.files[0];
  if (f) void open(f);
});
$("replace").onclick = () => $("file").click();
$("clear").onclick = clear;
$("svg-view").onclick = () => {
  table = false;
  render();
};
$("table-view").onclick = () => {
  table = true;
  render();
};
$("theme").onclick = () => {
  const light = document.documentElement.dataset.theme
    ? document.documentElement.dataset.theme === "light"
    : matchMedia("(prefers-color-scheme: light)").matches;
  document.documentElement.dataset.theme = light ? "dark" : "light";
};
$("copy").onclick = async () => {
  const d = dialogs[active];
  if (!d) return;
  const text = sanitizedLadder(d);
  try {
    await navigator.clipboard.writeText(text);
    $("status").textContent =
      "Sanitized ladder copied. Identities, addresses, raw headers and SDP omitted.";
  } catch {
    $("detail-content").replaceChildren(
      node(
        "p",
        "Clipboard unavailable. Select and copy the sanitized text below.",
      ),
      node("pre", text),
    );
  }
};
$("demo").onclick = () => {
  void open(new File([demoCapture()], "sample-answered.pcap"));
};
