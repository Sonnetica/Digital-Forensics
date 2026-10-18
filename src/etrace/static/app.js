"use strict";

const $ = (id) => document.getElementById(id);
const labels = {
  attachment_reuse: "Attachment reuse",
  url_reuse: "URL reuse",
  reply: "Reply relationship",
  possible_coordination: "Possible coordination",
};
const state = {
  view: "evidence",
  offset: 0,
  limit: 30,
  total: 0,
  run: "",
  serial: 0,
  summary: null,
};

function el(tag, attributes = {}, ...children) {
  const node = document.createElement(tag);
  for (const [key, value] of Object.entries(attributes)) {
    if (key.startsWith("on")) node.addEventListener(key.slice(2), value);
    else if (key === "class") node.className = value;
    else if (key === "text") node.textContent = value;
    else node.setAttribute(key, value);
  }
  for (const child of children.flat())
    if (child !== null && child !== undefined)
      node.append(
        child instanceof Node ? child : document.createTextNode(String(child)),
      );
  return node;
}

async function api(path, options = {}) {
  const headers = {
    "X-CSRF-Token": document.querySelector('meta[name="csrf-token"]').content,
    ...options.headers,
  };
  const response = await fetch(path, { ...options, headers });
  const data = await response.json();
  if (!response.ok)
    throw new Error(data.error || `Request failed (${response.status}).`);
  return data;
}

function notify(message, kind = "") {
  $("notice").textContent = message;
  $("notice").className = `notice ${kind}`;
}
function empty(title, message, action) {
  return el(
    "div",
    { class: "empty" },
    el("h3", {}, title),
    el("p", {}, message),
    action || null,
  );
}
function pill(type, text) {
  return el("span", { class: `pill ${type}` }, text || labels[type] || type);
}
function timestamp(value) {
  return value ? value.replace("T", " ").replace("Z", " UTC") : "Time unknown";
}
function short(value, length = 16) {
  return value.length > length ? value.slice(0, length) + "..." : value;
}
function button(text, action, cls = "button secondary") {
  return el("button", { type: "button", class: cls, onclick: action }, text);
}
function detailList(items) {
  return el(
    "dl",
    { class: "detail-grid" },
    Object.entries(items).flatMap(([key, value]) => [
      el("dt", {}, key),
      el("dd", {}, value ?? "Unknown"),
    ]),
  );
}
function disclose(title, text) {
  return el("details", {}, el("summary", {}, title), el("pre", {}, text));
}

async function refresh() {
  const [summary, runs] = await Promise.all([
    api("/api/case"),
    api("/api/runs"),
  ]);
  state.summary = summary;
  $("stat-messages").textContent = summary.evidence.toLocaleString();
  $("stat-sources").textContent =
    `${summary.sources.toLocaleString()} acquisition locations`;
  $("stat-artifacts").textContent = summary.artifacts.toLocaleString();
  $("stat-warnings").textContent = summary.warnings.toLocaleString();
  $("stat-undated").textContent =
    `${summary.undated} messages without a Date time`;
  const run = summary.latest_run;
  $("stat-events").textContent = run
    ? run.statistics.events.toLocaleString()
    : "0";
  $("stat-run").textContent = run
    ? run.stale
      ? "New evidence: rerun analysis"
      : `${summary.runs} saved analysis ${summary.runs === 1 ? "run" : "runs"}`
    : "Analysis not run";
  if (run?.stale)
    notify(
      "New evidence has been acquired since the latest analysis. Run analysis to include it.",
    );
  $("run-select").replaceChildren(
    el("option", { value: "" }, "Latest run"),
    ...runs.map((r) =>
      el(
        "option",
        { value: r.id },
        `${r.created_at.slice(0, 19).replace("T", " ")} / ${short(r.id, 8)}`,
      ),
    ),
  );
  $("run-select").value = state.run;
  await loadView();
}

function query() {
  const params = new URLSearchParams({
    q: $("search").value,
    offset: state.offset,
    limit: state.limit,
  });
  if (state.run) params.set("run", state.run);
  if (state.view !== "evidence") {
    for (const [name, id] of [
      ["type", "type-filter"],
      ["start", "start-filter"],
      ["end", "end-filter"],
    ])
      if ($(id).value) params.set(name, $(id).value);
  }
  return params.toString();
}

async function loadView() {
  const serial = ++state.serial;
  const descriptions = {
    evidence: [
      "Evidence collection",
      "Original messages and their extracted artifacts.",
    ],
    timeline: [
      "Reconstructed timeline",
      "Relationships in time, with the evidence behind each inference.",
    ],
    graph: [
      "Relationship graph",
      "Inspect how messages connect through shared artifacts and reply headers.",
    ],
    integrity: [
      "Case integrity",
      "Verify preserved evidence and review unresolved relationships.",
    ],
  };
  $("view-title").textContent = descriptions[state.view][0];
  $("view-description").textContent = descriptions[state.view][1];
  $("filters").classList.toggle("hidden", state.view === "integrity");
  document
    .querySelectorAll(".event-filter,.run-filter")
    .forEach((n) =>
      n.classList.toggle("hidden", !["timeline", "graph"].includes(state.view)),
    );
  $("pagination").classList.add("hidden");
  $("result-count").textContent = "";
  $("content").replaceChildren(empty("Loading case data", "Please wait."));
  try {
    const endpoint = {
      evidence: "emails",
      timeline: "events",
      graph: "graph",
      integrity: "verify",
    }[state.view];
    const data = await api(`/api/${endpoint}?${query()}`);
    if (serial !== state.serial) return;
    if (state.view === "evidence") renderEvidence(data);
    if (state.view === "timeline") renderTimeline(data);
    if (state.view === "graph") renderGraph(data);
    if (state.view === "integrity") await renderIntegrity(data, serial);
  } catch (error) {
    if (serial === state.serial)
      $("content").replaceChildren(
        empty("Unable to load this view", error.message),
      );
  }
}

function page(data) {
  state.total = data.total;
  $("result-count").textContent = `${data.total.toLocaleString()} results`;
  $("pagination").classList.toggle("hidden", data.total <= state.limit);
  $("page-description").textContent =
    `${data.offset + 1}-${Math.min(data.offset + data.limit, data.total)} of ${data.total}`;
  $("previous-page").disabled = state.offset === 0;
  $("next-page").disabled = state.offset + state.limit >= data.total;
}

function renderEvidence(data) {
  page(data);
  if (!data.items.length) {
    $("content").replaceChildren(
      empty(
        state.summary.evidence
          ? "No matching evidence"
          : "Start with the original messages",
        state.summary.evidence
          ? "Try a different subject, address, URL or hash."
          : "Import EML or MSG files to preserve their source bytes and extract the artifacts for your investigation.",
        button("Import evidence", () => $("import-dialog").showModal()),
      ),
    );
    return;
  }
  const rows = data.items.map((record) =>
    el(
      "tr",
      {},
      el(
        "td",
        {},
        el(
          "button",
          { class: "subject-button", onclick: () => showEmail(record.id) },
          record.subject || "(no subject)",
        ),
        el("span", { class: "cell-sub mono" }, short(record.id, 20)),
      ),
      el(
        "td",
        {},
        record.senders.map((s) => s.address).join(", ") || "Unknown sender",
        el(
          "span",
          { class: "cell-sub" },
          `To: ${record.recipients.map((r) => r.address).join(", ") || "Unknown"}`,
        ),
      ),
      el(
        "td",
        {},
        record.date_utc ? record.date_utc.slice(0, 10) : "Unknown",
        el(
          "span",
          { class: "cell-sub" },
          record.date_utc
            ? record.date_utc.slice(11, 19) + " UTC"
            : "No usable Date",
        ),
      ),
      el(
        "td",
        {},
        el("span", {}, `${record.artifact_counts.url || 0} URLs`),
        el(
          "span",
          { class: "cell-sub" },
          `${record.artifact_counts.attachment_sha256 || 0} attachments`,
        ),
      ),
      el(
        "td",
        {},
        record.warning_count
          ? pill("warning", `${record.warning_count} observations`)
          : pill("good", "Parsed"),
        el(
          "span",
          { class: "cell-sub" },
          `${record.format.toUpperCase()} / ${(record.size / 1024).toFixed(1)} KiB`,
        ),
      ),
    ),
  );
  $("content").replaceChildren(
    el(
      "div",
      { class: "table-scroll" },
      el(
        "table",
        {},
        el(
          "thead",
          {},
          el(
            "tr",
            {},
            [
              "MESSAGE / SHA-256",
              "PARTICIPANTS",
              "DATE HEADER",
              "ARTIFACTS",
              "REVIEW",
            ].map((t) => el("th", { scope: "col" }, t)),
          ),
        ),
        el("tbody", {}, rows),
      ),
    ),
  );
}

function renderTimeline(data) {
  page(data);
  if (!data.items.length) {
    $("content").replaceChildren(
      empty(
        "No relationships in this view",
        data.run_id
          ? "No rule results match these filters. Single messages and unrelated artifacts remain in the evidence collection."
          : "Import evidence and run analysis to reconstruct a timeline.",
      ),
    );
    return;
  }
  $("content").replaceChildren(
    el(
      "div",
      { class: "timeline" },
      data.items.map((event) =>
        el(
          "article",
          { class: "timeline-event" },
          el(
            "div",
            { class: "timeline-time" },
            event.start_utc ? event.start_utc.slice(0, 10) : "Unknown time",
            el(
              "small",
              {},
              event.start_utc
                ? event.start_utc.slice(11, 19) + " UTC"
                : "No date assigned",
            ),
          ),
          el(
            "div",
            { class: "timeline-card" },
            pill(event.type),
            el(
              "h3",
              {},
              event.subjects.filter(Boolean).join(" / ") || "Untitled messages",
            ),
            el("p", {}, event.explanation),
            el(
              "div",
              { class: "timeline-meta" },
              `${event.email_ids.length} source messages`,
              `${event.support_count} observations`,
              `${event.context_count} context notes`,
              button(
                "Inspect evidence",
                () => showEvent(event.id, data.run_id),
                "text-button",
              ),
            ),
          ),
        ),
      ),
    ),
  );
}

async function showEmail(id, back = null) {
  try {
    const record = await api(`/api/emails/${id}`);
    $("detail-title").textContent = record.subject || "(no subject)";
    $("detail-eyebrow").textContent = "SOURCE EMAIL";
    const content = $("detail-content");
    content.replaceChildren();
    if (back)
      content.append(button("Back to relationship", back, "text-button"));
    content.append(
      detailList({
        "SHA-256": el("span", { class: "mono" }, record.sha256),
        From: record.senders.map((s) => s.address).join(", ") || "Unknown",
        Recipients:
          record.recipients
            .map((s) => `${s.address} (${s.field})`)
            .join(", ") || "Unknown",
        "Date (UTC)": timestamp(record.date_utc),
        "Received (UTC)": timestamp(record.received_utc),
        "Message-ID": record.message_ids.join(", ") || "Missing",
        "Source format": `${record.format.toUpperCase()} / ${record.size.toLocaleString()} bytes`,
        "Parser version": record.parser_version,
      }),
    );
    content.append(
      el(
        "div",
        { class: "detail-block" },
        el(
          "a",
          {
            class: "button secondary",
            href: `/api/emails/${id}/source`,
            download: "",
          },
          "Download preserved source",
        ),
      ),
    );
    content.append(
      el("h3", {}, "Acquisition locations"),
      ...record.sources.map((s) =>
        el(
          "div",
          { class: "observation" },
          el("small", {}, timestamp(s.acquired_at)),
          s.name,
        ),
      ),
    );
    if (record.warnings.length)
      content.append(
        el("h3", {}, "Parsing observations"),
        ...record.warnings.map((w) =>
          el(
            "div",
            { class: "observation context" },
            el("small", {}, `${w.code} / ${w.location}`),
            w.message,
          ),
        ),
      );
    content.append(
      disclose(
        "Header fields and source locations",
        record.headers
          .map(
            (h) =>
              `[${h.location}]${h.byte_start !== undefined ? ` bytes ${h.byte_start}-${h.byte_end} (end exclusive)` : ""}\n${h.raw || h.name + ": " + h.value}`,
          )
          .join("\n"),
      ),
    );
    content.append(
      disclose(
        "Body preview (text only, up to 12,000 characters)",
        record.body_preview || "No supported text body.",
      ),
    );
    content.append(
      disclose(
        "All extracted artifacts",
        JSON.stringify(record.artifacts, null, 2),
      ),
      disclose(
        "Timestamp observations",
        JSON.stringify(record.timestamps, null, 2),
      ),
      disclose("MIME and Outlook parts", JSON.stringify(record.parts, null, 2)),
    );
    if (!$("detail-dialog").open) $("detail-dialog").showModal();
    $("detail-dialog").scrollTop = 0;
  } catch (error) {
    notify(error.message, "error");
  }
}

async function showEvent(id, run = state.run) {
  try {
    const event = await api(
      `/api/events/${id}${run ? "?run=" + encodeURIComponent(run) : ""}`,
    );
    $("detail-title").textContent = labels[event.type];
    $("detail-eyebrow").textContent = "RELATIONSHIP PROVENANCE";
    const content = $("detail-content");
    content.replaceChildren(
      el(
        "div",
        { class: "detail-block" },
        pill(event.type),
        el("p", {}, event.explanation),
      ),
    );
    content.append(
      detailList({
        Interpretation: event.interpretation,
        Rule: `${event.rule_id} / v${event.rule_version}`,
        "Time range": `${timestamp(event.start_utc)} to ${timestamp(event.end_utc)}`,
        "Relationship ID": el("span", { class: "mono" }, event.id),
      }),
    );
    content.append(
      el("h3", {}, "Participating evidence"),
      ...event.messages.map((m) =>
        button(
          m.subject || "(no subject)",
          () => showEmail(m.id, () => showEvent(id, run)),
          "evidence-link",
        ),
      ),
    );
    content.append(el("h3", {}, "Supporting observations"));
    for (const observation of event.support) {
      content.append(
        el(
          "div",
          { class: "observation" },
          el("small", {}, `${observation.kind} / ${observation.location}`),
          el("div", { class: "mono" }, observation.value),
          button(
            `Source ${short(observation.email_id)}`,
            () => showEmail(observation.email_id, () => showEvent(id, run)),
            "text-button",
          ),
          disclose("Original observation", observation.raw),
          Object.keys(observation.metadata || {}).length
            ? disclose(
                "Observation metadata",
                JSON.stringify(observation.metadata, null, 2),
              )
            : null,
        ),
      );
    }
    content.append(el("h3", {}, "Context and counter-evidence"));
    if (!event.context.length)
      content.append(
        el(
          "p",
          { class: "muted" },
          "No additional context was flagged by these rules.",
        ),
      );
    for (const item of event.context)
      content.append(
        el(
          "div",
          { class: "observation context" },
          el("small", {}, item.code),
          item.detail,
          ...(item.email_ids || []).map((i) =>
            button(
              `Source ${short(i)}`,
              () => showEmail(i, () => showEvent(id, run)),
              "text-button",
            ),
          ),
        ),
      );
    content.append(
      disclose(
        "Recorded rule parameters",
        JSON.stringify(event.parameters, null, 2),
      ),
    );
    if (event.direction)
      content.append(
        disclose(
          "Header-indicated reply direction",
          JSON.stringify(event.direction, null, 2),
        ),
      );
    if (!$("detail-dialog").open) $("detail-dialog").showModal();
    $("detail-dialog").scrollTop = 0;
  } catch (error) {
    notify(error.message, "error");
  }
}

async function renderIntegrity(data, serial) {
  const diagnostics = await api(
    `/api/diagnostics${state.run ? "?run=" + state.run : ""}`,
  );
  if (serial !== state.serial) return;
  $("result-count").textContent = data.ok
    ? "Verification passed"
    : "Review required";
  const box = el(
    "div",
    { class: "integrity" },
    pill(
      data.ok ? "good" : "warning",
      data.ok ? "CONSISTENT" : "MISMATCH DETECTED",
    ),
    el(
      "h3",
      {},
      data.ok ? "Evidence checks passed" : "Case integrity needs attention",
    ),
    el("p", {}, data.scope),
    detailList({
      "Audit head": el("span", { class: "mono" }, data.audit_head),
      Checks:
        "Source hashes, parsed records, artifact index, analysis hashes and audit chain.",
    }),
    el(
      "p",
      {},
      "Retain the exported audit head separately. Internal consistency is not a digital signature or independent proof of custody.",
    ),
    button("Verify again", loadView),
  );
  for (const issue of data.errors)
    box.append(el("div", { class: "observation context" }, issue));
  box.append(el("h3", {}, "Unresolved relationships"));
  if (!diagnostics.length)
    box.append(
      el(
        "p",
        {},
        state.summary.latest_run
          ? "No unresolved parent identifiers in this run."
          : "Run analysis to review relationship diagnostics.",
      ),
    );
  for (const item of diagnostics)
    box.append(
      el(
        "div",
        { class: "observation context" },
        el("small", {}, item.code),
        item.detail,
        item.target ? el("p", { class: "mono" }, item.target) : null,
        button(
          `Inspect ${short(item.email_id)}`,
          () => showEmail(item.email_id),
          "text-button",
        ),
      ),
    );
  $("content").replaceChildren(box);
}

function renderGraph(data) {
  $("result-count").textContent =
    `${data.shown_events} of ${data.total_events} relationships`;
  if (!data.nodes.length) {
    $("content").replaceChildren(
      empty(
        "No connections to display",
        data.total_events
          ? "Matching groups exceed the 180-node interactive view limit. Inspect the timeline to see full group membership."
          : "Run analysis or adjust the filters to explore related evidence.",
      ),
    );
    return;
  }
  const ns = "http://www.w3.org/2000/svg";
  const svgEl = (tag, attrs = {}) => {
    const node = document.createElementNS(ns, tag);
    for (const [key, value] of Object.entries(attrs))
      node.setAttribute(key, value);
    return node;
  };
  const svg = svgEl("svg", {
    viewBox: "0 0 1100 560",
    role: "group",
    "aria-label":
      "Interactive evidence relationship graph. Tab to a node and press Enter to inspect it.",
  });
  const definitions = svgEl("defs");
  const marker = svgEl("marker", {
    id: "arrow",
    viewBox: "0 0 10 10",
    refX: "22",
    refY: "5",
    markerWidth: "5",
    markerHeight: "5",
    orient: "auto-start-reverse",
  });
  marker.append(svgEl("path", { d: "M 0 0 L 10 5 L 0 10 z", fill: "#8aa1b8" }));
  definitions.append(marker);
  svg.append(definitions);
  const layer = svgEl("g");
  svg.append(layer);
  const nodes = data.nodes.map((n, i) => ({
    ...n,
    x: 550 + Math.cos((i * 2 * Math.PI) / data.nodes.length) * 220,
    y: 280 + Math.sin((i * 2 * Math.PI) / data.nodes.length) * 180,
  }));
  const indexed = new Map(nodes.map((n) => [n.id, n]));
  for (let step = 0; step < 220; step++) {
    const forces = new Map(
      nodes.map((n) => [
        n.id,
        { x: (550 - n.x) * 0.02, y: (280 - n.y) * 0.02 },
      ]),
    );
    for (let i = 0; i < nodes.length; i++)
      for (let j = i + 1; j < nodes.length; j++) {
        const a = nodes[i],
          b = nodes[j],
          dx = a.x - b.x,
          dy = a.y - b.y;
        const distance = Math.max(25, dx * dx + dy * dy),
          force = 350 / distance;
        forces.get(a.id).x += dx * force;
        forces.get(a.id).y += dy * force;
        forces.get(b.id).x -= dx * force;
        forces.get(b.id).y -= dy * force;
      }
    for (const link of data.links) {
      const a = indexed.get(link.source),
        b = indexed.get(link.target),
        dx = b.x - a.x,
        dy = b.y - a.y;
      const length = Math.max(1, Math.hypot(dx, dy)),
        spring = (length - 105) * 0.06;
      forces.get(a.id).x += (dx / length) * spring;
      forces.get(a.id).y += (dy / length) * spring;
      forces.get(b.id).x -= (dx / length) * spring;
      forces.get(b.id).y -= (dy / length) * spring;
    }
    for (const node of nodes) {
      const force = forces.get(node.id);
      const cooling = 10 * (1 - step / 220) + 0.3;
      node.x += Math.max(-cooling, Math.min(cooling, force.x));
      node.y += Math.max(-cooling, Math.min(cooling, force.y));
    }
  }
  const xs = nodes.map((n) => n.x),
    ys = nodes.map((n) => n.y);
  const minX = Math.min(...xs),
    maxX = Math.max(...xs),
    minY = Math.min(...ys),
    maxY = Math.max(...ys);
  const fit = Math.min(
    900 / Math.max(1, maxX - minX),
    410 / Math.max(1, maxY - minY),
    1.4,
  );
  for (const node of nodes) {
    node.x = 550 + (node.x - (minX + maxX) / 2) * fit;
    node.y = 280 + (node.y - (minY + maxY) / 2) * fit;
  }
  const lineNodes = data.links.map((link) => {
    const line = svgEl("line", {
      class: "graph-link",
      ...(link.directed ? { "marker-end": "url(#arrow)" } : {}),
    });
    layer.append(line);
    return { link, line };
  });
  let dragged = false;
  for (const node of nodes) {
    const group = svgEl("g", {
      class: `graph-node ${node.type || ""}`,
      tabindex: "0",
      role: "button",
      "aria-label": node.label,
    });
    const shape =
      node.kind === "email"
        ? svgEl("circle", { r: "13" })
        : svgEl("rect", {
            x: "-10",
            y: "-10",
            width: "20",
            height: "20",
            rx: "3",
            transform: "rotate(45)",
          });
    const title = svgEl("title");
    title.textContent = `${node.label}\n${node.id}`;
    const graphLabels = {
      attachment_reuse: "Attachment",
      url_reuse: "URL",
      reply: "Reply",
      possible_coordination: "Coordination",
    };
    const text = svgEl("text", { y: "31", "text-anchor": "middle" });
    text.textContent =
      node.kind === "event"
        ? graphLabels[node.type]
        : node.id.slice(0, 10);
    group.append(title, shape, text);
    layer.append(group);
    node.element = group;
    const inspect = () =>
      node.kind === "email"
        ? showEmail(node.id)
        : showEvent(node.id, data.run_id);
    group.addEventListener("click", () => {
      if (!dragged) inspect();
    });
    group.addEventListener("keydown", (event) => {
      if (["Enter", " "].includes(event.key)) {
        event.preventDefault();
        inspect();
      }
    });
  }
  let zoom = 1,
    panX = 0,
    panY = 0,
    dragging = null;
  function draw() {
    layer.setAttribute(
      "transform",
      `translate(${panX} ${panY}) scale(${zoom})`,
    );
    for (const node of nodes)
      node.element.setAttribute("transform", `translate(${node.x} ${node.y})`);
    for (const { link, line } of lineNodes) {
      const a = indexed.get(link.source),
        b = indexed.get(link.target);
      for (const [attr, value] of Object.entries({
        x1: a.x,
        y1: a.y,
        x2: b.x,
        y2: b.y,
      }))
        line.setAttribute(attr, value);
    }
  }
  function point(event) {
    const p = svg.createSVGPoint();
    p.x = event.clientX;
    p.y = event.clientY;
    return p.matrixTransform(svg.getScreenCTM().inverse());
  }
  svg.addEventListener("pointerdown", (event) => {
    const p = point(event),
      group = event.target.closest(".graph-node");
    const node = group ? nodes.find((n) => n.element === group) : null;
    dragging = { x: p.x, y: p.y, node };
    dragged = false;
    if (!node) svg.setPointerCapture(event.pointerId);
  });
  svg.addEventListener("pointermove", (event) => {
    if (!dragging) return;
    const p = point(event),
      dx = p.x - dragging.x,
      dy = p.y - dragging.y;
    if (Math.abs(dx) + Math.abs(dy) > 1) dragged = true;
    if (dragging.node) {
      dragging.node.x += dx / zoom;
      dragging.node.y += dy / zoom;
    } else {
      panX += dx;
      panY += dy;
    }
    dragging.x = p.x;
    dragging.y = p.y;
    draw();
  });
  svg.addEventListener("pointerup", () => {
    dragging = null;
  });
  svg.addEventListener("pointercancel", () => {
    dragging = null;
  });
  const scale = (factor) => {
    const next = Math.min(3, Math.max(0.35, zoom * factor));
    panX = 550 - ((550 - panX) * next) / zoom;
    panY = 280 - ((280 - panY) * next) / zoom;
    zoom = next;
    draw();
  };
  svg.addEventListener(
    "wheel",
    (event) => {
      event.preventDefault();
      scale(event.deltaY < 0 ? 1.1 : 0.9);
    },
    { passive: false },
  );
  const tools = el(
    "div",
    { class: "graph-tools" },
    el(
      "div",
      { class: "graph-legend" },
      Object.keys(labels).map((type) => pill(type)),
    ),
    el(
      "div",
      {},
      button("+", () => scale(1.2)),
      button("-", () => scale(0.8)),
      button("Reset view", () => {
        zoom = 1;
        panX = 0;
        panY = 0;
        draw();
      }),
    ),
  );
  $("content").replaceChildren(
    tools,
    el(
      "p",
      { class: "graph-note" },
      `${data.truncated ? "This view is limited to 180 nodes; use the timeline for complete results. " : ""}Circles are messages; diamonds are relationships. Arrows indicate header-linked replies. Drag to pan or move nodes; scroll to zoom. Select a node to inspect it.`,
    ),
    el("div", { class: "graph-surface" }, svg),
  );
  draw();
}

document.querySelectorAll(".nav-item").forEach((node) =>
  node.addEventListener("click", () => {
    state.view = node.dataset.view;
    state.offset = 0;
    document.querySelectorAll(".nav-item").forEach((n) => {
      n.classList.toggle("active", n === node);
      if (n === node) n.setAttribute("aria-current", "page");
      else n.removeAttribute("aria-current");
    });
    loadView();
  }),
);
document
  .querySelectorAll(".close-dialog")
  .forEach((node) =>
    node.addEventListener("click", () => node.closest("dialog").close()),
  );
$("import-open").addEventListener("click", () =>
  $("import-dialog").showModal(),
);
$("analyze-open").addEventListener("click", () =>
  $("analysis-dialog").showModal(),
);
$("filters").addEventListener("submit", (event) => {
  event.preventDefault();
  state.offset = 0;
  state.run = $("run-select").value;
  loadView();
});
$("clear-filters").addEventListener("click", () => {
  $("filters").reset();
  state.offset = 0;
  state.run = "";
  loadView();
});
$("previous-page").addEventListener("click", () => {
  state.offset = Math.max(0, state.offset - state.limit);
  loadView();
});
$("next-page").addEventListener("click", () => {
  state.offset += state.limit;
  loadView();
});

$("import-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  const files = [...$("evidence-files").files];
  if (
    files.length > 100 ||
    files.some((f) => f.size > 25 * 1024 * 1024) ||
    files.reduce((s, f) => s + f.size, 0) > 99 * 1024 * 1024
  ) {
    $("import-result").textContent =
      "Reduce this batch to at most 100 files, 25 MiB each and under 99 MiB total.";
    return;
  }
  const submit = event.submitter;
  submit.disabled = true;
  $("import-result").textContent = "Acquiring and parsing evidence...";
  const data = new FormData();
  files.forEach((file) => data.append("files", file));
  try {
    const result = await api("/api/ingest", { method: "POST", body: data });
    const fresh = result.ingested.filter((r) => r.new_evidence).length;
    const message = `${fresh} new messages acquired; ${result.ingested.length - fresh} duplicate sources recognized; ${result.errors.length} files rejected.`;
    $("import-result").textContent =
      message + result.errors.map((e) => `\n${e.name}: ${e.error}`).join("");
    if (!result.errors.length) {
      $("import-dialog").close();
      $("import-form").reset();
    }
    notify(message, result.errors.length ? "error" : "success");
    await refresh();
  } catch (error) {
    $("import-result").textContent = error.message;
  } finally {
    submit.disabled = false;
  }
});

$("analysis-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  const submit = event.submitter;
  submit.disabled = true;
  $("analysis-result").textContent =
    "Verifying evidence and evaluating correlation rules...";
  try {
    const result = await api("/api/analyze", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        window_seconds: Number($("window-seconds").value),
        minimum_signals: Number($("minimum-signals").value),
        timestamp_source: $("timestamp-source").value,
      }),
    });
    state.run = "";
    state.offset = 0;
    $("analysis-dialog").close();
    notify(
      `Analysis saved: ${result.statistics.events} relationships across ${result.statistics.messages} messages. ${result.diagnostics.length} unresolved header relationships.`,
      "success",
    );
    $("analysis-result").textContent = "";
    await refresh();
  } catch (error) {
    $("analysis-result").textContent = error.message;
  } finally {
    submit.disabled = false;
  }
});

refresh().catch((error) => notify(error.message, "error"));
