const http = require("http");

const moderationPort = 19090;
const upstreamPort = 19091;

function readBody(req) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    req.on("data", (chunk) => chunks.push(chunk));
    req.on("end", () => resolve(Buffer.concat(chunks).toString("utf8")));
    req.on("error", reject);
  });
}

function sendJSON(res, statusCode, payload) {
  const body = JSON.stringify(payload);
  res.writeHead(statusCode, {
    "Content-Type": "application/json",
    "Content-Length": Buffer.byteLength(body),
  });
  res.end(body);
}

function extractInputText(raw) {
  let body;
  try {
    body = JSON.parse(raw || "{}");
  } catch {
    return "";
  }
  if (typeof body.input === "string") {
    return body.input;
  }
  if (Array.isArray(body.input)) {
    return JSON.stringify(body.input);
  }
  return JSON.stringify(body.input || "");
}

function moderationDecision(inputText) {
  const text = String(inputText || "").toLowerCase();
  if (text.includes("child sexual abuse") || text.includes("[danger-csam]")) {
    return {
      flagged: true,
      categories: { "sexual/minors": true },
      category_scores: { "sexual/minors": 0.999 },
    };
  }
  if (text.includes("violent contraband") || text.includes("[danger-violent]")) {
    return {
      flagged: true,
      categories: { "illicit/violent": true },
      category_scores: { "illicit/violent": 0.996 },
    };
  }
  if (text.includes("hate speech") || text.includes("[observe-hate]")) {
    return {
      flagged: true,
      categories: { hate: true },
      category_scores: { hate: 0.881 },
    };
  }
  return {
    flagged: false,
    categories: {},
    category_scores: {},
  };
}

const moderationServer = http.createServer(async (req, res) => {
  if (req.method === "GET" && req.url === "/health") {
    return sendJSON(res, 200, { ok: true, service: "moderation" });
  }
  if (req.method !== "POST" || req.url !== "/v1/moderations") {
    return sendJSON(res, 404, { error: "not found" });
  }

  const raw = await readBody(req);
  const inputText = extractInputText(raw);
  const result = moderationDecision(inputText);
  sendJSON(res, 200, {
    id: "modr-local-test",
    model: "omni-moderation-latest",
    results: [result],
  });
});

const upstreamServer = http.createServer(async (req, res) => {
  if (req.method === "GET" && req.url === "/health") {
    return sendJSON(res, 200, { ok: true, service: "codex-upstream" });
  }
  if (req.method === "GET" && req.url === "/models") {
    return sendJSON(res, 200, {
      object: "list",
      data: [{ id: "gpt-5", object: "model" }],
    });
  }
  if (req.method !== "POST" || req.url !== "/responses") {
    return sendJSON(res, 404, { error: "not found" });
  }

  const raw = await readBody(req);
  let inputPreview = "ok";
  try {
    const body = JSON.parse(raw || "{}");
    if (typeof body.input === "string" && body.input.trim() !== "") {
      inputPreview = body.input.trim();
    } else if (Array.isArray(body.input) && body.input.length > 0) {
      inputPreview = JSON.stringify(body.input[0]);
    }
  } catch {
    inputPreview = "ok";
  }

  const payload = {
    type: "response.completed",
    response: {
      id: "resp_local_1",
      object: "response",
      created_at: Math.floor(Date.now() / 1000),
      status: "completed",
      model: "gpt-5",
      output: [
        {
          type: "message",
          id: "out_local_1",
          role: "assistant",
          content: [
            {
              type: "output_text",
              text: "mock upstream ok: " + inputPreview,
            },
          ],
        },
      ],
      usage: {
        input_tokens: 10,
        output_tokens: 5,
        total_tokens: 15,
      },
      error: null,
    },
  };

  res.writeHead(200, { "Content-Type": "text/event-stream" });
  res.end(`data: ${JSON.stringify(payload)}\n\n`);
});

function shutdown(signal) {
  console.log(`received ${signal}, shutting down mock servers`);
  moderationServer.close(() => {});
  upstreamServer.close(() => {});
  setTimeout(() => process.exit(0), 200);
}

process.on("SIGINT", () => shutdown("SIGINT"));
process.on("SIGTERM", () => shutdown("SIGTERM"));

moderationServer.listen(moderationPort, "127.0.0.1", () => {
  console.log(`mock moderation listening on http://127.0.0.1:${moderationPort}`);
});

upstreamServer.listen(upstreamPort, "127.0.0.1", () => {
  console.log(`mock codex upstream listening on http://127.0.0.1:${upstreamPort}`);
});
