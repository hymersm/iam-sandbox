import express from "express";

const app = express();
app.use(express.json());

const OLLAMA_BASE_URL = process.env.OLLAMA_BASE_URL || "http://localhost:11434";
const MODEL = process.env.OLLAMA_MODEL || "gpt-oss:20b";

// Simple healthcheck
app.get("/health", async (_req, res) => {
  res.json({ ok: true, ollama: OLLAMA_BASE_URL, model: MODEL });
});

// Proxy chat -> Ollama /api/chat
app.post("/chat", async (req, res) => {
  const { messages, stream = false } = req.body ?? {};
  if (!Array.isArray(messages)) {
    return res.status(400).json({ error: "messages must be an array of {role, content}" });
  }

  const r = await fetch(`${OLLAMA_BASE_URL}/api/chat`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ model: MODEL, messages, stream })
  });

  if (!r.ok) {
    const text = await r.text();
    return res.status(502).send(text);
  }

  // Non-streaming response
  const data = await r.json();
  res.json(data);
});

app.post("/vector", async (req, res) => {
  const { prompt } = req.body ?? {};
  const r = await fetch(`${OLLAMA_BASE_URL}/api/embeddings`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ model: MODEL, prompt: prompt })
  });

  if (!r.ok) {
    const text = await r.text();
    return res.status(502).send(text);
  }

  // Non-streaming response
  const data = await r.json();
  res.json(data);

});

app.listen(3000, () => console.log("Listening on :3000"));
