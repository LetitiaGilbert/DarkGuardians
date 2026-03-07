const http = require("http");
const { spawn } = require("child_process");
const path = require("path");

const HOST = "127.0.0.1";
const PORT = 8787;

const repoRoot = path.resolve(__dirname, "../..");
const circuitsDir = path.join(repoRoot, "circuits");
const blockchainDir = path.join(repoRoot, "whisperguard-blockchain");
const scanResultsPath = path.join(repoRoot, "scan_results.json");

const jobs = new Map();
const jobsByCid = new Map();

const NPX_BIN = process.platform === "win32" ? "npx.cmd" : "npx";

function nowIso() {
  return new Date().toISOString();
}

function createJob(cid) {
  const id = `${Date.now()}-${Math.random().toString(36).slice(2, 10)}`;
  const job = {
    jobId: id,
    cid,
    status: "queued",
    stage: "queued",
    message: "Job created",
    aiResult: null,
    logs: [],
    createdAt: nowIso(),
    updatedAt: nowIso(),
  };
  jobs.set(id, job);
  jobsByCid.set(cid, id);
  return job;
}

function readAiResultForCid(cid) {
  try {
    if (!require("fs").existsSync(scanResultsPath)) {
      return null;
    }
    const results = JSON.parse(require("fs").readFileSync(scanResultsPath, "utf-8"));
    const entry = Array.isArray(results) ? results.find((r) => r.cid === cid) : null;
    if (!entry) {
      return null;
    }

    const status = String(entry.status || "").toUpperCase();
    const confidence = Number.parseFloat(String(entry.threat_confidence || "0").replace("%", ""));
    const category = status === "MALICIOUS" ? "malicious" : "safe";
    return {
      status,
      category,
      confidence: Number.isFinite(confidence) ? confidence : 0,
      analysis: entry.analysis || "",
      engine: entry.engine || "",
    };
  } catch {
    return null;
  }
}

function setJobState(job, status, stage, message) {
  job.status = status;
  job.stage = stage;
  job.message = message;
  job.updatedAt = nowIso();
}

function appendLog(job, line) {
  job.logs.push(`[${nowIso()}] ${line}`);
  if (job.logs.length > 200) {
    job.logs.shift();
  }
  job.updatedAt = nowIso();
}

function runStep({ job, stage, message, command, args, cwd, extraEnv }) {
  return new Promise((resolve, reject) => {
    setJobState(job, "running", stage, message);

    const useShell = process.platform === "win32" && command.toLowerCase().endsWith(".cmd");

    const child = spawn(command, args, {
      cwd,
      env: { ...process.env, ...(extraEnv || {}) },
      shell: useShell,
    });

    child.stdout.on("data", (chunk) => {
      appendLog(job, chunk.toString().trim());
    });

    child.stderr.on("data", (chunk) => {
      appendLog(job, chunk.toString().trim());
    });

    child.on("error", (err) => {
      reject(err);
    });

    child.on("close", (code) => {
      if (code === 0) {
        resolve();
      } else {
        reject(new Error(`${command} exited with code ${code}`));
      }
    });
  });
}

async function runPipeline(job) {
  try {
    await runStep({
      job,
      stage: "scanning",
      message: "AI model checking content",
      command: "python",
      args: ["engine.py", `--cid=${job.cid}`],
      cwd: repoRoot,
      extraEnv: {
        PYTHONIOENCODING: "utf-8",
        PYTHONUTF8: "1",
      },
    });

    const aiResult = readAiResultForCid(job.cid);
    if (aiResult) {
      job.aiResult = aiResult;
      setJobState(job, "running", "ai_decision", `AI decision: ${aiResult.category}`);
    }

    await runStep({
      job,
      stage: "proof",
      message: "Generating zero-knowledge proof",
      command: "node",
      args: ["generate_proofs.js", "--once", `--cid=${job.cid}`],
      cwd: circuitsDir,
    });

    await runStep({
      job,
      stage: "mapping",
      message: "Updating CID hash mapping",
      command: "node",
      args: [path.join("scripts", "updateCidHashes.js")],
      cwd: repoRoot,
    });

    await runStep({
      job,
      stage: "submitting",
      message: "Storing result on blockchain",
      command: NPX_BIN,
      args: [
        "hardhat",
        "run",
        "scripts/submitProof.js",
        "--network",
        "sepolia",
      ],
      cwd: blockchainDir,
      extraEnv: {
        CID: job.cid,
        SEND: "1",
        MAX: "1",
        PYTHONIOENCODING: "utf-8",
        PYTHONUTF8: "1",
      },
    });

    setJobState(job, "completed", "completed", "Realtime verification finished");
  } catch (err) {
    appendLog(job, String(err && err.stack ? err.stack : err));
    setJobState(job, "failed", "failed", err.message || "Pipeline failed");
  }
}

function sendJson(res, statusCode, data) {
  res.writeHead(statusCode, {
    "content-type": "application/json",
    "cache-control": "no-store",
    "access-control-allow-origin": "*",
    "access-control-allow-methods": "GET,POST,OPTIONS",
    "access-control-allow-headers": "content-type",
  });
  res.end(JSON.stringify(data));
}

function readBody(req) {
  return new Promise((resolve, reject) => {
    let raw = "";
    req.on("data", (chunk) => {
      raw += chunk.toString();
      if (raw.length > 1024 * 64) {
        reject(new Error("Request too large"));
      }
    });
    req.on("end", () => {
      try {
        resolve(raw ? JSON.parse(raw) : {});
      } catch {
        reject(new Error("Invalid JSON body"));
      }
    });
    req.on("error", reject);
  });
}

const server = http.createServer(async (req, res) => {
  try {
    if (req.method === "OPTIONS") {
      sendJson(res, 200, { ok: true });
      return;
    }

    if (req.method === "GET" && req.url === "/health") {
      sendJson(res, 200, { ok: true, service: "realtime-pipeline", ts: nowIso() });
      return;
    }

    if (req.method === "POST" && req.url === "/jobs") {
      const body = await readBody(req);
      const cid = body && body.cid ? String(body.cid).trim() : "";
      if (!cid) {
        sendJson(res, 400, { error: "cid is required" });
        return;
      }

      const existingId = jobsByCid.get(cid);
      if (existingId) {
        const existing = jobs.get(existingId);
        if (existing && (existing.status === "running" || existing.status === "queued")) {
          sendJson(res, 200, existing);
          return;
        }
      }

      const job = createJob(cid);
      sendJson(res, 202, job);
      runPipeline(job);
      return;
    }

    if (req.method === "GET" && req.url.startsWith("/jobs/")) {
      const id = req.url.slice("/jobs/".length).trim();
      const job = jobs.get(id);
      if (!job) {
        sendJson(res, 404, { error: "job not found" });
        return;
      }
      sendJson(res, 200, job);
      return;
    }

    sendJson(res, 404, { error: "not found" });
  } catch (err) {
    sendJson(res, 500, { error: err.message || "internal error" });
  }
});

server.listen(PORT, HOST, () => {
  console.log(`Realtime pipeline server listening at http://${HOST}:${PORT}`);
});
