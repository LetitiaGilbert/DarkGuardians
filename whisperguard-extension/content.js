console.log("WhisperGuard scanning page")

const STATUS_POLL_MS = 2500

function detectCID(url){
 const match = String(url || "").match(/ipfs\/([a-zA-Z0-9]+)/)
 return match ? match[1] : null
}

function mapStageToMessage(stage){
 switch((stage || "").toLowerCase()){
  case "queued":
   return "Queued for realtime verification..."
  case "scanning":
   return "AI model checking content..."
  case "ai_decision":
   return "AI decision ready. Continuing backend proof + storage..."
  case "proof":
   return "Generating zero-knowledge proof..."
  case "mapping":
   return "Updating CID hash mapping..."
  case "submitting":
   return "Storing result on blockchain..."
  case "completed":
   return "Backend processing complete."
  case "failed":
   return "Backend processing failed."
  default:
   return "Processing..."
 }
}

function createShield(message){
 const root = document.createElement("div")
 root.id = "whisperguard-shield"
 root.style.position = "fixed"
 root.style.inset = "0"
 root.style.zIndex = "2147483647"
 root.style.display = "flex"
 root.style.flexDirection = "column"
 root.style.gap = "12px"
 root.style.alignItems = "center"
 root.style.justifyContent = "center"
 root.style.padding = "24px"
 root.style.textAlign = "center"
 root.style.fontFamily = "Segoe UI, Arial, sans-serif"
 root.style.color = "#ffffff"
 root.style.background = "#0f172a"

 const title = document.createElement("h2")
 title.textContent = "WhisperGuard"
 title.style.margin = "0"

 const body = document.createElement("p")
 body.id = "wg-shield-body"
 body.textContent = message
 body.style.margin = "0"
 body.style.maxWidth = "780px"

 const hint = document.createElement("p")
 hint.id = "wg-shield-hint"
 hint.textContent = ""
 hint.style.margin = "0"
 hint.style.maxWidth = "780px"
 hint.style.opacity = "0.9"
 hint.style.fontSize = "13px"

 root.appendChild(title)
 root.appendChild(body)
 root.appendChild(hint)
 document.documentElement.appendChild(root)
 return root
}

function updateShield(shield, message, tone, hint){
 if(!shield){
  return
 }
 shield.style.background = tone === "danger" ? "#240808" : "#0f172a"
 const body = shield.querySelector("#wg-shield-body")
 const hintNode = shield.querySelector("#wg-shield-hint")
 if(body){
  body.textContent = message
 }
 if(hintNode){
  hintNode.textContent = hint || ""
 }
}

function removeShield(shield){
 if(shield && shield.parentNode){
  shield.parentNode.removeChild(shield)
 }
}

function createBackendBadge(){
 const badge = document.createElement("div")
 badge.id = "whisperguard-backend-badge"
 badge.style.position = "fixed"
 badge.style.bottom = "16px"
 badge.style.right = "16px"
 badge.style.zIndex = "2147483646"
 badge.style.maxWidth = "420px"
 badge.style.padding = "10px 12px"
 badge.style.borderRadius = "10px"
 badge.style.background = "#0b1020"
 badge.style.color = "#e5e7eb"
 badge.style.fontFamily = "Segoe UI, Arial, sans-serif"
 badge.style.fontSize = "12px"
 badge.style.lineHeight = "1.4"
 badge.style.boxShadow = "0 6px 20px rgba(0,0,0,0.30)"
 badge.style.border = "1px solid rgba(255,255,255,0.15)"
 badge.textContent = "WhisperGuard backend processing..."
 document.documentElement.appendChild(badge)
 return badge
}

function updateBadge(badge, status){
 if(!badge || !status){
  return
 }
 const stageMsg = mapStageToMessage(status.stage)
 const msg = status.message ? ` ${status.message}` : ""
 badge.textContent = `WhisperGuard: ${stageMsg}${msg}`

 if(status.status === "completed"){
  badge.style.background = "#0b3d2f"
  setTimeout(() => {
   if(badge.parentNode){
    badge.parentNode.removeChild(badge)
   }
  }, 6000)
 }

 if(status.status === "failed"){
  badge.style.background = "#4b1f1f"
 }
}

function sendMessage(payload){
 return new Promise((resolve) => {
  chrome.runtime.sendMessage(payload, (response) => {
   resolve(response || null)
  })
 })
}

async function pollPipelineUntilDone(cid, jobId, badge){
 while(true){
  const status = await sendMessage({ type: "pipelineStatus", cid, jobId })
  if(!status || status.found === false){
   if(badge){
    badge.textContent = "WhisperGuard: backend status unavailable"
   }
   return
  }

  updateBadge(badge, status)

  if(status.status === "completed" || status.status === "failed"){
   return
  }

  await new Promise((r) => setTimeout(r, STATUS_POLL_MS))
 }
}

async function waitForAiDecision(cid, jobId, shield){
 while(true){
  const status = await sendMessage({ type: "pipelineStatus", cid, jobId })
  if(!status || status.found === false){
   updateShield(shield, "Realtime backend unavailable.", "info", "Run local realtime pipeline server.")
   return { verdict: "pending" }
  }

  updateShield(shield, mapStageToMessage(status.stage), "info", status.message || "")

  if(status.aiResult){
   const aiCategory = status.aiResult.category || "safe"
   if(aiCategory === "malicious"){
    updateShield(shield, "Blocked by WhisperGuard: AI marked this CID malicious.", "danger", "Backend proof + blockchain continue in background.")
    window.stop()
    return { verdict: "malicious", status }
   }

   removeShield(shield)
   const badge = createBackendBadge()
   updateBadge(badge, status)
   pollPipelineUntilDone(cid, jobId, badge)
   return { verdict: "allowed", status }
  }

  if(status.status === "failed"){
   removeShield(shield)
   return { verdict: "pending", status }
  }

  await new Promise((r) => setTimeout(r, STATUS_POLL_MS))
 }
}

async function runCidFlow(cid){
 const shield = createShield("Checking CID reputation on-chain...")

 const onchain = await sendMessage({ type: "checkCID", cid })
 if(!onchain){
  updateShield(shield, "No response from extension backend.", "danger")
  return
 }

 if(onchain.category === "malicious"){
  updateShield(shield, "Blocked by WhisperGuard: CID is malicious on-chain.", "danger")
  window.stop()
  return
 }

 if(onchain.category === "suspicious"){
  removeShield(shield)
  alert("Caution: This IPFS content is suspicious. Proceed carefully.")
  return
 }

 if(onchain.category !== "pending"){
  removeShield(shield)
  return
 }

 const pipeline = onchain.pipeline || {}
 if(!pipeline.jobId){
  updateShield(shield, "Realtime pipeline unavailable.", "info", "Run: node whisperguard-blockchain/scripts/realtimePipelineServer.js")
  return
 }

 await waitForAiDecision(cid, pipeline.jobId, shield)
}

const cid = detectCID(window.location.href)
if(cid){
 console.log("CID detected:", cid)
 runCidFlow(cid)
}
