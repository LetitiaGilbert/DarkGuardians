console.log("WhisperGuard popup opened")

const REFRESH_MS = 2500
let intervalId = null

function detectCID(url){
 const match = String(url || "").match(/ipfs\/([a-zA-Z0-9]+)/)
 return match ? match[1] : null
}

function setText(id, value){
 const node = document.getElementById(id)
 if(node){
  node.textContent = value
 }
}

function friendlyStage(stage){
 switch((stage || "").toLowerCase()){
  case "queued": return "Queued"
  case "scanning": return "AI model checking"
  case "ai_decision": return "AI decision done"
  case "proof": return "Generating ZK proof"
  case "mapping": return "Updating hash map"
  case "submitting": return "Storing on blockchain"
  case "completed": return "Completed"
  case "failed": return "Failed"
  default: return "Idle"
 }
}

async function getSnapshot(url){
 return new Promise((resolve) => {
  chrome.runtime.sendMessage({ type: "activeTabSnapshot", url }, (resp) => {
   resolve(resp || null)
  })
 })
}

async function refresh(){
 const tabs = await chrome.tabs.query({ active: true, currentWindow: true })
 const tab = tabs && tabs[0] ? tabs[0] : null
 const url = tab && tab.url ? tab.url : ""
 const cid = detectCID(url)

 if(!cid){
  setText("cid", "No IPFS CID in this tab")
  setText("verdict", "N/A")
  setText("score", "")
  setText("pipeline", "Idle")
  setText("hint", "Open an ipfs.io/ipfs/<cid> page")
  return
 }

 const snapshot = await getSnapshot(url)
 if(!snapshot || snapshot.ok === false){
  setText("cid", cid)
  setText("verdict", "Unable to fetch status")
  setText("score", "")
  setText("pipeline", "Unavailable")
  setText("hint", "Check extension background logs")
  return
 }

 const verdict = snapshot.verdict || {}
 const pipeline = snapshot.pipeline

 setText("cid", cid)
 setText("verdict", (verdict.category || "pending").toUpperCase())
 setText("score", `score=${verdict.score || "0"} reports=${verdict.reports || "0"}`)

 if(pipeline){
  setText("pipeline", friendlyStage(pipeline.stage))
  setText("hint", pipeline.message || "")
 }else{
  setText("pipeline", "Idle")
  setText("hint", "Pipeline starts automatically for new CIDs in page view")
 }
}

document.addEventListener("DOMContentLoaded", async () => {
 await refresh()
 intervalId = setInterval(refresh, REFRESH_MS)
})

window.addEventListener("beforeunload", () => {
 if(intervalId){
  clearInterval(intervalId)
 }
})