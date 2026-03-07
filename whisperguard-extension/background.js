importScripts("ethers.min.js")

console.log("Background worker started")

const RPC_URL = "https://ethereum-sepolia.publicnode.com"
const PIPELINE_API = "http://127.0.0.1:8787"

const ORACLE_ADDRESSES = [
 "0x0403556d47162c91346C5Da245C966df283C0444",
 "0x65F0bfE000a715ED45caBE9858b0849C5f6873A7"
]

const CID_HASH_MAP_URL = chrome.runtime.getURL("cidHashes.json")
const ABI = ["function getReputation(bytes32 cidHash) view returns(uint256,uint256,string)"]

const provider = new ethers.JsonRpcProvider(RPC_URL)
const oracles = ORACLE_ADDRESSES.map((address) => ({
 address,
 client: new ethers.Contract(address, ABI, provider)
}))

let cidHashMap = {}
const pipelineJobsByCid = {}

async function loadCidHashMap(){
 try{
  const resp = await fetch(CID_HASH_MAP_URL, { cache: "no-store" })
  if(!resp.ok){
   throw new Error(`cidHashes.json not found (${resp.status})`)
  }
  const data = await resp.json()
  if(typeof data === "object" && data !== null){
   cidHashMap = data
  }
 }catch(err){
  console.warn("Could not load cidHashes.json, using fallback hash only", err)
  cidHashMap = {}
 }
}

loadCidHashMap()

function cidToNumber(cid){
 const hex = Array.from(new TextEncoder().encode(cid))
  .map((b) => b.toString(16).padStart(2, "0"))
  .join("")
  .slice(0, 30)

 return BigInt("0x" + hex)
}

function normalizeCategory(score, category){
 const fromChain = (category || "").trim().toLowerCase()
 if(fromChain){
  return fromChain
 }
 if(score >= 80){
  return "malicious"
 }
 if(score >= 50){
  return "suspicious"
 }
 return "good"
}

function detectCID(url){
 const text = String(url || "")
 const match = text.match(/ipfs\/([a-zA-Z0-9]+)/)
 return match ? match[1] : null
}

async function computeCidHash(cid){
 const mapped = cidHashMap[cid]
 if(mapped){
  return ethers.toBeHex(BigInt(mapped), 32)
 }
 return ethers.toBeHex(cidToNumber(cid), 32)
}

async function getBestReputation(cidHash){
 let best = null

 for(const oracle of oracles){
  try{
   const rep = await oracle.client.getReputation(cidHash)
   const score = Number(rep[0])
   const reports = Number(rep[1])

   if(reports === 0){
    continue
   }

   const entry = {
    oracleAddress: oracle.address,
    score: rep[0].toString(),
    reports: rep[1].toString(),
    category: normalizeCategory(score, rep[2])
   }

   if(entry.category === "malicious"){
    return entry
   }

   if(!best || Number(entry.reports) > Number(best.reports)){
    best = entry
   }
  }catch(err){
   console.warn(`Oracle read failed for ${oracle.address}`, err)
  }
 }

 return best
}

async function startPipelineJob(cid){
 const res = await fetch(`${PIPELINE_API}/jobs`, {
  method: "POST",
  headers: { "content-type": "application/json" },
  body: JSON.stringify({ cid })
 })

 if(!res.ok){
  throw new Error(`Pipeline API failed (${res.status})`)
 }

 const payload = await res.json()
 if(payload && payload.jobId){
  pipelineJobsByCid[cid] = payload.jobId
 }

 return payload
}

async function getPipelineStatus(jobId){
 const res = await fetch(`${PIPELINE_API}/jobs/${jobId}`, {
  method: "GET",
  headers: { "content-type": "application/json" }
 })

 if(!res.ok){
  throw new Error(`Pipeline status failed (${res.status})`)
 }

 return res.json()
}

async function checkCidFlow(cid, startPipelineIfMissing){
 const cidHash = await computeCidHash(cid)
 const bestRep = await getBestReputation(cidHash)

 if(bestRep){
  return {
   found: true,
   cid,
   score: bestRep.score,
   reports: bestRep.reports,
   category: bestRep.category,
   oracleAddress: bestRep.oracleAddress
  }
 }

 let pipeline = null
 if(startPipelineIfMissing){
  try{
   pipeline = await startPipelineJob(cid)
  }catch(pipelineError){
   console.warn("Could not start realtime pipeline", pipelineError)
  }
 }

 return {
  found: false,
  cid,
  score: "0",
  reports: "0",
  category: "pending",
  pipeline
 }
}

chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
 if(request.type === "checkCID"){
  ;(async() => {
   try{
    sendResponse(await checkCidFlow(request.cid, true))
   }catch(e){
    console.error("checkCID error", e)
    sendResponse({ found: false, cid: request.cid, score: "0", reports: "0", category: "pending" })
   }
  })()
  return true
 }

 if(request.type === "peekCID"){
  ;(async() => {
   try{
    sendResponse(await checkCidFlow(request.cid, false))
   }catch(e){
    console.error("peekCID error", e)
    sendResponse({ found: false, cid: request.cid, score: "0", reports: "0", category: "pending" })
   }
  })()
  return true
 }

 if(request.type === "pipelineStatus"){
  ;(async() => {
   try{
    const jobId = request.jobId || pipelineJobsByCid[request.cid]
    if(!jobId){
     sendResponse({ found: false, status: "unknown", stage: "idle", message: "No job found" })
     return
    }
    const status = await getPipelineStatus(jobId)
    sendResponse({ found: true, ...status })
   }catch(e){
    console.error("pipelineStatus error", e)
    sendResponse({ found: false, status: "error", stage: "error", message: e.message || "status check failed" })
   }
  })()
  return true
 }

 if(request.type === "activeTabSnapshot"){
  ;(async() => {
   try{
    const cid = detectCID(request.url)
    if(!cid){
      sendResponse({ ok: true, cid: null, verdict: null, pipeline: null })
      return
    }

    const verdict = await checkCidFlow(cid, false)
    const jobId = pipelineJobsByCid[cid]
    let pipeline = null
    if(jobId){
      try{
        pipeline = await getPipelineStatus(jobId)
      }catch{
        pipeline = { status: "error", stage: "error", message: "pipeline status unavailable" }
      }
    }

    sendResponse({ ok: true, cid, verdict, pipeline })
   }catch(e){
    sendResponse({ ok: false, error: e.message || "snapshot failed" })
   }
  })()
  return true
 }
})
