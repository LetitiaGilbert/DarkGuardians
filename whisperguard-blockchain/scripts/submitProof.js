const fs = require("fs")
const path = require("path")

const oracleAddress = "0x0403556d47162c91346C5Da245C966df283C0444"

const proofDir = path.join(__dirname, "../../circuits")
const scanFile = path.join(__dirname, "../../scan_results.json")

const argv = process.argv.slice(2)
const envShouldSend = process.env.SEND === "1" || process.env.SEND === "true"
const shouldSend = argv.includes("--send") || envShouldSend
const maxArg = argv.find((arg) => arg.startsWith("--max="))
const envMax = process.env.MAX ? Number(process.env.MAX) : undefined
const maxSubmissions = maxArg ? Number(maxArg.split("=")[1]) : (envMax ?? (shouldSend ? 1 : 0))
const cidArg = argv.find((arg) => arg.startsWith("--cid="))
const envCid = process.env.CID ? String(process.env.CID).trim() : ""
const targetCid = cidArg ? cidArg.split("=")[1] : (envCid || null)

if (!Number.isFinite(maxSubmissions) || maxSubmissions < 0) {
 throw new Error("Invalid --max value. Use a non-negative number, e.g. --max=1")
}

async function main() {

 let oracle
 if (shouldSend) {
  const signer = await ethers.provider.getSigner()
  oracle = await ethers.getContractAt(
   "ReputationOracle",
   oracleAddress,
   signer
  )
 } else {
  oracle = await ethers.getContractAt(
   "ReputationOracle",
   oracleAddress,
   ethers.provider
  )
 }

 const scanResults = JSON.parse(
  fs.readFileSync(scanFile)
 )

 const proofFiles = fs.readdirSync(proofDir)
 let submittedCount = 0

 for (const file of proofFiles) {

  if (!file.startsWith("proof_")) continue
  if (submittedCount >= maxSubmissions) {
   console.log(`Reached max submissions (${maxSubmissions}). Stopping.`)
   break
  }

  const proofData = JSON.parse(
   fs.readFileSync(path.join(proofDir, file))
  )

  const cidHash = ethers.toBeHex(
   BigInt(proofData.cidHash),
   32
  )

  const nullifier = ethers.toBeHex(
   BigInt(proofData.nullifier),
   32
  )

  const cid = proofData.cid
  if (targetCid && cid !== targetCid) {
   continue
  }

  const scan = scanResults.find(r => r.cid === cid)

  if (!scan) {
   console.log("No ML result for:", cid)
   continue
  }

  const score = Math.floor(parseFloat(scan.threat_confidence))

  const category =
   scan.status === "MALICIOUS"
    ? "malicious"
    : "safe"

  const proofBytes = ethers.hexlify(
   ethers.toUtf8Bytes(JSON.stringify(proofData.proof))
  )

  const rep = await oracle.getReputation(cidHash)

  if (rep[1] > 0) {
   console.log("Already submitted:", cid)
   continue
  }

  console.log("Prepared CID:", cid)
  console.log("Score:", score)
  console.log("Category:", category)
  console.log("Nullifier:", nullifier)

  if (!shouldSend) {
   console.log("Dry run mode: skipping tx (use --send to submit)")
   continue
  }

  console.log("Submitting CID:", cid)

  const tx = await oracle.submitReport(
   cidHash,
   score,
   category,
   proofBytes,
   nullifier
  )

  await tx.wait()
  submittedCount += 1

  console.log("CID HEX:", cid)
  console.log("Score:", score)
  console.log("Category:", category)
  console.log("Proof Bytes:", proofBytes)
  console.log("Nullifier:", nullifier)
  console.log("CID reputation submitted to blockchain")

 }

 if (!shouldSend) {
  console.log("Finished dry run. No transactions were sent.")
 } else {
  console.log(`Finished submission run. Sent ${submittedCount} tx(s).`)
 }

}

main()
