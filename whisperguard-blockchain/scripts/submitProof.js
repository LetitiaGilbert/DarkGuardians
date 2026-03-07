const fs = require("fs")

async function main() {

const oracleAddress = "0x65F0bfE000a715ED45caBE9858b0849C5f6873A7"

 const oracle = await ethers.getContractAt(
   "ReputationOracle",
   oracleAddress
 )

 const data = JSON.parse(
   fs.readFileSync("../circuits/proof_ljcr5jdq.json")
 )

 const cid = ethers.toBeHex(
   BigInt(data.cidHash),
   32
 )

 const nullifier = ethers.toBeHex(
   BigInt(data.nullifier),
   32
 )

 const score = data.scanResult === "1" ? 90 : 10

 const category = data.status.toLowerCase()

 const proofBytes = ethers.hexlify(
   ethers.toUtf8Bytes(JSON.stringify(data.proof))
 )

 const tx = await oracle.submitReport(
   cid,
   score,
   category,
   proofBytes,
   nullifier
 )

 await tx.wait()
console.log("CID HEX:", cid)
console.log("Score:", score)
console.log("Category:", category)
console.log("Proof Bytes:", proofBytes)
console.log("Nullifier:", nullifier)
console.log("CID reputation submitted to blockchain")

}

main().catch((error) => {
 console.error(error)
 process.exitCode = 1
})