const fs = require("fs")

async function main() {

 const oracleAddress = "0xe7f1725E7734CE288F8367e1Bb143E90bb3F0512"

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

 console.log("CID reputation submitted to blockchain")

}

main().catch((error) => {
 console.error(error)
 process.exitCode = 1
})