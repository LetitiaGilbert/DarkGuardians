const fs = require("fs")
const path = require("path")

const proofsDir = path.join(__dirname, "../circuits")
const extensionFile = path.join(
 __dirname,
 "../whisperguard-extension/cidHashes.json"
)

const files = fs.readdirSync(proofsDir)

const cidMap = {}

files.forEach(file => {

 if(file.startsWith("proof_") && file.endsWith(".json")){

  const proof = JSON.parse(
   fs.readFileSync(path.join(proofsDir,file))
  )

    if (proof && proof.cid && proof.cidHash) {
     cidMap[proof.cid] = proof.cidHash
    }

 }

})

fs.writeFileSync(
 extensionFile,
 JSON.stringify(cidMap,null,2)
)

console.log("✅ cidHashes.json updated")