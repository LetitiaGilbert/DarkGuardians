async function main() {

  const signers = await ethers.getSigners();
  if (!signers.length) {
    throw new Error("No signer configured for deployment. Set PRIVATE_KEY in terminal session only, e.g. $env:PRIVATE_KEY='<key>' (PowerShell), then run deploy again.");
  }

  const Verifier = await ethers.getContractFactory("ZKVerifier");
  const verifier = await Verifier.deploy();
  await verifier.waitForDeployment();

  console.log("Verifier deployed:", verifier.target);

  const Oracle = await ethers.getContractFactory("ReputationOracle");
  const oracle = await Oracle.deploy(verifier.target);
  await oracle.waitForDeployment();

  console.log("Oracle deployed:", oracle.target);
}

main().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});