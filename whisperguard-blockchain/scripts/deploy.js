async function main() {

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