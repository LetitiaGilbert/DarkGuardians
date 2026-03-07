require("@nomicfoundation/hardhat-toolbox");

// Optional: load .env when present. Runtime env vars still override file values.
try {
  require("dotenv").config();
} catch (_) {
  // no-op
}

const sepoliaRpc = process.env.SEPOLIA_RPC || "https://ethereum-sepolia.publicnode.com";
const privateKey = process.env.PRIVATE_KEY;
const sepoliaAccounts = privateKey ? [privateKey] : [];

module.exports = {
  solidity: "0.8.24",
  networks: {
    sepolia: {
      url: sepoliaRpc,
      accounts: sepoliaAccounts
    }
  }
};