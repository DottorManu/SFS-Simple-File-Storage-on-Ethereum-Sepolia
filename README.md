# 🧬 SFS — Simple File Storage on Ethereum (Sepolia)

Minimal, encrypted, chunk-based file storage directly on Ethereum testnet.  
No backend. No database. No login. Just blockchain.

---

## ⚡ What is this?

SFS is a CLI tool that lets you:

- 📦 Upload files to Ethereum (Sepolia) as transaction data
- 🔐 Encrypt everything (end-to-end, chunk-level)
- 🔄 Resume interrupted uploads safely
- 📚 Maintain an on-chain catalog of files
- 🔍 Browse and reconstruct files interactively

All with **minimal local state**.

---

## 🧠 Philosophy

- No servers  
- No accounts  
- No dependencies on external services  
- Minimal local files  
- Blockchain = source of truth  

---

## 🏗️ Architecture Overview

### 📦 Manifest
Each file is:
- chunked
- encrypted per chunk
- uploaded as multiple transactions

A **manifest** stores:
- chunk references
- encryption metadata
- file metadata

---

### 📚 Catalog
Files are indexed using an **append-only on-chain catalog**:

ROOT (latest)
 ↓
file_n
 ↓
file_n-1
 ↓
...

Each entry links to:
- file name
- manifest tx hash
- previous catalog entry

---

### 📄 Local State

Only two files are used:

wallet_sepolia.key.txt   # private key  
sfs_root.txt             # current catalog root  

No hidden files. No JSON clutter.

---

## 🔐 Encryption

- ECIES (secp256k1) for key exchange
- HKDF-SHA256 for key derivation
- AES-256-GCM per chunk

✔ Authenticated  
✔ Streaming-friendly  
✔ Secure  

---

## 🚀 Features

- ✅ Chunk-based upload (optimized size)
- ✅ Per-chunk encryption
- ✅ Resume after crash or interruption
- ✅ Interactive catalog browser
- ✅ Search files by name
- ✅ Reconstruct files from blockchain
- ✅ Minimal local footprint

---

## 📦 Installation

pip install web3 eth-account cryptography coincurve qrcode requests

---

## 🔑 Wallet

python script.py wallet

---

## 📤 Upload a file

python script.py upload file.bin

---

## 📚 Browse catalog

python script.py catalog

Search:

python script.py catalog --search mp3

---

## 🔍 Inspect file

python script.py inspect

---

## 📥 Reconstruct file

python script.py reconstruct

---

## 💸 Sweep funds

python script.py sweep 0xDEST_ADDRESS

---

## ⚠️ Notes

- Uses Ethereum Sepolia testnet
- Large files = many transactions
- RPC rate limits may apply

---

## 🧪 Limitations

- No directories (yet)
- Linear catalog scan
- No deduplication (yet)

---

## 🤯 Why?

Because we can.

---

## 📜 License

MIT
