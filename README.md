# 🧬 SFS — Simple File Storage on Ethereum (Sepolia)

Minimal, encrypted, chunk-based file storage directly on Ethereum testnet.  
No backend. No database. No login. Just blockchain.

---

## ⚡ What is this?

SFS is a CLI tool that lets you:

- 📦 Upload files to Ethereum (Sepolia) as transaction data
- 🔐 Encrypt everything (end-to-end, chunk-level)
- 🔑 Optionally encrypt the local wallet private key with a password
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

wallet_sepolia.key.txt   # local wallet private key, plaintext or encrypted  
sfs_root.txt             # current catalog root  

No hidden files. No database.

If wallet encryption is enabled, `wallet_sepolia.key.txt` is stored as a small encrypted keystore instead of raw private-key hex.

---

## 🔐 Encryption

### File encryption

Uploaded files are encrypted before being written on-chain:

- ECIES (secp256k1) for key exchange
- HKDF-SHA256 for key derivation
- AES-256-GCM per chunk

✔ Authenticated  
✔ Streaming-friendly  
✔ Secure  

### Wallet key encryption

The local wallet private key can optionally be protected with a password.

- Uses scrypt for password-based key derivation
- Uses AES-256-GCM for the encrypted wallet keystore
- Decrypts the private key only in RAM, at use time
- Keeps backward compatibility with plaintext `wallet_sepolia.key.txt`
- Leaving the password empty keeps the old plaintext behavior

If the wallet is encrypted, commands that need the private key will ask for the password.

For non-interactive usage, the password can also be provided with:

```bash
SFS_WALLET_PASSWORD="your-password" python script.py wallet
```

---

## 🚀 Features

- ✅ Chunk-based upload (optimized size)
- ✅ Per-chunk encryption
- ✅ Optional local wallet private-key encryption
- ✅ In-RAM wallet decryption at use time
- ✅ Add, change, or remove wallet password
- ✅ Resume after crash or interruption
- ✅ Interactive catalog browser
- ✅ Search files by name
- ✅ Reconstruct files from blockchain
- ✅ Minimal local footprint

---

## 📦 Installation

```bash
pip install web3 eth-account cryptography coincurve qrcode requests
```

---

## 🔑 Wallet

Show wallet, balance, public key and QR:

```bash
python script.py wallet
```

On first wallet creation, SFS asks for an optional wallet password:

```text
Password nuovo wallet (Invio = non cifrare):
```

Press Enter to keep the original plaintext behavior.

---

## 🔒 Change wallet password

Add or change the wallet password:

```bash
python script.py key-password
```

Remove wallet encryption and save the private key in plaintext again:

```bash
python script.py key-password --remove
```

If the wallet is already encrypted, the current password is required before changing or removing it.

⚠️ If you lose the wallet password, SFS cannot recover the encrypted private key.

---

## 📤 Upload a file

```bash
python script.py upload file.bin
```

---

## 📚 Browse catalog

```bash
python script.py catalog
```

Search:

```bash
python script.py catalog --search mp3
```

---

## 🔍 Inspect file

```bash
python script.py inspect
```

---

## 📥 Reconstruct file

```bash
python script.py reconstruct
```

---

## 💸 Sweep funds

```bash
python script.py sweep 0xDEST_ADDRESS
```

---

## ⚠️ Notes

- Uses Ethereum Sepolia testnet
- Large files = many transactions
- RPC rate limits may apply
- Wallet encryption protects the local key file, not the on-chain data
- File encryption remains unchanged and independent from wallet key encryption

---

## 🧪 Limitations

- No directories (yet)
- Linear catalog scan
- No deduplication (yet)
- Losing the encrypted wallet password means losing access to that local private key

---

## 🤯 Why?

Because we can.

---

## 📜 License

MIT
