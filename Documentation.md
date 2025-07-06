
# 🗳️ Secure EVM (Electronic Voting Machine)

> A cryptographically secure and tamper-proof E-Voting system using C++, SQLite, OpenSSL, and Merkle Tree.

![Platform](https://img.shields.io/badge/Platform-C++%20%7C%20Linux-blue)
![Security](https://img.shields.io/badge/Security-Cryptographic-green)
![Database](https://img.shields.io/badge/Database-SQLite-lightgrey)
![Concurrency](https://img.shields.io/badge/Multithreading-Enabled-purple)
![Status](https://img.shields.io/badge/Status-Active-brightgreen)

---

## 🧠 Overview

This project simulates a **secure electronic voting system** with:

- ✅ Cryptographic User Authentication (RSA + SHA-256)
- ✅ Secure Vote Casting with Digital Signatures
- ✅ Encrypted UID to ensure anonymity
- ✅ Tamper-Proof Merkle Tree storage
- ✅ Real-time Monitor Dashboard
- ✅ Tamper Simulation & Detection

---

## 🚀 Project Flow

```mermaid
    A[ User Registers] --> B[RSA Key Pair Generated]
    B --> C[ Private Key AES Encrypted]
    C --> D[Registration Request Sent to Server]

    D --> E[ Server Stores hashUID, hashPwd, publicKey]
    
    F[ Login] --> G[ UID & Password Hashed & Verified]
    G --> H{Has User Voted?}
    H -- Yes --> I[ Reject Voting]
    H -- No --> J[ Accept Voting]

    J --> K[Vote Casted (Hash + Signature)]
    K --> L[ Signature Verified]
    L --> M[ Vote Added to Merkle Tree]
    M --> N[Vote Stored in DB]
    N --> O[ Periodic Verification via Monitor]

    P[ User Requests Verification] --> Q[ Merkle Proof + Signature + Root Hash]
```

---

## 🔐 Features

<details>
  <summary><strong>📝 Registration</strong></summary>

- User provides UID & password
- RSA Key Pair is generated
- Public key is sent to the server
- Private key is AES encrypted and saved locally

</details>

<details>
  <summary><strong>🔐 Login</strong></summary>

- UID and password are hashed and verified
- User is allowed to vote if not already voted

</details>

<details>
  <summary><strong>🗳️ Vote Casting</strong></summary>

- Vote is hashed and signed using private key
- Server verifies signature using stored public key
- Vote is stored securely
- Merkle Tree updated with vote

</details>

<details>
  <summary><strong>🧩 Vote Verification</strong></summary>

- Client requests Merkle proof
- Server provides:
  - voteHash, leafHash, Merkle path
  - Signature and root hash
- Client verifies inclusion and signature

</details>

<details>
  <summary><strong>🔍 Tamper Simulation</strong></summary>

- `TAMPER_TEST` command modifies vote hash
- Verifier detects change in Merkle root or invalid proof

</details>

<details>
  <summary><strong>📊 Real-time Monitoring</strong></summary>

- `monitor.cpp` refreshes every 15 sec
- Displays:
  - All registered users
  - All votes and distribution
  - % votes per party

</details>

---

## 🧬 Merkle Tree Snapshot

Each vote creates a leaf hash:
```
leaf = SHA256(hashUID + voteHash)
```

The Merkle Tree maintains integrity and supports verification:
```text
               Root
              /    \
           Hash1   Hash2
           /  \     /  \
     Leaf1 Leaf2 Leaf3 Leaf4
```

📌 If a single leaf is tampered, the root will change — enabling tamper detection.

---

## 📁 Directory Structure

```
├── server/
│   └── server.cpp              # Main server logic
├── monitor/
│   └── monitor.cpp             # Realtime DB monitor
├── include/
│   ├── crypto.h                # Crypto-related functions
│   ├── merkle.h                # Merkle Tree class
├── keys/
│   └── *.key                   # Encrypted private keys
├── evote.db                    # SQLite DB
└── README.md
```

---

## ⚙️ Tech Stack

| Area             | Technology     |
|------------------|----------------|
| Language         | C++17          |
| Database         | SQLite3        |
| Crypto           | OpenSSL        |
| Data Format      | JSON (nlohmann)|
| Multithreading   | std::thread    |
| Security         | AES, RSA, SHA256|
| Tree Structure   | Merkle Tree    |
| Communication    | TCP Sockets    |

---

## 💻 Sample Commands

- Register:
  ```
  REGISTER <hashUID> <hashPWD> <publicKey PEM>
  ```
- Login:
  ```
  LOGIN <hashUID> <hashPWD>
  ```
- Cast Vote:
  ```
  CAST_VOTE <encUID> <voteHash> <hashUID> <signature>
  ```
- Verify Vote:
  ```
  VERIFY_VOTE <hashUID>
  ```

---

## 🧪 Tamper Testing

Run this to simulate an attack:
```
TAMPER_TEST <hashUID>
```

Then verify the vote:
```
VERIFY_VOTE <hashUID>
```
You'll observe a mismatch in Merkle root — proving tampering!

---

## 🧠 Future Enhancements

- 🔄 Blockchain-style append-only vote logging
- 🌐 Web UI for voting & monitoring
- 🧾 Voter receipts with QR-coded Merkle proofs
- 🔎 Role-based admin control

---

## 👨‍💻 Authors

- Dashrath Kumar
- Herambh Tapper
- Vivek linux

---

## 📜 License

MIT License

---

## 🎯 Screenshots or Demos

> Add terminal screenshots or demo video link here if available.
