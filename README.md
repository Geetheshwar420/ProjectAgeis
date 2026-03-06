# Project Agis: Quantum-Resistant Secure Messaging

A high-performance, real-time messaging application designed with future-proof security at its core. Project Agis implements a **Hybrid Post-Quantum Cryptography (PQC)** stack to ensure that conversations remain private even against the threat of future quantum computers.

## 🚀 Key Features

- **Hybrid PQC Architecture**: Combines traditional security with **BB84** (Quantum Key Distribution), **Kyber** (KEM), and **Dilithium** (Digital Signatures).
- **End-to-End Encryption (E2EE)**: Messages are encrypted and decrypted strictly on the client side. The server never sees plaintext.
- **Real-Time Communication**: Built with **Flask-SocketIO** for instantaneous message delivery.
- **Modern Tech Stack**: React (Frontend), Flask (Backend), and **Firebase (Firestore & Storage)** for robust data persistence and file sharing.
- **Ephemeral Storage**: Messages and keys can be cleared instantly upon logout via IndexedDB integration.

## 🔒 Security Deep Dive (Hybrid Flow)

1.  **BB84 Entropy**: A deterministic shared secret is derived between peers to seed the exchange.
2.  **Kyber KEM**: Post-quantum key encapsulation is used to establish a secure shared secret.
3.  **Dilithium Signatures**: Every message is digitally signed by the sender and verified by the receiver to prevent tampering.
4.  **AES-256-GCM**: The final payload is encrypted using established symmetrical encryption standards with the quantum-derived key.

## ⚙️ Setup & Installation

### Backend (Flask + Firebase)
1.  Navigate to `/backend`.
2.  Install dependencies: `pip install -r requirements.txt`.
3.  Configure your credentials:
    - Copy `.env.example` to `.env`.
    - Place your Firebase Admin SDK JSON file in the `/backend` directory.
    - Update `FIREBASE_CREDENTIALS_PATH` in `.env`.
4.  Launch the server: `python app.py`.

### Frontend (React + Vite)
1.  Navigate to `/frontend`.
2.  Install dependencies: `npm install`.
3.  Configure API endpoint:
    - Copy `.env.example` to `.env`.
    - Ensure `VITE_API_URL` points to your running backend (default: `http://localhost:5000`).
4.  Start development server: `npm run dev`.

## 📁 Project Structure

```text
messaging_app_capstone/
├── backend/
│   ├── app.py              # Main Entry Point
│   ├── routes.py           # API Endpoints (Auth, Friends, Keys)
│   ├── firebase_db.py      # Firestore & Storage Logic
│   └── socket_events.py    # Real-time WebSocket Logic
├── frontend/
│   ├── components/         # UI Components (Modals, Sidebars, Chat)
│   ├── context/            # Auth & Socket State Management
│   ├── services/           # CryptoEngine, API, StorageService
│   └── types.ts            # Shared TypeScript Definitions
└── README.md
```

## ⚠️ Disclaimer
This project is an **Educational/Research demonstration** of quantum-resistant algorithms. While it implements advanced PQC concepts, it has not undergone a formal cryptographic audit for production-level banking or government deployments.

## 📝 License
Research Project - MIT License / Educational Use.
