# ZeroDay Threat Detection System

A cutting-edge, **Active Manual Vulnerability Scanner** featuring a sleek React dashboard and a powerful AI-driven FastAPI backend. 

The ZeroDay Threat Detection System is designed to intercept and analyze real-time threats. It intelligently detects if your input is a live website URL, a `package.json` manifest, or raw packet traffic, and immediately scans it for zero-day vulnerabilities, SQL injections, XSS attacks, and more using a sophisticated two-tier analysis engine.

---

## 🚀 Features

- **Seamless Auto-Detection**: Paste anything into the search bar. The system automatically detects whether to perform a live HTTP scrape, a package dependency analysis, or a raw payload regex scan.
- **Tier 1 Security Engine (Heuristics)**: Blazing-fast static signature matching to catch 90% of known threats (e.g., Log4Shell, Spring4Shell, standard SQLi).
- **Tier 2 AI Engine (Anomaly Detection)**: An Isolation Forest ML model kicks in for ambiguous payloads to catch evasive zero-day attacks that bypass standard regex.
- **Beautiful UI**: A highly responsive, glassmorphism-inspired React dashboard powered by Vite and Tailwind CSS.
- **Live Metrics**: Instant visualizations of your scanning statistics, detected threat types, and response times.

---

## 🛠️ Technology Stack

- **Frontend**: React 18, Vite, Tailwind CSS v4, Framer Motion, Lucide Icons, Recharts.
- **Backend**: FastAPI, Python 3.10+, HTTPX (for async active scanning).
- **Threat Engine**: Custom Heuristics + Scikit-Learn (Isolation Forest).

---

## ⚙️ Installation & Setup

### 1. Clone the repository
```bash
git clone https://github.com/yourusername/zeroday-threat-detection.git
cd zeroday-threat-detection
```

### 2. Backend Setup
The backend runs on Python and FastAPI.
```bash
# Install dependencies
pip install -r phase2/requirements.txt
pip install fastapi uvicorn httpx

# Start the server (runs on http://localhost:8000)
uvicorn main:app --reload
```

### 3. Frontend Setup
The frontend is powered by React and Vite.
```bash
# Open a new terminal and navigate to the Frontend directory
cd Frontend

# Install Node modules
npm install

# Start the development server
npm run dev
```

---

## 🎯 How to Use

1. Open the dashboard (usually `http://localhost:5173`).
2. Use the central search bar:
   - **Scan a Website:** Type `example.com` or `https://example.com`. The backend will actively fetch the live HTML and analyze the response headers and body.
   - **Scan a Package:** Upload your `package.json` file. The engine will check your dependencies against known vulnerable libraries.
   - **Scan a Payload:** Paste raw HTTP traffic or suspicious SQL queries to test the Tier 1 and Tier 2 engines directly.
3. View the generated alert cards and threat visualizations instantly on your screen!

---

## 📁 Architecture Overview
```text
ZeroDay-smart-proxy-main/
│
├── Frontend/               # React Dashboard (Vite)
│   ├── src/app/            # Main React components (InputScreen, ResultsScreen)
│   └── src/api/            # API integration layer
│
├── phase2/                 # The Threat Detection Engine
│   ├── rules.py            # Tier 1: Static signatures & heuristics
│   ├── tier2_inference.py  # Tier 2: Isolation Forest AI/ML Model
│   ├── alerts.json         # Threat detection logs (ignored in git)
│   └── statistics.json     # Live dashboard metrics (ignored in git)
│
└── main.py                 # Core FastAPI Application & Routing
```

---

*This project was built to demonstrate modern cybersecurity practices, full-stack integration, and the seamless application of AI in Threat Detection.*
