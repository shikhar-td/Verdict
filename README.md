# 🛡️ Verdict — Explainable SOC Detection Platform

🚀 **Live Demo:** https://your-app-name.streamlit.app

---

## 📌 Overview

Verdict is an **Explainable Security Operations Center (SOC) Detection Platform** designed to analyze system logs using a hybrid detection approach.

Unlike traditional tools that rely only on static rules, Verdict combines:

* 🔴 Rule-based detection (known threats)
* 🟡 Heuristic analysis (suspicious behaviors)
* 🔵 Machine Learning (Isolation Forest) for anomaly detection

It provides **clear explanations for every alert**, enabling faster and more reliable security investigations.

---

## 🔥 Key Features

* 📂 **Flexible Log Ingestion**

  * Upload any CSV logs
  * Dynamic column mapping (no fixed schema required)

* 🧠 **Hybrid Detection Engine**

  * Rules + Heuristics + ML anomaly detection

* 🎚️ **Adjustable ML Sensitivity**

  * Control anomaly detection threshold in real time

* 📊 **Explainable Alerts**

  * Reasons + MITRE mapping + confidence score

* 🕒 **Attack Story Correlation**

  * Groups events into attack timelines

* 🔐 **Production-Ready Safeguards**

  * File size limits
  * Row limits
  * Safe parsing & error handling

---

## 🧠 How It Works

```text
User Logs
   ↓
Column Mapping Layer
   ↓
Normalized Data
   ↓
Detection Engine
   ├── Rules
   ├── Heuristics
   └── ML (Isolation Forest)
   ↓
Explainability Layer
   ↓
Dashboard (Streamlit)
```

---

## 📸 Screenshots

> Add your screenshots here (VERY IMPORTANT)

* Alerts Dashboard
* ML Anomaly Score
* Attack Story Timeline
* Column Mapping UI

---

## ⚙️ Installation (Local Setup)

```bash
git clone https://github.com/shikhar-td/Verdict.git
cd Verdict

pip install -r requirements.txt
```

---

## ▶️ Run Locally

```bash
python main.py
streamlit run dashboard/app.py
```

---

## 📂 Project Structure

```text
Verdict/
├── dashboard/        # Streamlit UI
├── engine/           # Detection + correlation logic
├── detection/        # Rule definitions
├── output/           # Alert formatting
├── data/             # Sample logs
├── main.py           # Pipeline runner
├── requirements.txt
```

---

## 🧪 Detection Approach

| Layer                 | Purpose                       |
| --------------------- | ----------------------------- |
| Rules                 | Known attack patterns         |
| Heuristics            | Suspicious behavior detection |
| ML (Isolation Forest) | Unknown anomaly detection     |

---

## 🎯 Use Cases

* SOC Analyst training
* Threat detection simulation
* Log analysis automation
* Cybersecurity learning projects

---

## ⚠️ Limitations

* Works on CSV-based logs (no live ingestion yet)
* ML model is lightweight (not trained on enterprise datasets)

---

## 🚀 Future Improvements

* 📊 SOC analytics dashboard (charts & trends)
* 🔐 User authentication
* ☁️ Cloud log integration (SIEM-like ingestion)
* 📈 Advanced ML models

---

## 👨‍💻 Author

**Shikhar Singh**

---

## ⭐ If you found this useful, give it a star!
