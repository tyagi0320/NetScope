# 🌐 NetScope: Visualize & Analyze Your Network in Real-Time

A lightweight network data visualization tool that helps you:

- 📊 Visualize real-time network traffic across ports  
- 📈 Track bandwidth usage and live data transfer rates  
- 🧮 Monitor packet transmission and reception statistics  
- 🔍 Detect common protocols in use  
- 🚨 Set up alerts for unusual port activity  

---

## ⚙️ Getting Started

### 1. Install Dependencies

```bash
pip install -r requirements.txt
```

### 2. Run the Application

```bash
python app.py
```

### 3. Access the Dashboard

Open your browser and navigate to:

```
http://localhost:5000
```

---

## ⚠️ Prerequisites & Notes

- **Root/Administrator Privileges** are required to capture network packets.
- If you're on **Windows**, you must install [**Npcap**](https://npcap.com/) (a modern packet capture library).  
  > Without it, packet sniffing won’t work properly.  
- **Browser Developer Mode** may be needed to allow full access to all frontend features (especially if running as a local extension or with cross-origin data).
- The tool uses `scapy` under the hood for low-level packet inspection.

---

## ✅ You're all set!

Enjoy exploring your network traffic like never before with **NetScope** — because understanding your data shouldn't be boring.
