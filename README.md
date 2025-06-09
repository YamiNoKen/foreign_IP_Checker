# VirusTotal IP Reputation Checker
A PowerShell script to analyze active network connections, extract public IPs, and check their reputation using [VirusTotal](https://www.virustotal.com/) and [ipinfo.io](https://ipinfo.io).

## 🛠 Features

- Extracts foreign IPs from current TCP connections
- Filters out private/local IP ranges
- Uses `ipinfo.io` to retrieve ISP, region, and country info
- Uses `VirusTotal` API to analyze IP reputation
- Color-coded output:
  - ✅ Green for clean IPs
  - ❌ Red if IP has a negative reputation

---

## ⚙️ Prerequisites

- PowerShell (Windows)
- Internet access
- A free [VirusTotal API Key](https://www.virustotal.com/gui/join-us)

---

## 📦 Installation

1. Clone the repository:
   ```bash
   git clone https://github.com/YamiNoKen/vt-ip-checker.git
   cd vt-ip-checker
2. Open VT_ip_checker.ps1 in a text editor.
3. Paste your VirusTotal API key into the $apiKey variable.

## 🚀 Usage
Run the script from PowerShell:
.\VT_ip_checker.ps1

It will:

- Display each public IP found
- Show details from ipinfo.io
- Show detection counts and reputation score from VirusTotal

## 📄 License
 This project is licensed under the MIT License.
