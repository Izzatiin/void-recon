# 📡 Advanced Async Network Scanner & Banner Grabber

![Python Version](https://img.shields.io/badge/python-3.10%2B-blue?style=for-the-badge&logo=python)
![Security Focus](https://img.shields.io/badge/Security-Network%20Reconnaissance-red?style=for-the-badge&logo=shield)
![License](https://img.shields.io/badge/license-MIT-green?style=for-the-badge)

**Advanced Network Scanner** is a high-performance Python-based port scanning tool engineered for **Network Reconnaissance** and **Vulnerability Assessment**. Powered by high-speed **Asynchronous I/O (`asyncio`)**, it includes service detection and banner grabbing capabilities.

---

## ✨ Key Features

* ⚡ **High-Speed Asynchronous Scanning:** Built on Python's `asyncio` engine with configurable concurrency limits to scan thousands of ports in seconds.
* 🔍 **Banner Grabbing & Service Detection:** Identifies running service names and extracts active banner/header responses from open ports.
* 📊 **Rich Interactive Terminal UI:** Features real-time progress indicators and structured, color-coded audit reports.
* 📜 **System Logging:** Records all successful scan events systematically in a `scanner.log` file.
* 🎛️ **Flexible Port Parsing:** Supports single ports, comma-separated lists (`80,443`), and numerical ranges (`1-10000`).

---

## 🛠️ Prerequisites & Installation

Ensure you have **Python 3.10+** installed.

### 1. Clone this repository
git clone [https://github.com/Izzatiin/Python-network-port-scanner.git](https://github.com/Izzatiin/Python-network-port-scanner.git)
cd Python-network-port-scanner

### 2. Install Dependencies
pip install rich

---

## 📖 Usage Guide

### 1. Standard Scan (Default Ports 1-1024)
python network_scanner.py -t scanme.nmap.org

### 2. Custom Port Range Scan
python network_scanner.py -t 192.168.1.1 -p 1-10000

### 3. High-Concurrency Scan for Specific Ports
python network_scanner.py -t 10.10.10.1 -p 21,22,80,443,8080 -c 500

---

## 🖥️ Audit Report Example

| Port | Status | Service | Banner / Version |
| :---: | :---: | :---: | :--- |
| **22** | **OPEN** | `SSH` | `SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.5` |
| **80** | **OPEN** | `HTTP` | `HTTP/1.1 200 OK (Apache/2.4.41)` |
| **8080** | **OPEN** | `HTTP-ALT` | `HTTP/1.1 400 Bad Request` |

> 📌 **Log File:** All activity is automatically logged to `scanner.log`.

---

## 📝 License

Distributed under the MIT License. See `LICENSE` for more information.

---

*Developed by [Mohammad Nawfal Arfa](https://github.com/Izzatiin) — Cybersecurity & Python Enthusiast.*
