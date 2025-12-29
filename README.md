# Process-Inspector_EDR_Tool

# CYBER-PULSE | SIMPLE EDR Tool

# It Will Upgrade In Future This The DEMO and Experiment version

**SIMPLE_EDR_TOOL** is a cross-platform Endpoint Detection and Response (EDR) tool for **Windows** and **macOS**.
It provides **real-time process monitoring**, **memory scanning**, and **process dump with SHA256 hash** analysis. Built with `CustomTkinter` and `psutil` for a modern and responsive interface.

> ⚠️ **Note:** This is a **DEMO and Experimental version**. The code will be updated in future releases with more features and improvements.

---

## 📖 About

SIMPLE_EDR_TOOL is designed for cybersecurity professionals and enthusiasts to monitor and analyze running processes on their system.
It provides real-time CPU, RAM, and network metrics, memory scanning for suspicious strings, and the ability to dump and hash executables for further analysis.

---

## 🌟 Features

* **SIMPLE_EDR_TOOL:** Works on Windows and macOS
* **Live Metrics:** CPU, RAM, and Network usage displayed as text
* **Memory Scan:** Scan executable memory for suspicious strings
* **Dump & Hash:** Generate SHA256 hash of target executables
* **Zombie Handling:** Safely monitors terminated or zombie processes
* **Thread-safe Logging:** Logs events in real-time
* **Modern UI:** Clean GUI using CustomTkinter

---

## 📝 Requirements

* Python 3.10 or higher
* Libraries:

  * `psutil`
  * `customtkinter`
  * `tkinter` (built-in)

---

## 📦 Installation

1. **Clone the repository**

```bash
https://github.com/TerminatorNox/Process-Inspector_EDR_Tool.git
cd cyber-pulse-edr
```

2. **Install dependencies**

```bash
python3 -m pip install --upgrade pip
python3 -m pip install psutil customtkinter
```

> Note: `tkinter` is included with Python on both Windows and macOS.

---

## ⚙️ Usage

1. **Run the tool**

```bash
python3 Simple_EDR_Tool.py
```

2. **Select Platform**

* Choose **Windows** or **macOS** at startup.

3. **Load target executable**

* Click **Browse** to select the executable you want to monitor.

4. **Start Monitoring**

* Click **Start** to view live CPU, RAM, and Network metrics.

5. **Memory Scan**

* Click **Scan Memory** to check the executable for suspicious strings.

6. **Dump & Hash**

* Click **Dump & Hash** to generate the SHA256 hash of the executable.

---

## 🙏 Thank You

Thank you for using **SIMPLE EDR TOOL**!
If you find this tool helpful, please **star the repository** and consider contributing to its development.
