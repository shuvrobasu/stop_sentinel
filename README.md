# <p align="center">STOP SENTINEL</p>

<p align="center">
  <img width="256" height="256" alt="image" src="https://github.com/user-attachments/assets/7c688f89-1121-40e9-bf66-eeee79949abb" />

</p>

<p align="center">
  <strong><i>S</i>ensitive. <i>T</i>oken. <i>O</i>bfuscation. <i>P</i>rotection.</strong><br>
  <em>Your clipboard's first line of defense.</em>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/Status-Active-brightgreen" alt="Status">
  <img src="https://img.shields.io/badge/License-MIT-blue" alt="License">
  <img src="https://img.shields.io/badge/Platform-Windows-lightgrey" alt="Platform">
  <img src="https://img.shields.io/badge/Privacy-100%25_Offline-success" alt="Privacy">
</p>

---

<img width="1920" height="1040" alt="image" src="https://github.com/user-attachments/assets/9f223792-a69a-43b8-87d1-d59931d94bc6" />

### 🛡️ Overview
**S.T.O.P. Sentinel** is a high-performance Data Loss Prevention (DLP) agent designed to intercept sensitive information within the Windows clipboard. Utilizing a low-level C++ system hook (`promptsec_hook.dll`), it provides real-time detection and blocking of credential leaks, API keys, and custom defined patterns.

### 🚀 Key Features
*   **Low-Level Hooking:** Utilizes native Windows API hooks for zero-latency clipboard monitoring.
*   **Customizable Security Policies:** Easily add or modify detection patterns via `hooks.dlp` (CSV format).
*   **Audit Trail:** Automated logging of security events (Source App, Timestamp, Threat Level) in JSONL format for compliance.
*   **Stealth Integration:** Resides in the System Tray with non-intrusive toast notifications upon threat detection.
*   **User-Centric UI:** Modern `Tkinter` dashboard with real-time statistics and uptime tracking.
<img width="1394" height="746" alt="image" src="https://github.com/user-attachments/assets/20c78032-706e-4b9f-80ec-57d9b55e52b8" />

### 🛠️ Technical Stack
*   **Core Logic:** Python 3.10+ with `ctypes` for native Windows API interaction.
*   **Performance Engine:** Custom C++ DLL for high-speed regex/string matching.
*   **GUI:** `Tkinter` with `ttk` styling.
*   **System Integration:** `pystray` (System Tray) and `Pillow` (Icon generation).

### 📋 Configuration (`hooks.dlp`)
The application loads detection rules from a local CSV file. You can manage these via the GUI or by editing the file directly:

| Name | Pattern | Threat Level | Description | Enabled |
| :--- | :--- | :--- | :--- | :--- |
| GitHub PAT | `ghp_` | CRITICAL | GitHub Token | true |
| AWS Key | `AKIA` | CRITICAL | AWS Access Key | true |

### ⚙️ Installation
1.  **Clone the repository:**
    ```bash
    git clone https://github.com/your-repo/stop-sentinel.git
    ```
2.  **Install dependencies:**
    ```bash
    pip install pystray Pillow
    ```
3.  **Deploy:** Ensure `promptsec_hook.dll` is located in the root directory.
4.  **Run:**
    ```bash
    python main.py
    ```

### 🔒 Privacy & Security
*   **100% Local:** All scanning processes occur strictly within your machine's memory space.
*   **Data Integrity:** No clipboard content is transmitted over the network.
*   **Minimalist Design:** Low CPU and memory footprint for background operation.

### 📈 Roadmap
- [ ] Implement Regex-based detection patterns.
- [ ] Add encrypted log storage.
- [ ] Remote Policy Sync (Enterprise Feature).

``Note: Tested on Windows 11, Main Python is cross platform, compile the hooks from your OS (Linux/MacOS) by downloading the files from the respective folder``
---

*Built with security-first architecture for the modern developer.*
