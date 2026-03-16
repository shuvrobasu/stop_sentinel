# <p align="center">S.T.O.P. SENTINEL</p>

<p align="center">
  <img width="256" height="256" alt="image" src="https://github.com/user-attachments/assets/7c688f89-1121-40e9-bf66-eeee79949abb" />

</p>

<p align="center">
  <strong><i>S</i>ensitive. <i>T</i>oken. <i>O</i>bfuscation. & <i>P</i>rotection.</strong><br>
  <em>Your clipboard's first line of defense.</em>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/Status-Active-brightgreen" alt="Status">
  <img src="https://img.shields.io/badge/License-MIT-blue" alt="License">
  <img src="https://img.shields.io/badge/Platform-Windows-lightgrey" alt="Platform">
<img src="https://img.shields.io/badge/Linux-Supported-lightgrey?logo=linux&logoColor=white" alt="Linux">
  <img src="https://img.shields.io/badge/macOS-Supported-lightgrey?logo=apple&logoColor=black" alt="macOS">
  <img src="https://img.shields.io/badge/Privacy-100%25_Offline-success" alt="Privacy">
</p>

---

<img width="1920" height="1040" alt="image" src="https://github.com/user-attachments/assets/eb3e0a43-012d-40c9-bd2a-c33a511d7795" />


### 🛡️ Overview
**S.T.O.P. Sentinel** is a high-performance Data Loss Prevention (DLP) agent designed to intercept sensitive information within the Windows clipboard. Utilizing a low-level C++ system hook (`promptsec_hook.dll`), it provides real-time detection and blocking of credential leaks, API keys, and custom defined patterns.

### 🚀 Key Features
*  **Native Low-Level Clipboard Hooking:** Uses OS-specific native hook libraries for fast clipboard interception and monitoring on supported platforms.
*  **Regex + Substring Detection Engine:** Supports both exact substring matching and regex-based detection for secrets, tokens, credentials, PII, and structured identifiers.
*  **Customizable Security Policies:** Add, edit, delete, enable, or disable rules through hooks.dlp (CSV-based policy file).
*  **Built-in Detection Library:** Ships with 80+ ready-to-use patterns covering API keys, cloud credentials, private keys, database URLs, PII, financial identifiers, and more.
*  **Threat Blocking & Redaction:** Automatically replaces detected sensitive clipboard content with blocked/redacted placeholders before reuse.
*  **Threat Scoring Engine:** Assigns severity and score to detections for better prioritization and triage.
*  **Entropy-Based Secret Detection:** Identifies suspicious high-entropy strings that may represent unknown or custom secrets.
*  **Luhn Validation:** Detects and validates payment card numbers using checksum validation to reduce false positives.
*  **Application Whitelisting:** Allows selected applications to bypass scanning rules where needed.
*  **Application-Specific Policies:** Supports different actions and alert levels depending on the source or target application.
*  **Clipboard Auto-Expire:** Optionally clears sensitive clipboard content automatically after a configured time window.
*  **Undo Support:** Provides protected recovery of recently redacted clipboard entries.
*  **Clipboard History:** Maintains an encrypted clipboard event/history store for inspection and review.
*  **Encrypted Log Storage:** Audit and event logs can be encrypted at rest for stronger privacy and compliance.
*  **Audit Trail:** Automatically logs source app, timestamp, threat, action taken, and score in JSONL format for compliance and forensics.
*  **Exportable Logs:** Security events can be exported for reporting and compliance workflows.
*  **Remote Policy Sync:** Supports centralized rule synchronization from a remote source for managed deployments.
*  **Pattern Auto-Update:** Can pull updated detection templates automatically from a configured repository/source.
*  **Email Alerts:** Sends alert notifications to users/admins when threats are detected.
*  **SIEM Integration:** Supports forwarding events to external SIEM/syslog-style pipelines for centralized monitoring.
*  **Embedded Dashboard Server:** Includes a lightweight built-in web dashboard server for viewing logged activity.
*  **Pattern Testing Sandbox:** Lets users test text against configured rules without affecting the live clipboard.
*  **Collapsible Pattern Categories:** Security rules are grouped in expandable/collapsible sections for easier management.
*  **User-Centric GUI:** Modern Tkinter-based desktop interface with real-time status, threat counters, and session uptime.
*  **System Tray Integration:** Runs quietly in the tray with toast notifications and quick access controls.
*  **Cross-Platform Design:** Structured for Windows, Linux, and macOS with platform-specific hook implementations.
*  **Ready to Use:** Comes preloaded with a broad set of practical detection templates so it works out of the box.

---

<img width="1394" height="746" alt="image" src="https://github.com/user-attachments/assets/20c78032-706e-4b9f-80ec-57d9b55e52b8" />

### 🛠️ Technical Stack
*   **Core Logic:** Python 3.10+ with `ctypes` for native OS API interaction.
*   **Performance Engine:** Custom C DLL for high-speed regex/string matching.
*   **GUI:** `Tkinter` with `ttk` styling.
*   **System Integration:** `pystray` (System Tray) and `Pillow` (Icon generation).

### 📋 Configuration (`hooks.dlp`)
The application loads detection rules from a local CSV file. You can manage these via the GUI or by editing the file directly:

| Name | Pattern | Threat Level | Description | Enabled |
| :--- | :--- | :--- | :--- | :--- |
| GitHub PAT | `ghp_` | CRITICAL | GitHub Token | true |
| AWS Key | `AKIA` | CRITICAL | AWS Access Key | true |

| | |
| :---: | :---: |
| <img src="https://github.com/user-attachments/assets/023cdc1e-f219-41ec-b8fc-bfd13fb267a3" alt="image" width="720" height="720"> | <img src="https://github.com/user-attachments/assets/e81d9073-9c32-4e7f-8c17-1c63f7acf209" alt="image" width="720" height="720"> |
| <img src="https://github.com/user-attachments/assets/f855c454-3378-4e39-8b4b-7ca11dc16957" alt="image" width="720" height="720"> | <img src="https://github.com/user-attachments/assets/8c16718e-4cf2-4549-9b74-16dda21e18da" alt="image" width="720" height="720"> |




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
### Build Commands for the Hook file.

* Windows:
<br>gcc -shared -o promptsec_hook.dll promptsec_hook.c -luser32 -O2
---
* Linux:
<br>sudo apt install libx11-dev xclip xdotool python3-tk
<br>gcc -shared -fPIC -o stop_sentinel_hook.so stop_sentinel_hook_linux.c -lX11 -lpthread -O2
---
* macOS:
## This is a bit tricky as there are different hardware and OS out there
### Setup Instructions
1. **Install Xcode Command Line Tools**: `xcode-select --install`
2. **Install Python**: `/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"` then `brew install python@3.11 python-tk@3.11`
3. **Install Dependencies**: `pip3 install pystray pillow`
4. **Clone Repository**: `git clone https://github.com/shuvrobasu/stop_sentinel.git` then `cd stop_sentinel`
5. **Compile Native Hook**: 
   - Apple Silicon: `gcc -shared -fPIC -o stop_sentinel_hook.dylib stop_sentinel_hook_macos.m -framework Cocoa -lpthread -O2 -arch arm64`
   - Intel Mac: `gcc -shared -fPIC -o stop_sentinel_hook.dylib stop_sentinel_hook_macos.m -framework Cocoa -lpthread -O2 -arch x86_64`
   - Universal: `gcc -shared -fPIC -o stop_sentinel_hook.dylib stop_sentinel_hook_macos.m -framework Cocoa -lpthread -O2 -arch arm64 -arch x86_64`
6. **Grant Permissions**: Go to **System Settings > Privacy & Security > Accessibility** and add your python interpreter (path found via `which python3`). If running from a terminal, add the terminal app to this list as well.
7. **Run**: `python3 stop_sentinel.py`

### Troubleshooting
- **Library Error**: Run `file stop_sentinel_hook.dylib` or `otool -L stop_sentinel_hook.dylib`.
- **Security/Quarantine Error**: `xattr -d com.apple.quarantine stop_sentinel_hook.dylib`.
- **Clipboard Access Denied**: `tccutil reset Accessibility`, then re-add permissions.
- **Tkinter Missing**: `brew reinstall python-tk@3.11`.

### Compatibility
Verified on macOS 12 Monterey (Intel), 13 Ventura, 14 Sonoma, and 15 Sequoia (Apple Silicon).

---
### 🔒 Privacy & Security
*   **100% Local:** All scanning processes occur strictly within your machine's memory space.
*   **Data Integrity:** No clipboard content is transmitted over the network.
*   **Minimalist Design:** Low CPU and memory footprint for background operation.

### 📈 Roadmap
- [ ] Implement Regex-based detection patterns.
- [ ] Add encrypted log storage.
- [ ] Remote Policy Sync (Enterprise Feature).
- [ ] Email alerts to user/admin 

#### Note: Tested on Windows 11, Main Python is cross platform, compile the hooks for your OS (Linux/MacOS) by downloading the files from the respective folder and following instrunctions above to compile/build from source.
---

*Built with security-first architecture for the modern developer.*
