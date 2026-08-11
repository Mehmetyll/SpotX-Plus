<p align="center">
  <h1 align="center">SpotX+</h1>
  <p align="center">
    <strong>A highly streamlined, zero-telemetry Spotify Desktop patcher for Windows.</strong>
    <br />
    <br />
    <a href="#-quick-installation">Quick Install</a>
    •
    <a href="#-features">Features</a>
    •
    <a href="#-security--audit-verdict">Security Audit</a>
    •
    <a href="#-cli-parameters">CLI Parameters</a>
    •
    <a href="#-license">License</a>
  </p>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/Windows-10%2F11-0078D6?style=for-the-badge&logo=windows&logoColor=white" alt="Windows 10/11" />
  <img src="https://img.shields.io/badge/PowerShell-5.1%2B-5391FE?style=for-the-badge&logo=powershell&logoColor=white" alt="PowerShell 5.1+" />
  <img src="https://img.shields.io/badge/Telemetry-DISABLED-brightgreen?style=for-the-badge" alt="Telemetry Disabled" />
  <img src="https://img.shields.io/badge/License-MIT-blue?style=for-the-badge" alt="MIT License" />
</p>

---

## ⚡ Quick Installation

Run PowerShell as Administrator or regular user and execute the following single command:

```powershell
iwr https://raw.githubusercontent.com/Mehmetyll/SpotX-Plus/main/SpotX+.ps1 -UseBasicParsing | iex
```

Or download and double-click `SpotX+.bat` from the latest release.

---

## ✨ Features

- 🚫 **Blocks all Audio, Video, and Banner Ads** inside the Spotify desktop client.
- 🔒 **Zero Telemetry & Tracking** — Completely removes third-party background reporting scripts present in legacy patchers (`checkVersion.js`).
- 🎙️ **Podcast & Audiobook Filtering** — Cleans up the home tab by hiding podcasts and audiobooks (optional).
- 🔄 **Auto-Update Blocking** — Prevents Spotify from silently auto-updating and breaking your patches.
- ⚡ **Single-Command & Zero Hassle** — Runs completely automated without requiring manual Y/N user prompts.
- 🏬 **Automatic MS Store Spotify Removal** — Auto-detects and replaces unsupported Microsoft Store Spotify versions with the official desktop edition.
- 🛠️ **Experiment Flag Customization** — Automatically force-disables upsell pop-ups, fraud signals, and in-app purchase prompts.

---

## 🛡️ Security & Code Audit Verdict

SpotX+ was built following a deep reverse-engineering audit of legacy Spotify patching tools.

| Area | Status | Description |
|---|---|---|
| **Malware / Malware Scanning** | ✅ **Clean** | No packed binaries, no obfuscation, no trojans. 100% open-source PowerShell & JS. |
| **Telemetry / Tracking** | 🔒 **Disabled** | 0 analytics or tracking endpoints contacted. No data is sent to external servers. |
| **Remote Code Execution** | ✅ **Safe** | Self-contained single script. No runtime `iex` fetches of external language files. |
| **Windows Defender** | ✅ **Untouched** | Does not alter OS security settings or force Windows Defender exclusions. |

---

## 💻 CLI Parameters

You can pass parameters to `SpotX+.ps1` for custom behavior:

```powershell
# Patch and automatically launch Spotify when finished:
.\SpotX+.ps1 -LaunchAfter

# Keep podcasts and audiobooks on the homepage:
.\SpotX+.ps1 -NoPodcastFilter

# Allow Spotify to auto-update normally:
.\SpotX+.ps1 -NoUpdateBlock

# Patch existing Spotify without downloading an installer:
.\SpotX+.ps1 -SkipInstall
```

---

## 📁 Repository Structure

```
SpotX+/
├── SpotX+.ps1           # Core PowerShell patcher script
├── SpotX+.bat           # One-click Windows batch launcher
├── versions.json        # Spotify installer version manifest
├── GITHUB_SETUP.md      # Self-hosting documentation
└── patches/
    └── patches.json     # Ad-blocking and UI patch definitions
```

---

## ⚠️ Disclaimer

- **SpotX+** is an open-source educational project and is **not affiliated with or endorsed by Spotify AB**.
- SpotX+ is provided as-is under the MIT License for evaluation purposes.

---

## 📄 License

Distributed under the **MIT License**. See [`LICENSE`](LICENSE) for details.
