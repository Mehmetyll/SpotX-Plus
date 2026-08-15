# SpotX+ Self-Hosting & GitHub Setup Guide

## 1. Standalone Repo vs. Fork

> [!TIP]
> **Creating a standalone repository (NOT a fork) is recommended and completely fine.**

### Why Standalone is Better:
1. **GitHub Search Visibility**: Standalone repositories appear in search results. GitHub automatically hides forks from search unless specifically filtered.
2. **Clean Project History**: You won't accidentally submit Pull Requests back to `SpotX-Official`.
3. **Independent Issue Tracker & Discussions**: Gives your project its own identity.
4. **MIT License Compliance**: SpotX is licensed under the **MIT License**, which explicitly allows you to copy, modify, distribute, and re-license the software as long as you keep the license/copyright notice.

---

## 2. Directory Structure for Your Repository

To make your repository 100% self-contained on your GitHub account, your repository layout should look like this:

```
SpotX+/
├── .gitignore
├── LICENSE
├── README.md
├── SpotX+.bat
├── SpotX+.ps1
├── versions.json
└── patches/
    └── patches.json
```

---

## 3. URL Mapping for Your GitHub

Once pushed to your GitHub (e.g. `https://github.com/YOUR_USERNAME/SpotX-Plus`), the raw URLs used by PowerShell will be:

| Resource | Raw GitHub URL |
|---|---|
| **Installer Script** | `https://raw.githubusercontent.com/YOUR_USERNAME/SpotX-Plus/main/SpotX+.ps1` |
| **Patch Rules** | `https://raw.githubusercontent.com/YOUR_USERNAME/SpotX-Plus/main/patches/patches.json` |
| **Versions Manifest** | `https://raw.githubusercontent.com/YOUR_USERNAME/SpotX-Plus/main/versions.json` |
| **Spotify Binaries** | Public Worker proxy (`loadspot.amd64fox1.workers.dev`) or GitHub Releases |

---

## 4. Single-Command Web Installer

After setting your GitHub username in `SpotX+.ps1`, users can install SpotX+ using:

```powershell
iwr https://raw.githubusercontent.com/YOUR_USERNAME/SpotX-Plus/main/SpotX+.ps1 -UseBasicParsing | iex
```
