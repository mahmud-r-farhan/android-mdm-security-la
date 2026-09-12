# Android MDM Security Lab — Desktop GUI

An Electron dashboard for non-technical users, wrapping the read-only Python
inspection engine in `../core`.

![status](https://img.shields.io/badge/status-read--only-green)

## Features (Roadmap Phase 3)

| Capability | Implementation |
|---|---|
| Device info (brand, model, Android/SDK/Knox) | `core/mdm_inspector.py --json` via IPC |
| Device Owner / Profile Owner indicator | Visual SAFE / WORK PROFILE / MANAGED badge |
| Known MDM / financing-lock package list | Signature database from the Python engine |
| One-click Export Audit Report (JSON) | Native save dialog in the main process |

## Security model

* `contextIsolation: true`, `nodeIntegration: false` — the renderer can only
  reach four whitelisted IPC calls (`lab:scan`, `lab:devices`,
  `lab:save-report`, plus platform info).
* Strict `Content-Security-Policy` in `renderer/index.html`.
* External links are handed to the system browser, never rendered in-app.
* The GUI only ever invokes the inspector in read-only mode
  (`--json --no-export`) — it cannot modify device state.

## Requirements

* Node.js 18+ and npm
* Python 3.9+ on PATH (run `../scripts/setup.sh` / `setup.bat` first)
* `adb` on PATH (installed by the same setup scripts)

## Run in development

```bash
cd gui
npm install
npm start
```

## Package installers

```bash
npm run dist        # current platform
npm run dist:win    # Windows NSIS installer
npm run dist:mac    # macOS dmg
npm run dist:linux  # AppImage + deb
```

Outputs land in `gui/dist/` (git-ignored).

## Troubleshooting

| Symptom | Fix |
|---|---|
| "Python 3.9+ was not found" | Run `../scripts/setup.sh` or `setup.bat`, restart the app |
| "No device connected" though plugged in | Accept the USB-debugging RSA dialog; check `../scripts/oem_driver_check.ps1` on Windows |
| Scan times out | Restart `adb` (`adb kill-server && adb start-server`) and retry |
