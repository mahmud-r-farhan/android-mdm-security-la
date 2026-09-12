/*
 * Android Enterprise Security Lab - Desktop GUI (Electron main process)
 * ---------------------------------------------------------------------
 * Thin, secure wrapper around the Python inspection engine in ../core.
 *
 * Security model:
 *   - renderer runs with contextIsolation ON, nodeIntegration OFF
 *   - all privileged work (spawning python/adb, saving files) happens here
 *   - the Python engine is invoked strictly read-only (--json --no-export)
 *
 * License: Apache License 2.0
 */

const { app, BrowserWindow, ipcMain, dialog, shell } = require('electron');
const { spawn } = require('child_process');
const path = require('path');
const fs = require('fs');

const REPO_ROOT = path.resolve(__dirname, '..');
const INSPECTOR = path.join(REPO_ROOT, 'core', 'mdm_inspector.py');
const SCAN_TIMEOUT_MS = 90_000;

// Candidate python launchers per platform (first hit wins).
const PYTHON_CANDIDATES = process.platform === 'win32'
  ? ['python', 'python3', 'py']
  : ['python3', 'python'];

function findPython() {
  const { execFileSync } = require('child_process');
  for (const candidate of PYTHON_CANDIDATES) {
    try {
      execFileSync(candidate, ['--version'], { stdio: 'ignore', timeout: 5000 });
      return candidate;
    } catch (_err) {
      // try next candidate
    }
  }
  return null;
}

function runInspector(pythonCmd) {
  return new Promise((resolve) => {
    const args = [INSPECTOR, '--json', '--no-export'];
    let child;
    try {
      child = spawn(pythonCmd, args, {
        cwd: REPO_ROOT,
        env: { ...process.env },
        windowsHide: true,
      });
    } catch (err) {
      resolve({ ok: false, error: `Failed to launch python: ${err.message}` });
      return;
    }

    let stdout = '';
    let stderr = '';
    const timer = setTimeout(() => {
      child.kill();
      resolve({ ok: false, error: 'Scan timed out after 90 seconds.' });
    }, SCAN_TIMEOUT_MS);

    child.stdout.on('data', (chunk) => { stdout += chunk.toString(); });
    child.stderr.on('data', (chunk) => { stderr += chunk.toString(); });

    child.on('error', (err) => {
      clearTimeout(timer);
      resolve({ ok: false, error: `Inspector failed to start: ${err.message}` });
    });

    child.on('close', (code) => {
      clearTimeout(timer);
      const jsonStart = stdout.indexOf('{');
      if (jsonStart >= 0) {
        try {
          const report = JSON.parse(stdout.slice(jsonStart));
          resolve({ ok: true, report, stderr });
          return;
        } catch (_err) {
          // fall through to error path
        }
      }
      const message = stderr.trim() || `Inspector exited with code ${code}`;
      resolve({ ok: false, error: message, code });
    });
  });
}

function listDevices() {
  return new Promise((resolve) => {
    let child;
    try {
      child = spawn('adb', ['devices'], { windowsHide: true });
    } catch (_err) {
      resolve({ ok: false, error: 'adb not found on PATH.' });
      return;
    }
    let stdout = '';
    let stderr = '';
    const timer = setTimeout(() => {
      child.kill();
      resolve({ ok: false, error: 'adb devices timed out.' });
    }, 10_000);
    child.stdout.on('data', (c) => { stdout += c.toString(); });
    child.stderr.on('data', (c) => { stderr += c.toString(); });
    child.on('error', (err) => {
      clearTimeout(timer);
      resolve({ ok: false, error: `adb failed: ${err.message}` });
    });
    child.on('close', () => {
      clearTimeout(timer);
      const devices = stdout.split('\n').slice(1)
        .map((line) => line.trim())
        .filter((line) => line.length > 0)
        .map((line) => {
          const [serial, state] = line.split(/\s+/);
          return { serial, state };
        });
      resolve({ ok: true, devices, stderr });
    });
  });
}

function createWindow() {
  const win = new BrowserWindow({
    width: 1180,
    height: 800,
    minWidth: 900,
    minHeight: 640,
    backgroundColor: '#0f172a',
    title: 'Android MDM Security Lab',
    webPreferences: {
      preload: path.join(__dirname, 'preload.js'),
      contextIsolation: true,
      nodeIntegration: false,
      sandbox: false,
    },
  });

  win.setMenuBarVisibility(false);
  win.loadFile(path.join(__dirname, 'renderer', 'index.html'));

  // Open external links in the system browser, never inside the app.
  win.webContents.setWindowOpenHandler(({ url }) => {
    if (url.startsWith('https://')) shell.openExternal(url);
    return { action: 'deny' };
  });
}

ipcMain.handle('lab:scan', async () => {
  const pythonCmd = findPython();
  if (!pythonCmd) {
    return {
      ok: false,
      error: 'Python 3.9+ was not found on PATH. Run scripts/setup.sh (Linux/macOS) '
        + 'or scripts\\setup.bat (Windows), then restart this app.',
    };
  }
  if (!fs.existsSync(INSPECTOR)) {
    return { ok: false, error: `Inspector not found at ${INSPECTOR}.` };
  }
  return runInspector(pythonCmd);
});

ipcMain.handle('lab:devices', () => listDevices());

ipcMain.handle('lab:save-report', async (_event, reportJson) => {
  const { canceled, filePath } = await dialog.showSaveDialog({
    title: 'Export Audit Report',
    defaultPath: 'mdm_audit_report.json',
    filters: [{ name: 'JSON report', extensions: ['json'] }],
  });
  if (canceled || !filePath) return { ok: false, canceled: true };
  try {
    fs.writeFileSync(filePath, reportJson, 'utf-8');
    return { ok: true, filePath };
  } catch (err) {
    return { ok: false, error: err.message };
  }
});

app.whenReady().then(() => {
  createWindow();
  app.on('activate', () => {
    if (BrowserWindow.getAllWindows().length === 0) createWindow();
  });
});

app.on('window-all-closed', () => {
  if (process.platform !== 'darwin') app.quit();
});
