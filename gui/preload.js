/*
 * Preload bridge: exposes a minimal, promise-based API to the renderer.
 * Only these four operations are ever reachable from web content.
 *
 * License: Apache License 2.0
 */

const { contextBridge, ipcRenderer } = require('electron');

contextBridge.exposeInMainWorld('labAPI', {
  runScan: () => ipcRenderer.invoke('lab:scan'),
  listDevices: () => ipcRenderer.invoke('lab:devices'),
  saveReport: (reportJson) => ipcRenderer.invoke('lab:save-report', reportJson),
  platform: process.platform,
});
