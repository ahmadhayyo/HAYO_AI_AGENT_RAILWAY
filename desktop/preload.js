const { contextBridge, ipcRenderer } = require("electron");

contextBridge.exposeInMainWorld("hayo", {
  getState: () => ipcRenderer.invoke("app:getState"),
  setConfig: (patch) => ipcRenderer.invoke("app:setConfig", patch),
  pickApk: () => ipcRenderer.invoke("app:pickApk"),
  pickPath: (kind) => ipcRenderer.invoke("app:pickPath", kind),
  openExternal: (url) => ipcRenderer.invoke("app:openExternal", url),
  writeTempFile: (filename, content) => ipcRenderer.invoke("app:writeTempFile", filename, content),

  adbDevices: () => ipcRenderer.invoke("adb:devices"),
  adbPackages: (device) => ipcRenderer.invoke("adb:packages", device),

  launchBat: (bat, arg) => ipcRenderer.invoke("launch:bat", bat, arg),
  launchPy: (script, arg, envPatch) => ipcRenderer.invoke("launch:py", script, arg, envPatch || {}),

  pipelineStart: (pkg, duration) => ipcRenderer.invoke("pipeline:start", pkg, duration),
  pipelineStop: () => ipcRenderer.invoke("pipeline:stop"),

  onLog: (cb) => ipcRenderer.on("log:line", (_e, l) => cb(l)),
  onPhase: (cb) => ipcRenderer.on("pipeline:phase", (_e, p) => cb(p)),
  onPipelineDone: (cb) => ipcRenderer.on("pipeline:done", (_e, code) => cb(code)),

  win: {
    minimize: () => ipcRenderer.send("win:minimize"),
    toggleMaximize: () => ipcRenderer.send("win:toggleMaximize"),
    close: () => ipcRenderer.send("win:close"),
    onMaximized: (cb) => ipcRenderer.on("window:maximized", (_e, v) => cb(v)),
  },
});
