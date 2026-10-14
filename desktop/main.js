const { app, BrowserWindow, shell } = require('electron');
const path = require('path'), fs = require('fs');

// Адреса сервера: змінна середовища або config.json (щоб користувачам не вводити її вручну)
function serverUrl() {
  if (process.env.NEUROMAP_SERVER) return process.env.NEUROMAP_SERVER;
  try { return (JSON.parse(fs.readFileSync(path.join(__dirname, 'config.json'), 'utf8')).server || '').trim().replace(/\/$/, ''); }
  catch { return ''; }
}

function createWindow() {
  const win = new BrowserWindow({
    width: 1280, height: 800, minWidth: 700, minHeight: 500, title: 'Нейромапа',
    webPreferences: { contextIsolation: true, nodeIntegration: false, sandbox: true }
  });
  const s = serverUrl();
  win.loadFile(path.join(__dirname, 'index.html'), s ? { query: { server: s } } : undefined);
  win.webContents.setWindowOpenHandler(({ url }) => { shell.openExternal(url); return { action: 'deny' }; });
}

app.whenReady().then(() => {
  createWindow();
  app.on('activate', () => { if (BrowserWindow.getAllWindows().length === 0) createWindow(); });
});
app.on('window-all-closed', () => { if (process.platform !== 'darwin') app.quit(); });
