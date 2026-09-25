const express = require('express');
const si = require('systeminformation');
const { Pool } = require('pg');
const { execFile } = require('child_process');
const http = require('http');
const os = require('os');
const fs = require('fs');
const crypto = require('crypto');
const pty = require('node-pty');
const WebSocket = require('ws');
const jwt = require('jsonwebtoken');
const path = require('path');
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 3001;
app.set('trust proxy', 1);

const AUTH_USER = process.env.PANEL_USER;
const AUTH_PASS = process.env.PANEL_PASS;
const JWT_SECRET = process.env.JWT_SECRET;

if (!AUTH_USER) throw new Error('Variável PANEL_USER não definida no ambiente.');
if (!AUTH_PASS) throw new Error('Variável PANEL_PASS não definida no ambiente.');
if (!JWT_SECRET) throw new Error('Variável JWT_SECRET não definida no ambiente.');
if (JWT_SECRET.length < 32) throw new Error('JWT_SECRET precisa ter pelo menos 32 caracteres.');
if (process.env.NODE_ENV === 'production' && !/^https:\/\//i.test(process.env.ORIGIN || '')) {
  throw new Error('Defina ORIGIN com o dominio HTTPS do painel em producao.');
}

app.use(express.json({ limit: '16kb' }));
app.use(express.static(path.join(__dirname, 'public')));
app.use('/vendor/xterm', express.static(path.join(__dirname, 'node_modules/@xterm/xterm/lib')));
app.use('/vendor/xterm-css', express.static(path.join(__dirname, 'node_modules/@xterm/xterm/css')));
app.use('/vendor/xterm-fit', express.static(path.join(__dirname, 'node_modules/@xterm/addon-fit/lib')));

const pool = new Pool({
  host: process.env.DB_HOST || 'localhost',
  port: process.env.DB_PORT || 5432,
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  database: process.env.DB_NAME || 'postgres',
  max: 8,
  min: 2,
  connectionTimeoutMillis: 2000,
  idleTimeoutMillis: 10000,
});

pool.on('error', (err) => console.error('Erro no pool PostgreSQL:', err));

function verificarToken(req, res, next) {
  const cookie = req.headers.cookie?.split(';').map((part) => part.trim()).find((part) => part.startsWith('painel_token='));
  const token = cookie?.slice('painel_token='.length);
  if (!token) {
    return res.status(401).json({ erro: 'Não autenticado' });
  }
  try {
    const session = jwt.verify(decodeURIComponent(token), JWT_SECRET);
    req.usuario = session.usuario;
    next();
  } catch {
    return res.status(401).json({ erro: 'Token inválido' });
  }
}

const loginAttempts = new Map();
const LOGIN_WINDOW_MS = 15 * 60 * 1000;
const MAX_LOGIN_ATTEMPTS = 10;

app.post('/api/login', (req, res) => {
  console.log('📨 Requisição de login recebida');
  const clientIp = req.ip;
  const now = Date.now();
  const attempts = loginAttempts.get(clientIp);
  if (attempts && now - attempts.startedAt < LOGIN_WINDOW_MS && attempts.count >= MAX_LOGIN_ATTEMPTS) {
    return res.status(429).json({ sucesso: false, mensagem: 'Muitas tentativas. Tente novamente em alguns minutos.' });
  }
  if (loginAttempts.size > 5000) loginAttempts.clear();
  const { usuario, senha } = req.body;
  if (!usuario || !senha) {
    return res.status(400).json({ sucesso: false, mensagem: 'Usuário e senha obrigatórios' });
  }
  loginAttempts.set(clientIp, attempts && now - attempts.startedAt < LOGIN_WINDOW_MS
    ? { startedAt: attempts.startedAt, count: attempts.count + 1 }
    : { startedAt: now, count: 1 });
  if (usuario === AUTH_USER && senha === AUTH_PASS) {
    const token = jwt.sign({ usuario }, JWT_SECRET, { expiresIn: '8h' });
    console.log('✅ Login bem-sucedido:', usuario);
    loginAttempts.delete(clientIp);
    const secure = process.env.NODE_ENV === 'production' ? '; Secure' : '';
    res.setHeader('Set-Cookie', `painel_token=${encodeURIComponent(token)}; HttpOnly; SameSite=Strict; Path=/; Max-Age=28800${secure}`);
    return res.json({ sucesso: true });
  }
  console.log('❌ Falha no login');
  res.status(401).json({ sucesso: false, mensagem: 'Usuário ou senha incorretos' });
});

app.post('/api/logout', (req, res) => {
  const secure = process.env.NODE_ENV === 'production' ? '; Secure' : '';
  res.setHeader('Set-Cookie', [
    `painel_token=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0${secure}`,
    `terminal_root=; HttpOnly; SameSite=Strict; Path=/terminal; Max-Age=0${secure}`,
  ]);
  res.json({ sucesso: true });
});

app.use('/api/consumo', verificarToken);
app.use('/api/pg', verificarToken);
app.use('/api/docker', verificarToken);
app.use('/api/pgadmin', verificarToken);
app.use('/api/controle-semanal', verificarToken);

app.get('/api/session', verificarToken, (req, res) => res.json({ autenticado: true }));

const rootAttempts = new Map();
const ROOT_WINDOW_MS = 15 * 60 * 1000;
const MAX_ROOT_ATTEMPTS = 5;

app.post('/api/terminal/root-session', verificarToken, (req, res) => {
  if (!originPermitida(req)) return res.status(403).json({ erro: 'Origem invalida.' });
  if (process.platform === 'win32' || process.getuid?.() !== 0) {
    return res.status(503).json({ erro: 'Modo root indisponivel: o painel precisa estar rodando como root em Linux.' });
  }
  const clientIp = req.ip;
  const now = Date.now();
  const attempts = rootAttempts.get(clientIp);
  if (attempts && now - attempts.startedAt < ROOT_WINDOW_MS && attempts.count >= MAX_ROOT_ATTEMPTS) {
    return res.status(429).json({ erro: 'Muitas tentativas. Aguarde 15 minutos.' });
  }
  const provided = Buffer.from(String(req.body?.senha || ''));
  const expected = Buffer.from(AUTH_PASS);
  const passwordMatches = provided.length === expected.length && crypto.timingSafeEqual(provided, expected);
  if (!passwordMatches) {
    rootAttempts.set(clientIp, attempts && now - attempts.startedAt < ROOT_WINDOW_MS
      ? { startedAt: attempts.startedAt, count: attempts.count + 1 }
      : { startedAt: now, count: 1 });
    return res.status(401).json({ erro: 'Senha incorreta.' });
  }
  rootAttempts.delete(clientIp);
  const token = jwt.sign({ usuario: req.usuario, scope: 'root-terminal' }, JWT_SECRET, { expiresIn: '10m' });
  const secure = process.env.NODE_ENV === 'production' ? '; Secure' : '';
  res.setHeader('Set-Cookie', `terminal_root=${encodeURIComponent(token)}; HttpOnly; SameSite=Strict; Path=/terminal; Max-Age=600${secure}`);
  res.json({ sucesso: true, expiraEm: 600 });
});

app.post('/api/terminal/root-exit', verificarToken, (req, res) => {
  const secure = process.env.NODE_ENV === 'production' ? '; Secure' : '';
  res.setHeader('Set-Cookie', `terminal_root=; HttpOnly; SameSite=Strict; Path=/terminal; Max-Age=0${secure}`);
  res.json({ sucesso: true });
});

app.get('/api/consumo', async (req, res) => {
  try {
    const [cpu, mem, disco] = await Promise.all([si.currentLoad(), si.mem(), si.fsSize()]);
    const mainDisk = disco[0] || { used: 0, size: 0, available: 0 };
    
    // ✅ CÁLCULO CORRIGIDO: mem.available = memória REALMENTE livre
    const ramUsadaPercent = ((mem.total - mem.available) / mem.total) * 100;
    
    res.json({
      cpu: cpu.currentLoad?.toFixed(1) || '0.0',
      ramUsada: ramUsadaPercent.toFixed(1),
      ramTotalGB: (mem.total / 1024 ** 3).toFixed(1),
      ramLivreGB: (mem.available / 1024 ** 3).toFixed(1),
      discoUsado: (mainDisk.size ? (mainDisk.used / mainDisk.size) * 100 : 0).toFixed(1),
      discoUsadoGB: (mainDisk.used / 1024 ** 3).toFixed(1),
      discoTotalGB: (mainDisk.size / 1024 ** 3).toFixed(0),
      discoLivreGB: (mainDisk.available / 1024 ** 3).toFixed(1),
      tempoAtivoSistema: Math.floor(si.time().uptime / 3600)
    });
  } catch (erro) {
    console.error('Erro em /api/consumo:', erro);
    res.status(500).json({ erro: 'Falha ao coletar métricas' });
  }
});

app.get('/api/pg/geral', async (req, res) => {
  try {
    if (!process.env.DB_USER || !process.env.DB_PASSWORD) {
      return res.status(503).json({ total: 'Indisponível', conexoes: 0 });
    }
    const client = await pool.connect();
    try {
      const total = await client.query(`SELECT pg_size_pretty(sum(pg_database_size(datname))) as total FROM pg_database WHERE datistemplate = false`);
      const conexoes = await client.query(`SELECT count(*) as total FROM pg_stat_activity`);
      res.json({ total: total.rows[0]?.total || '0 MB', conexoes: parseInt(conexoes.rows[0]?.total || 0) });
    } finally { client.release(); }
  } catch (erro) {
    console.error('Erro em /api/pg/geral:', erro.message);
    res.status(503).json({ total: 'Indisponível', conexoes: 0 });
  }
});

app.get('/api/docker', (req, res) => {
  const composePath = process.env.DOCKER_COMPOSE_PATH || '/root/DB';
  execFile('docker', ['compose', 'ps', '--format', 'json'], { cwd: composePath, timeout: 10000, maxBuffer: 1024 * 1024 }, (err, stdout) => {
    if (!err && stdout.trim()) {
      try {
        const containers = stdout.trim().startsWith('[') ? JSON.parse(stdout) : stdout.trim().split('\n').map(JSON.parse);
        return res.json(containers.map(c => ({ Name: c.Name || c.Names, State: c.State || c.Status })));
      } catch (parseErr) { console.error('Erro parse JSON:', parseErr); }
    }
    execFile('docker', ['ps', '--format', '{{.Names}}|{{.Status}}'], { timeout: 10000, maxBuffer: 1024 * 1024 }, (e, out) => {
      if (e || !out.trim()) return res.json([]);
      res.json(out.trim().split('\n').map(l => {
        const [name, status] = l.split('|');
        return { Name: name, State: status?.toLowerCase().includes('up') ? 'running' : 'stopped' };
      }));
    });
  });
});

app.get('/api/pgadmin/status', (req, res) => {
  execFile('docker', ['inspect', '-f', '{{.State.Running}}', 'pgadmin_web'], { timeout: 10000 }, (err, stdout) => {
    res.json({ running: !err && stdout.trim() === 'true' });
  });
});

app.post('/api/pgadmin/start', (req, res) => {
  execFile('docker', ['start', 'pgadmin_web'], { timeout: 30000 }, (err) => {
    res.json({ ok: !err, msg: err ? 'Erro ao ligar' : '✅ pgAdmin ligado!' });
  });
});

app.post('/api/pgadmin/stop', (req, res) => {
  execFile('docker', ['stop', 'pgadmin_web'], { timeout: 30000 }, (err) => {
    res.json({ ok: !err, msg: err ? 'Erro ao desligar' : '✅ pgAdmin desligado!' });
  });
});

app.get('/api/controle-semanal/status', (req, res) => {
  execFile('docker', ['inspect', '-f', '{{.State.Running}}', 'controle-semanal'], { timeout: 10000 }, (err, stdout) => {
    if (err) return res.json({ running: false, msg: 'Não encontrado', url: 'http://178.92.162.170:8080' });
    res.json({ running: stdout.trim() === 'true', url: 'http://178.92.162.170:8080' });
  });
});

app.post('/api/controle-semanal/start', (req, res) => {
  execFile('docker', ['start', 'controle-semanal'], { timeout: 30000 }, (err) => {
    res.json({ ok: !err, msg: err ? 'Erro' : '✅ Controle Semanal LIGADO!' });
  });
});

app.post('/api/controle-semanal/stop', (req, res) => {
  execFile('docker', ['stop', 'controle-semanal'], { timeout: 30000 }, (err) => {
    res.json({ ok: !err, msg: err ? 'Erro' : '✅ Controle Semanal DESLIGADO!' });
  });
});

const server = http.createServer(app);
const terminalWss = new WebSocket.Server({ noServer: true, maxPayload: 32 * 1024, perMessageDeflate: false });
const activeTerminals = new Set();

function originPermitida(req) {
  try {
    const origin = new URL(req.headers.origin);
    const expected = process.env.ORIGIN
      ? new URL(process.env.ORIGIN)
      : new URL(`${req.headers['x-forwarded-proto']?.split(',')[0] || 'http'}://${req.headers.host}`);
    return origin.origin === expected.origin;
  } catch {
    return false;
  }
}

function obterUsuarioTerminal(nome) {
  if (!/^[a-z_][a-z0-9_-]*[$]?$/i.test(nome || '')) throw new Error('TERMINAL_USER invalido.');
  const passwd = fs.readFileSync('/etc/passwd', 'utf8');
  const fields = passwd.split('\n').map((line) => line.split(':')).find((entry) => entry[0] === nome);
  if (!fields) throw new Error(`A conta Linux ${nome} nao existe.`);
  const uid = Number(fields[2]);
  const gid = Number(fields[3]);
  const home = fields[5];
  if (!Number.isInteger(uid) || uid <= 0 || !Number.isInteger(gid) || !home || !fs.existsSync(home)) {
    throw new Error(`A conta Linux ${nome} nao tem UID, GID ou home valido.`);
  }
  const homeOwner = fs.statSync(home).uid;
  if (homeOwner !== uid) throw new Error(`O home ${home} nao pertence a ${nome}.`);
  const primaryGroup = fs.readFileSync('/etc/group', 'utf8').split('\n')
    .map((line) => line.split(':'))
    .find((entry) => Number(entry[2]) === gid);
  if (!primaryGroup || primaryGroup[0] !== nome || ['root', 'docker', 'sudo', 'wheel'].includes(primaryGroup[0])) {
    throw new Error(`A conta ${nome} precisa de um grupo privado com o mesmo nome.`);
  }
  const setpriv = ['/usr/bin/setpriv', '/bin/setpriv'].find((candidate) => fs.existsSync(candidate));
  if (!setpriv) throw new Error('setpriv nao encontrado; instale o pacote util-linux.');
  return { nome, uid, gid, home, setpriv };
}

server.on('upgrade', (req, socket, head) => {
  let pathname;
  try { pathname = new URL(req.url, 'http://localhost').pathname; } catch {}
  if (pathname !== '/terminal') {
    socket.destroy();
    return;
  }
  const cookie = req.headers.cookie?.split(';').map((part) => part.trim()).find((part) => part.startsWith('painel_token='));
  let session;
  try { session = cookie && jwt.verify(decodeURIComponent(cookie.slice('painel_token='.length)), JWT_SECRET); } catch {}
  const originOk = originPermitida(req);
  if (!session) console.warn('Terminal WebSocket recusado: cookie de sessao ausente ou invalido.');
  if (session && !originOk) console.warn('Terminal WebSocket recusado: origem nao corresponde a ORIGIN.');
  if (!session || !originOk) {
    socket.write('HTTP/1.1 403 Forbidden\r\nConnection: close\r\n\r\n');
    socket.destroy();
    return;
  }
  const params = new URL(req.url, 'http://localhost').searchParams;
  req.terminalMode = params.get('mode') === 'root' ? 'root' : 'user';
  if (req.terminalMode === 'root') {
    const rootCookie = req.headers.cookie?.split(';').map((part) => part.trim()).find((part) => part.startsWith('terminal_root='));
    let rootSession;
    try { rootSession = rootCookie && jwt.verify(decodeURIComponent(rootCookie.slice('terminal_root='.length)), JWT_SECRET); } catch {}
    if (!rootSession || rootSession.scope !== 'root-terminal' || rootSession.usuario !== session.usuario || process.platform === 'win32' || process.getuid?.() !== 0) {
      socket.write('HTTP/1.1 403 Forbidden\r\nConnection: close\r\n\r\n');
      socket.destroy();
      return;
    }
    req.terminalSession = { usuario: session.usuario, exp: Math.min(session.exp, rootSession.exp) };
  } else {
    req.terminalSession = session;
  }
  terminalWss.handleUpgrade(req, socket, head, (ws) => terminalWss.emit('connection', ws, req));
});

terminalWss.on('connection', (ws, req) => {
  if (activeTerminals.size >= 1) {
    ws.close(1013, 'Terminal já aberto');
    return;
  }

  let terminal;
  try {
    const windows = process.platform === 'win32';
    let command;
    let args;
    let cwd;
    let terminalEnv;
    if (req.terminalMode === 'root') {
      command = '/bin/bash';
      args = ['--login'];
      cwd = '/root';
      terminalEnv = {
        HOME: '/root', USER: 'root', LOGNAME: 'root', SHELL: '/bin/bash',
        PATH: '/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin',
        LANG: process.env.LANG || 'C.UTF-8', TERM: 'xterm-256color', COLORTERM: 'truecolor',
      };
      console.warn(`Terminal root temporario aberto para ${req.terminalSession.usuario || 'usuario autenticado'}.`);
    } else if (windows) {
      command = process.env.TERMINAL_SHELL || 'powershell.exe';
      args = ['-NoLogo'];
      cwd = process.env.USERPROFILE || os.homedir();
      terminalEnv = { ...process.env, TERM: 'xterm-256color', COLORTERM: 'truecolor' };
    } else {
      const username = process.env.TERMINAL_USER || 'painelterminal';
      const account = obterUsuarioTerminal(username);
      command = account.setpriv;
      args = [
        `--reuid=${account.uid}`,
        `--regid=${account.gid}`,
        '--clear-groups',
        '--inh-caps=-all',
        '--bounding-set=-all',
        '--no-new-privs',
        '--',
        '/bin/bash',
        '--login',
      ];
      cwd = account.home;
      terminalEnv = {
        HOME: account.home,
        USER: account.nome,
        LOGNAME: account.nome,
        SHELL: '/bin/bash',
        PATH: '/usr/local/bin:/usr/bin:/bin',
        LANG: process.env.LANG || 'C.UTF-8',
        TERM: 'xterm-256color',
        COLORTERM: 'truecolor',
      };
      console.log(`Terminal iniciado como usuario sem privilegios: ${account.nome}.`);
    }
    terminal = pty.spawn(command, args, {
      name: 'xterm-256color',
      cols: 100,
      rows: 28,
      cwd,
      env: terminalEnv,
    });
  } catch (error) {
    console.error('Falha ao iniciar terminal PTY:', error.message);
    ws.close(1011, 'Não foi possível iniciar o terminal');
    return;
  }

  activeTerminals.add(ws);
  console.log(`Terminal WebSocket conectado em modo ${req.terminalMode}.`);
  const sessionTimeout = setTimeout(() => ws.close(4001, 'Sessão expirada'), Math.max(0, req.terminalSession.exp * 1000 - Date.now()));
  sessionTimeout.unref();
  const output = terminal.onData((data) => {
    if (ws.readyState !== WebSocket.OPEN) return;
    if (ws.bufferedAmount > 1024 * 1024) {
      ws.close(1013, 'Saída acima do limite');
      return;
    }
    ws.send(JSON.stringify({ type: 'output', data }));
  });
  const exited = terminal.onExit(({ exitCode }) => {
    if (ws.readyState === WebSocket.OPEN) {
      ws.send(JSON.stringify({ type: 'exit', code: exitCode }));
      ws.close(1000, 'Shell finalizado');
    }
  });

  ws.on('message', (raw) => {
    try {
      const message = JSON.parse(raw.toString());
      if (message.type === 'input' && typeof message.data === 'string' && message.data.length <= 16384) {
        terminal.write(message.data);
      } else if (message.type === 'resize' && Number.isInteger(message.cols) && Number.isInteger(message.rows)) {
        terminal.resize(Math.max(20, Math.min(message.cols, 240)), Math.max(8, Math.min(message.rows, 80)));
      }
    } catch {
      ws.close(1003, 'Mensagem inválida');
    }
  });
  ws.on('close', () => {
    console.log('Terminal WebSocket desconectado.');
    clearTimeout(sessionTimeout);
    activeTerminals.delete(ws);
    output.dispose();
    exited.dispose();
    try { terminal.kill(); } catch {}
  });
  ws.on('error', () => ws.close());
});

app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

server.listen(PORT, '127.0.0.1', () => {
  console.log(`🚀 Painel rodando em http://127.0.0.1:${PORT}`);
});
