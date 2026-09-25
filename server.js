const express = require('express');
const si = require('systeminformation');
const { Pool } = require('pg');
const { execFile } = require('child_process');
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

app.use(express.json({ limit: '16kb' }));
app.use(express.static(path.join(__dirname, 'public')));

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
    jwt.verify(decodeURIComponent(token), JWT_SECRET);
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
  res.setHeader('Set-Cookie', `painel_token=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0${secure}`);
  res.json({ sucesso: true });
});

app.use('/api/consumo', verificarToken);
app.use('/api/pg', verificarToken);
app.use('/api/docker', verificarToken);
app.use('/api/pgadmin', verificarToken);
app.use('/api/controle-semanal', verificarToken);

app.get('/api/session', verificarToken, (req, res) => res.json({ autenticado: true }));

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

app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

app.listen(PORT, '127.0.0.1', () => {
  console.log(`🚀 Painel rodando em http://127.0.0.1:${PORT}`);
});
