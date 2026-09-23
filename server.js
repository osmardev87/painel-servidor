const express = require('express');
const si = require('systeminformation');
const { Pool } = require('pg');
const { exec } = require('child_process');
const cors = require('cors');
const jwt = require('jsonwebtoken');
const path = require('path');
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 3001;

// ========== CONFIGURAÇÕES ==========
const AUTH_USER = process.env.PANEL_USER || 'gomes';
const AUTH_PASS = process.env.PANEL_PASS;
const JWT_SECRET = process.env.JWT_SECRET || 'chave_secreta_mude_isso!@#';

// ========== MIDDLEWARES ==========
app.use(cors({ origin: true, credentials: true }));
app.use(express.json());

// Serve o index.html na raiz — funciona com qualquer configuração do Nginx
app.use(express.static(path.join(__dirname, 'public')));

// ========== BANCO DE DADOS ==========
const pool = new Pool({
  host: process.env.DB_HOST || 'localhost',
  port: process.env.DB_PORT || 5432,
  user: process.env.DB_USER || 'gomes',
  password: process.env.DB_PASSWORD || 'gomes123',
  database: process.env.DB_NAME || 'postgres',
  max: 8,
  min: 2,
  connectionTimeoutMillis: 2000,
  idleTimeoutMillis: 10000,
});

pool.on('error', (err) => console.error('Erro no pool PostgreSQL:', err));

// ========== MIDDLEWARE DE AUTENTICAÇÃO ==========
function verificarToken(req, res, next) {
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({ erro: 'Não autenticado' });
  }
  try {
    jwt.verify(authHeader.split(' ')[1], JWT_SECRET);
    next();
  } catch {
    return res.status(401).json({ erro: 'Token inválido' });
  }
}

// ========== ROTA DE LOGIN — SEMPRE ACESSÍVEL ==========
app.post('/api/login', (req, res) => {
  console.log('📨 Requisição de login recebida');
  const { usuario, senha } = req.body;
  
  if (!usuario || !senha) {
    return res.status(400).json({ sucesso: false, mensagem: 'Usuário e senha obrigatórios' });
  }

  if (usuario === AUTH_USER && senha === AUTH_PASS) {
    const token = jwt.sign({ usuario }, JWT_SECRET, { expiresIn: '8h' });
    console.log('✅ Login bem-sucedido:', usuario);
    return res.json({ sucesso: true, token });
  }
  
  console.log('❌ Falha no login — usuário ou senha incorretos');
  res.status(401).json({ sucesso: false, mensagem: 'Usuário ou senha incorretos' });
});

// ========== ROTAS PROTEGIDAS ==========
app.use('/api/consumo', verificarToken);
app.use('/api/pg', verificarToken);
app.use('/api/docker', verificarToken);
app.use('/api/pgadmin', verificarToken);

app.get('/api/consumo', async (req, res) => {
  try {
    const [cpu, mem, disco] = await Promise.all([si.currentLoad(), si.mem(), si.fsSize()]);
    const mainDisk = disco[0] || { used: 0, size: 58 * 1024 ** 3, available: 0 };
    res.json({
      cpu: cpu.currentLoad?.toFixed(1) || '0.0',
      ramUsada: ((mem.used / mem.total) * 100).toFixed(1),
      ramTotalGB: (mem.total / 1024 ** 3).toFixed(1),
      ramLivreGB: (mem.available / 1024 ** 3).toFixed(1),
      discoUsado: ((mainDisk.used / mainDisk.size) * 100).toFixed(1),
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
    const client = await pool.connect();
    try {
      const total = await client.query(`SELECT pg_size_pretty(sum(pg_database_size(datname))) as total FROM pg_database WHERE datistemplate = false`);
      const conexoes = await client.query(`SELECT count(*) as total FROM pg_stat_activity`);
      res.json({ 
        total: total.rows[0]?.total || '0 MB', 
        conexoes: parseInt(conexoes.rows[0]?.total || 0) 
      });
    } finally { client.release(); }
  } catch (erro) {
    console.error('Erro em /api/pg/geral:', erro.message);
    res.status(503).json({ total: 'Indisponível', conexoes: 0 });
  }
});

app.get('/api/docker', (req, res) => {
  const composePath = process.env.DOCKER_COMPOSE_PATH || '/root/DB';
  exec(`cd ${composePath} && docker compose ps --format json 2>/dev/null`, (err, stdout) => {
    if (!err && stdout.trim()) {
      try {
        const containers = stdout.trim().startsWith('[') 
          ? JSON.parse(stdout) 
          : stdout.trim().split('\n').map(JSON.parse);
        return res.json(containers.map(c => ({ 
          Name: c.Name || c.Names, 
          State: c.State || c.Status 
        })));
      } catch (parseErr) {
        console.error('Erro ao parsear JSON do Docker:', parseErr);
      }
    }
    exec('docker ps --format "{{.Names}}|{{.Status}}"', (e, out) => {
      if (e || !out.trim()) return res.json([]);
      res.json(out.trim().split('\n').map(l => {
        const [name, status] = l.split('|');
        return { 
          Name: name, 
          State: status?.toLowerCase().includes('up') ? 'running' : 'stopped' 
        };
      }));
    });
  });
});

app.get('/api/pgadmin/status', (req, res) => {
  exec('docker inspect -f "{{.State.Running}}" pgadmin_web 2>/dev/null', (err, stdout) => {
    res.json({ running: !err && stdout.trim() === 'true' });
  });
});

app.post('/api/pgadmin/start', (req, res) => {
  exec('docker start pgadmin_web', (err) => {
    res.json({ ok: !err, msg: err ? 'Erro ao ligar' : '✅ pgAdmin ligado!' });
  });
});

app.post('/api/pgadmin/stop', (req, res) => {
  exec('docker stop pgadmin_web', (err) => {
    res.json({ ok: !err, msg: err ? 'Erro ao desligar' : '✅ pgAdmin desligado!' });
  });
});

// Fallback: qualquer rota desconhecida → serve o index.html
app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

app.listen(PORT, '127.0.0.1', () => {
  console.log(`🚀 Painel rodando em http://127.0.0.1:${PORT}`);
  console.log(`🔐 Login ativado — ${new Date().toLocaleString('pt-BR')}`);
  console.log(`📂 Pasta pública: ${path.join(__dirname, 'public')}`);
});