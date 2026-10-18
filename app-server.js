'use strict';

/**
 * Multi-OS SeedVault Offline Localhost Application Server (Hardened v3.0)
 *
 * Security & Inheritance Features:
 * - Strict Loopback Socket Verification (`127.0.0.1` / `::1` only)
 * - Cryptographic Anti-CSRF Session Token (`X-SeedVault-Token`)
 * - Server-Side Anti-Bot Multi-Game Gatekeeper (`gamePassToken` verified on `/api/unlock`)
 * - Offline Bitcoin HD Wallet Derivation & Transaction Signer (`/api/btc/derive`, `/api/btc/sign`)
 *   supporting dynamic 25th Passphrase overrides and Trezor/Ledger PSBT / USB WebHID Bridge
 */

const http = require('http');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { execFile } = require('child_process');
const { VaultStorageManager } = require('./vault-storage');
const { GameGuardModuleRegistry } = require('./game-module');
const {
  mnemonicToSeed,
  derivePath,
  deriveFromHardwarePublicKey,
  buildAndSignBitcoinTransaction,
  parseRawBitcoinTransaction,
  assembleSignedTransaction,
} = require('./bitcoin-signer');

const HOST = '127.0.0.1';
const DEFAULT_PORT = Number(process.env.SEEDVAULT_PORT) || 0;

function createSeedVaultServer(storageDir = __dirname) {
  const storage = new VaultStorageManager(storageDir);
  const gameRegistry = new GameGuardModuleRegistry();
  const uiDir = path.join(__dirname, 'ui');
  const instanceCsrfToken = crypto.randomBytes(32).toString('hex');

  const SECURITY_HEADERS = Object.freeze({
    'Cache-Control': 'no-store, no-cache, must-revalidate, private',
    Pragma: 'no-cache',
    'X-Content-Type-Options': 'nosniff',
    'X-Frame-Options': 'DENY',
    'Referrer-Policy': 'no-referrer',
    'Content-Security-Policy':
      "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self' https://mempool.space https://blockstream.info; frame-ancestors 'none';",
  });

  function sendJson(res, statusCode, payload) {
    const body = JSON.stringify(payload);
    res.writeHead(statusCode, {
      ...SECURITY_HEADERS,
      'Content-Type': 'application/json; charset=utf-8',
    });
    res.end(body);
  }

  function readJsonBody(req) {
    return new Promise((resolve, reject) => {
      let raw = '';
      req.on('data', (chunk) => {
        raw += chunk.toString('utf8');
        if (raw.length > 1024 * 128) {
          reject(new Error('Request payload too large'));
          req.destroy();
        }
      });
      req.on('end', () => {
        try {
          resolve(raw ? JSON.parse(raw) : {});
        } catch (_e) {
          reject(new Error('Invalid JSON payload'));
        }
      });
      req.on('error', reject);
    });
  }

  function verifyLoopbackAndCsrf(req, requireCsrf = true) {
    const remote = req.socket && req.socket.remoteAddress;
    if (remote && remote !== '127.0.0.1' && remote !== '::1' && remote !== '::ffff:127.0.0.1') {
      throw new Error('Forbidden: Non-loopback connection rejected');
    }

    if (requireCsrf) {
      const clientToken = req.headers['x-seedvault-token'] || '';
      const a = Buffer.from(String(clientToken), 'utf8');
      const b = Buffer.from(instanceCsrfToken, 'utf8');
      if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) {
        throw new Error('Security Error: Invalid or missing session token (กรุณารีเฟรชหน้าจอ)');
      }
    }
  }

  const server = http.createServer(async (req, res) => {
    try {
      verifyLoopbackAndCsrf(req, false);

      const urlObj = new URL(req.url, `http://${HOST}`);
      const pathname = urlObj.pathname;

      // Static UI Routes
      if (req.method === 'GET' && (pathname === '/' || pathname === '/index.html')) {
        let html = fs.readFileSync(path.join(uiDir, 'index.html'), 'utf8');
        html = html.replace(
          '</head>',
          `  <meta name="seedvault-token" content="${instanceCsrfToken}" />\n</head>`
        );
        res.writeHead(200, {
          ...SECURITY_HEADERS,
          'Content-Type': 'text/html; charset=utf-8',
        });
        return res.end(html);
      }

      if (req.method === 'GET' && pathname === '/styles.css') {
        const css = fs.readFileSync(path.join(uiDir, 'styles.css'), 'utf8');
        res.writeHead(200, {
          ...SECURITY_HEADERS,
          'Content-Type': 'text/css; charset=utf-8',
        });
        return res.end(css);
      }

      if (req.method === 'GET' && pathname === '/app.js') {
        const js = fs.readFileSync(path.join(uiDir, 'app.js'), 'utf8');
        res.writeHead(200, {
          ...SECURITY_HEADERS,
          'Content-Type': 'application/javascript; charset=utf-8',
        });
        return res.end(js);
      }

      // API Routes
      if (req.method === 'GET' && pathname === '/api/status') {
        const status = storage.getPublicStatus();
        return sendJson(res, 200, status);
      }

      if (req.method === 'POST' && pathname === '/api/setup') {
        verifyLoopbackAndCsrf(req, true);
        const body = await readJsonBody(req);
        const status = storage.initializeNewVault(body);
        return sendJson(res, 200, { ok: true, status });
      }

      if (req.method === 'POST' && pathname === '/api/unlock') {
        verifyLoopbackAndCsrf(req, true);
        const body = await readJsonBody(req);

        // Hard Server-Side Anti-Bot Game Gatekeeper Check:
        // If the vault has gameModule.enabled === true, require a valid gamePassToken
        const pubStatus = storage.getPublicStatus();
        if (pubStatus.initialized && pubStatus.gameModule && pubStatus.gameModule.enabled) {
          if (!gameRegistry.validateGamePassToken(body.gamePassToken)) {
            return sendJson(res, 403, {
              success: false,
              error: 'กรุณาเล่นด่านเกมส์ป้องกันบอทให้ผ่านครบทุกด่านก่อนกรอกรหัสผ่าน',
            });
          }
        }

        const result = storage.unlockVault(body);
        return sendJson(res, 200, result);
      }

      if (req.method === 'POST' && pathname === '/api/reset') {
        verifyLoopbackAndCsrf(req, true);
        const body = await readJsonBody(req);
        if (body.confirmToken !== 'RESET') {
          return sendJson(res, 400, {
            ok: false,
            error: 'กรุณายืนยันการรีเซ็ตด้วยคำว่า RESET',
          });
        }
        const resetResult = storage.secureWipeAndReset('User confirmed double-step reset');
        return sendJson(res, 200, { ok: true, ...resetResult });
      }

      // Game Module APIs (Supports multi-game pipeline)
      if (req.method === 'GET' && pathname === '/api/game/modules') {
        return sendJson(res, 200, { ok: true, modules: gameRegistry.listModules() });
      }

      if (req.method === 'POST' && pathname === '/api/game/start') {
        verifyLoopbackAndCsrf(req, true);
        const body = await readJsonBody(req);
        const session = gameRegistry.createChallengeSession(body);
        return sendJson(res, 200, { ok: true, session });
      }

      if (req.method === 'POST' && pathname === '/api/game/verify') {
        verifyLoopbackAndCsrf(req, true);
        const body = await readJsonBody(req);
        const verification = gameRegistry.verifyChallengeSession(body.sessionId, body.submission);
        return sendJson(res, 200, { ok: true, ...verification });
      }

      // Bitcoin HD Wallet & Transaction Signing APIs (24-Word Seed / Manual Seed / Direct Hardware USB)
      if (req.method === 'POST' && pathname === '/api/btc/derive') {
        verifyLoopbackAndCsrf(req, true);
        const body = await readJsonBody(req);
        const words = body.words || [];
        const passphrase25 = typeof body.passphrase25 === 'string' ? body.passphrase25 : '';
        const scriptType = body.scriptType || 'NATIVE_SEGWIT';
        const derivationPath = body.derivationPath || "m/84'/0'/0'/0/0";

        const seed = mnemonicToSeed(words, passphrase25);
        const derived = derivePath(seed, derivationPath, scriptType);
        seed.fill(0);
        derived.privateKey.fill(0);
        derived.tweakedPrivateKey.fill(0);

        return sendJson(res, 200, {
          ok: true,
          wallet: {
            path: derived.path,
            changePath: derived.changePath,
            changeAddress: derived.changeAddress,
            scanAddresses: derived.scanAddresses,
            scriptType: derived.scriptType,
            activeAddress: derived.activeAddress,
            masterFingerprint: derived.masterFingerprint,
            publicKeyHex: derived.publicKeyHex,
            taprootAddress: derived.taprootAddress,
            segwitAddress: derived.segwitAddress,
            nestedSegwitAddress: derived.nestedSegwitAddress,
            legacyAddress: derived.legacyAddress,
          },
        });
      }

      if (req.method === 'POST' && pathname === '/api/btc/hw-derive') {
        verifyLoopbackAndCsrf(req, true);
        const body = await readJsonBody(req);
        const wallet = deriveFromHardwarePublicKey({
          pubKeyHex: body.pubKeyHex || '',
          chainCodeHex: body.chainCodeHex || '',
          xpub: body.xpub || '',
          childPath: body.childPath || '',
          scriptType: body.scriptType || 'NATIVE_SEGWIT',
          derivationPath: body.derivationPath || "m/84'/0'/0'/0/0",
          masterFingerprint: body.masterFingerprint || 'HARDWARE',
        });
        return sendJson(res, 200, { ok: true, wallet });
      }

      if (req.method === 'POST' && pathname === '/api/btc/sign') {
        verifyLoopbackAndCsrf(req, true);
        const body = await readJsonBody(req);
        const txResult = buildAndSignBitcoinTransaction({
          words: body.words || [],
          passphrase25: typeof body.passphrase25 === 'string' ? body.passphrase25 : '',
          scriptType: body.scriptType || 'NATIVE_SEGWIT',
          derivationPath: body.derivationPath || "m/84'/0'/0'/0/0",
          senderAddress: body.senderAddress || '',
          inputs: body.inputs || [],
          outputs: body.outputs || [],
          signWithSeed: body.signWithSeed !== false,
        });
        return sendJson(res, 200, { ok: true, txResult });
      }

      if (req.method === 'POST' && pathname === '/api/btc/parse-rawtx') {
        verifyLoopbackAndCsrf(req, true);
        const body = await readJsonBody(req);
        const parsedTx = parseRawBitcoinTransaction(body.rawTxHex || '');
        return sendJson(res, 200, { ok: true, parsedTx });
      }

      if (req.method === 'POST' && pathname === '/api/btc/assemble-signed-tx') {
        verifyLoopbackAndCsrf(req, true);
        const body = await readJsonBody(req);
        const txResult = assembleSignedTransaction(body);
        return sendJson(res, 200, { ok: true, txResult });
      }

      return sendJson(res, 404, { ok: false, error: 'Not Found' });
    } catch (err) {
      return sendJson(res, 400, {
        ok: false,
        error: err.message || 'Internal Server Error',
      });
    }
  });

  return { server, storage, gameRegistry, instanceCsrfToken };
}

function launchNativeWindow(url) {
  if (process.env.SEEDVAULT_NO_BROWSER === '1') return;

  const platform = process.platform;
  if (platform === 'darwin') {
    execFile('open', [url], () => {});
  } else if (platform === 'win32') {
    execFile('cmd.exe', ['/c', 'start', '', url], () => {});
  } else {
    execFile('xdg-open', [url], (err) => {
      if (err) {
        execFile('firefox', [url], () => {});
      }
    });
  }
}

if (require.main === module) {
  const { server } = createSeedVaultServer(__dirname);
  server.listen(DEFAULT_PORT, HOST, () => {
    const addr = server.address();
    const url = `http://${HOST}:${addr.port}`;
    console.log('==============================================================');
    console.log(' 🔐 SeedVault Zero-Knowledge Vault & Bitcoin Signer (v3.0)');
    console.log(` 🌐 เปิดใช้งานที่: ${url}`);
    console.log(' 🖥️ รองรับ: Windows OS | macOS | Tails OS');
    console.log(' 🛑 กด Ctrl+C เพื่อปิดโปรแกรมเมื่อใช้งานเสร็จ');
    console.log('==============================================================');
    launchNativeWindow(url);
  });
}

module.exports = {
  createSeedVaultServer,
};
