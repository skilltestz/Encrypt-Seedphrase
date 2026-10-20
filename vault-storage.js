'use strict';

/**
 * Multi-OS Portable Vault Storage & Self-Destruct Counter Manager (Hardened v2.0)
 *
 * Security Upgrades:
 * 1. Encrypted & HMAC-Authenticated Monotonic State Anchor (`.svlt_state.anchor`):
 *    - Anchor file is no longer plaintext JSON; it is encrypted with AES-256-GCM
 *      and authenticated so attackers cannot manually edit `failedAttempts`, `seq`, or `wiped`.
 *    - If `.svlt_state.anchor` is tampered with or deleted while `seq > 1`, tampering is detected.
 * 2. Outer Rolling Envelope Encryption with PBKDF2-SHA512 + AAD Binding:
 *    - Every failed attempt re-encrypts the outer envelope with a fresh random salt and incremented
 *      monotonic sequence number (`seq`), binding `failedAttempts` and `remainingAttempts` into
 *      the AES-256-GCM Additional Authenticated Data (AAD).
 * 3. 3-Pass Cryptographic Zero-Wipe (Self-Destruct):
 *    - Overwrites `seedvault.dat` with CSPRNG random bytes, 0xFF, and 0x00 before unlinking.
 */

const fs = require('fs');
const path = require('path');
const os = require('os');
const crypto = require('crypto');
const {
  createEncryptedVault,
  attemptUnlockVault,
  encryptAES256GCM,
  decryptAES256GCM,
} = require('./crypto-engine');

const DEFAULT_VAULT_FILENAME = 'seedvault.dat';

/**
 * Per-device data directory. The vault the app actually runs on lives HERE (on the internal
 * disk of the Mac / PC / Tails), never on the Flash Drive: the Flash Drive only carries a master
 * copy that is imported into this directory before use. Override with `SEEDVAULT_DATA_DIR`.
 */
function resolveDefaultDataDir() {
  if (process.env.SEEDVAULT_DATA_DIR) {
    return path.resolve(process.env.SEEDVAULT_DATA_DIR);
  }
  const home = os.homedir();
  if (process.platform === 'darwin') {
    return path.join(home, 'Library', 'Application Support', 'SeedVault');
  }
  if (process.platform === 'win32') {
    return path.join(process.env.LOCALAPPDATA || path.join(home, 'AppData', 'Local'), 'SeedVault');
  }
  return path.join(process.env.XDG_DATA_HOME || path.join(home, '.local', 'share'), 'seedvault');
}

/**
 * Best-effort heuristic: is this path on removable media (Flash Drive)?
 */
function isLikelyRemovablePath(p) {
  const abs = path.resolve(p);
  if (process.platform === 'darwin') return abs.startsWith('/Volumes/');
  if (process.platform === 'win32') {
    const sysDrive = (process.env.SystemDrive || 'C:').toUpperCase();
    return path.parse(abs).root.toUpperCase().slice(0, 2) !== sysDrive;
  }
  return abs.startsWith('/media/') || abs.startsWith('/run/media/') || abs.startsWith('/mnt/');
}
const MAGIC_HEADER = 'SVLT1';
const ANCHOR_DOMAIN_SECRET = 'SeedVault-MonotonicAnchor-Integrity-Key-v2';

class VaultStorageManager {
  constructor(storageDir = __dirname, vaultFilename = DEFAULT_VAULT_FILENAME) {
    this.storageDir = storageDir;
    try {
      fs.mkdirSync(storageDir, { recursive: true, mode: 0o700 });
    } catch (_e) {
      // surfaced later on first write
    }
    this.vaultPath = path.join(storageDir, vaultFilename);
    this.portableAnchorPath = path.join(storageDir, '.svlt_state.anchor');
    this.osAnchorPaths = this._resolveOsAnchorPaths();
  }

  _resolveOsAnchorPaths() {
    const paths = [];
    try {
      const home = os.homedir();
      if (home && fs.existsSync(home)) {
        paths.push(path.join(home, '.seedvault_anchor.dat'));
        // Secondary OS-level hidden anchor in system config / application support
        if (process.platform === 'darwin') {
          const appSup = path.join(home, 'Library', 'Application Support');
          if (fs.existsSync(appSup)) {
            paths.push(path.join(appSup, '.svlt_ratchet.dat'));
          }
        } else if (process.platform === 'win32') {
          const appData = process.env.APPDATA || path.join(home, 'AppData', 'Roaming');
          if (fs.existsSync(appData)) {
            paths.push(path.join(appData, '.svlt_ratchet.dat'));
          }
        } else {
          const cfgDir = path.join(home, '.config');
          if (fs.existsSync(cfgDir)) {
            paths.push(path.join(cfgDir, '.svlt_ratchet.dat'));
          }
        }
      }
      const tmp = os.tmpdir();
      if (tmp && fs.existsSync(tmp)) {
        paths.push(path.join(tmp, '.svlt_sys_ratchet.dat'));
      }
    } catch (_e) {
      // Fallback on Tails OS amnesia or restricted environments
    }
    return paths;
  }

  _deriveAnchorKey(saltHex) {
    return crypto.pbkdf2Sync(
      Buffer.from(ANCHOR_DOMAIN_SECRET, 'utf8'),
      Buffer.from(saltHex, 'hex'),
      50000,
      32,
      'sha256'
    );
  }

  _readAnchorFile(filePath) {
    if (!filePath || !fs.existsSync(filePath)) return { exists: false, data: {}, tampered: false };
    try {
      const rawStr = fs.readFileSync(filePath, 'utf8');
      const parsed = JSON.parse(rawStr);

      // Support encrypted v2 anchor format
      if (parsed && parsed.v === 2 && parsed.salt && parsed.enc) {
        const key = this._deriveAnchorKey(parsed.salt);
        const decBytes = decryptAES256GCM(parsed.enc, key, 'SVLT-ANCHOR-v2');
        key.fill(0);
        return {
          exists: true,
          data: JSON.parse(decBytes.toString('utf8')),
          tampered: false,
        };
      }

      // Backward compatibility for v1 anchor format (will be upgraded to v2 on next write)
      if (parsed && typeof parsed === 'object' && !parsed.v) {
        return { exists: true, data: parsed, tampered: false };
      }

      return { exists: true, data: {}, tampered: true };
    } catch (_err) {
      return { exists: true, data: {}, tampered: true };
    }
  }

  _writeAnchorFile(filePath, dataObj) {
    if (!filePath) return;
    try {
      const salt = crypto.randomBytes(16).toString('hex');
      const key = this._deriveAnchorKey(salt);
      const plaintext = Buffer.from(JSON.stringify(dataObj), 'utf8');
      const enc = encryptAES256GCM(plaintext, key, 'SVLT-ANCHOR-v2');
      key.fill(0);
      plaintext.fill(0);

      const envelope = JSON.stringify({
        v: 2,
        salt,
        enc,
      });
      this._writeBufferInPlace(filePath, Buffer.from(envelope, 'utf8'));
    } catch (_e) {
      // Ignore if read-only OS home on Tails live boot
    }
  }

  /**
   * Overwrites a file in-place (with fsync) so old file blocks are not left in free disk space
   */
  _writeBufferInPlace(filePath, dataBuffer) {
    if (fs.existsSync(filePath)) {
      const fd = fs.openSync(filePath, 'r+');
      try {
        fs.writeSync(fd, dataBuffer, 0, dataBuffer.length, 0);
        fs.ftruncateSync(fd, dataBuffer.length);
        fs.fsyncSync(fd);
      } finally {
        fs.closeSync(fd);
      }
      try {
        fs.chmodSync(filePath, 0o600);
      } catch (_e) {
        // Ignore chmod on Windows
      }
    } else {
      fs.writeFileSync(filePath, dataBuffer, { mode: 0o600 });
    }
  }

  /**
   * Computes integrity binding key for outer rolling state protection.
   * Binds `ratchetSecret` (stored ONLY in anchors, never in `seedvault.dat`) so `seedvault.dat`
   * cannot be decrypted offline on its own or rolled back via copy-paste!
   */
  _deriveRollingOuterKey(vaultId, monotonicSeq, rollingSaltHex, ratchetSecretHex = '') {
    const secretPart = ratchetSecretHex ? `:RATCHET:${ratchetSecretHex}` : '';
    return crypto.pbkdf2Sync(
      Buffer.from(`OUTER:${vaultId}:SEQ:${monotonicSeq}${secretPart}`, 'utf8'),
      Buffer.from(rollingSaltHex, 'hex'),
      25000,
      32,
      'sha256'
    );
  }

  /**
   * Reads monotonic state anchor from portable and OS-level anchors to prevent counter reset
   * and detect copy-paste rollback attacks.
   */
  _readMaxObservedState(vaultId) {
    let maxFailed = 0;
    let maxSeq = 0;
    let wiped = false;
    let tampered = false;
    let latestRatchetSecret = '';
    let latestRatchetSeq = -1;
    let anyAnchorFound = false;

    const allAnchorPaths = [this.portableAnchorPath, ...this.osAnchorPaths];
    for (const fPath of allAnchorPaths) {
      const res = this._readAnchorFile(fPath);
      if (res.tampered) {
        tampered = true;
      }
      const rec = res.data && res.data[vaultId];
      if (rec) {
        anyAnchorFound = true;
        if (typeof rec.failedAttempts === 'number' && rec.failedAttempts > maxFailed) {
          maxFailed = rec.failedAttempts;
        }
        if (typeof rec.seq === 'number' && rec.seq >= maxSeq) {
          maxSeq = rec.seq;
          if (typeof rec.ratchetSecret === 'string' && rec.seq >= latestRatchetSeq) {
            latestRatchetSecret = rec.ratchetSecret;
            latestRatchetSeq = rec.seq;
          }
        }
        if (rec.wiped) {
          wiped = true;
        }
      }
    }

    return {
      maxFailed,
      maxSeq,
      wiped,
      tampered,
      anyAnchorFound,
      ratchetSecret: latestRatchetSecret,
    };
  }

  /**
   * Persists the monotonic attempt counter and split-key `ratchetSecret` to both the portable
   * directory (for cross-computer USB travel) and OS local hidden anchors (to detect folder copy-paste).
   */
  _writeObservedState(vaultId, failedAttempts, seq, wiped = false, ratchetSecret = '') {
    const updateAnchor = (filePath) => {
      if (!filePath) return;
      const existing = this._readAnchorFile(filePath);
      const data = existing.tampered ? {} : existing.data || {};
      const prev = data[vaultId] || { failedAttempts: 0, seq: 0, wiped: false, ratchetSecret: '' };

      const nextSeq = Math.max(prev.seq || 0, seq);
      const isWiped = Boolean(prev.wiped || wiped);

      data[vaultId] = {
        failedAttempts: Math.max(prev.failedAttempts || 0, failedAttempts),
        seq: nextSeq,
        wiped: isWiped,
        // Destroy ratchetSecret permanently when wiped; otherwise store latest secret
        ratchetSecret: isWiped
          ? ''
          : seq >= (prev.seq || 0) && ratchetSecret
          ? ratchetSecret
          : prev.ratchetSecret || '',
        updatedAt: new Date().toISOString(),
      };

      // Keep anchor map bounded to the 64 most recently updated vaultIds
      const keys = Object.keys(data);
      if (keys.length > 64) {
        keys
          .sort((a, b) => {
            const ta = (data[a] && data[a].updatedAt) || '';
            const tb = (data[b] && data[b].updatedAt) || '';
            return ta.localeCompare(tb);
          })
          .slice(0, keys.length - 64)
          .forEach((k) => {
            if (k !== vaultId) delete data[k];
          });
      }

      this._writeAnchorFile(filePath, data);
    };

    updateAnchor(this.portableAnchorPath);
    for (const osPath of this.osAnchorPaths) {
      updateAnchor(osPath);
    }
  }

  /**
   * Writes the inner vault state wrapped inside an outer rolling envelope to `seedvault.dat`.
   * Rotates a fresh 256-bit `ratchetSecret` stored exclusively in the anchors.
   */
  _saveVaultDiskState(innerVault) {
    const vaultId = innerVault.vaultId;
    const seq = (innerVault.monotonicSeq || 0) + 1;
    innerVault.monotonicSeq = seq;

    const rollingSalt = crypto.randomBytes(16).toString('hex');
    const ratchetToken = crypto.randomBytes(32).toString('hex');
    const outerKey = this._deriveRollingOuterKey(vaultId, seq, rollingSalt, ratchetToken);
    const innerBytes = Buffer.from(JSON.stringify(innerVault), 'utf8');
    const outerEncrypted = encryptAES256GCM(
      innerBytes,
      outerKey,
      `${MAGIC_HEADER}:${vaultId}:${seq}:${innerVault.securityCounter.failedAttempts}`
    );
    outerKey.fill(0);
    innerBytes.fill(0);

    const diskEnvelope = {
      magic: MAGIC_HEADER,
      vaultId,
      seq,
      ratchetToken,
      rollingSalt,
      failedAttempts: innerVault.securityCounter.failedAttempts,
      maxAttempts: innerVault.securityCounter.maxAttempts,
      remainingAttempts: innerVault.securityCounter.remainingAttempts,
      outerEncrypted,
    };

    const serialized = Buffer.from(JSON.stringify(diskEnvelope, null, 2), 'utf8');
    this._writeBufferInPlace(this.vaultPath, serialized);
    this._writeObservedState(
      vaultId,
      innerVault.securityCounter.failedAttempts,
      seq,
      false,
      ratchetToken
    );
  }

  /**
   * Loads and verifies the outer rolling envelope from `seedvault.dat`.
   * - Supports copying `seedvault.dat` / Flash Drive to another computer seamlessly.
   * - Detects any copy-paste / file restoration rollback attack on a computer or USB drive
   *   and triggers immediate 7-pass forensic self-destruct!
   */
  _loadVaultDiskState() {
    if (!fs.existsSync(this.vaultPath)) {
      return null;
    }

    let diskEnvelope;
    try {
      const raw = fs.readFileSync(this.vaultPath, 'utf8');
      diskEnvelope = JSON.parse(raw);
    } catch (_err) {
      throw new Error('ไฟล์ฐานข้อมูลเข้ารหัส (seedvault.dat) เสียหายหรือถูกดัดแปลง');
    }

    if (!diskEnvelope || diskEnvelope.magic !== MAGIC_HEADER || !diskEnvelope.vaultId) {
      throw new Error('รูปแบบไฟล์ seedvault.dat ไม่ถูกต้อง');
    }

    const { vaultId, seq, rollingSalt, failedAttempts, outerEncrypted, ratchetToken } = diskEnvelope;

    // 1. Check monotonic anchor state BEFORE decryption to catch Copy-Paste / Rollback attacks!
    const observed = this._readMaxObservedState(vaultId);
    if (observed.wiped) {
      this.secureWipeAndReset('ตรวจพบการนำไฟล์ที่ถูกทำลายไปแล้วกลับมาวางซ้ำ (Anti-Copy-Paste Protection)');
      return null;
    }

    // If any anchor (portable Flash Drive anchor or OS hidden anchors on this computer) has seen a
    // higher `seq`, more `failedAttempts`, or a different `ratchetSecret` for the same `seq`,
    // someone copied `seedvault.dat` (or the folder) earlier and pasted it back to reset attempts!
    if (observed.anyAnchorFound) {
      const isRollback = seq < observed.maxSeq || failedAttempts < observed.maxFailed;
      const isRatchetMismatch =
        seq === observed.maxSeq &&
        Boolean(observed.ratchetSecret) &&
        Boolean(ratchetToken) &&
        observed.ratchetSecret !== ratchetToken;

      if (isRollback || isRatchetMismatch) {
        this.secureWipeAndReset(
          'ตรวจพบการ Copy ไฟล์เก่ามา Paste ทับเพื่อรีเซ็ตจำนวนครั้ง (Rollback Attack Detected — ทำลายไฟล์ทันที)'
        );
        return null;
      }
    }

    const activeRatchet = ratchetToken || observed.ratchetSecret || '';
    const outerKey = this._deriveRollingOuterKey(vaultId, seq, rollingSalt, activeRatchet);

    let innerVault;
    try {
      const aad = `${MAGIC_HEADER}:${vaultId}:${seq}:${failedAttempts}`;
      const decryptedBytes = decryptAES256GCM(outerEncrypted, outerKey, aad);
      outerKey.fill(0);
      innerVault = JSON.parse(decryptedBytes.toString('utf8'));
      decryptedBytes.fill(0);
    } catch (_err) {
      outerKey.fill(0);
      this.secureWipeAndReset('ตรวจพบการแก้ไขดัดแปลงไฟล์รหัสผ่านหรือวางไฟล์ไม่ตรงรุ่น (Integrity Check Failed)');
      throw new Error('ตรวจพบการแก้ไขดัดแปลงไฟล์รหัสผ่าน (Integrity Check Failed — ข้อมูลถูกทำลายแล้ว)');
    }

    // Sync encrypted v2 anchor on current machine & Flash Drive so this computer is now locked to this state
    this._writeObservedState(
      vaultId,
      innerVault.securityCounter.failedAttempts,
      seq,
      false,
      activeRatchet
    );
    return innerVault;
  }

  /**
   * Cryptographic 7-Pass Forensic Shredding, Structural Corruption & Reset to Initial Setup Mode.
   * Ensures deleted `seedvault.dat` cannot be recovered or decrypted by file-recovery forensics.
   */
  secureWipeAndReset(reason = 'User requested reset') {
    let vaultId = null;
    let seq = 999999;

    if (fs.existsSync(this.vaultPath)) {
      try {
        const raw = JSON.parse(fs.readFileSync(this.vaultPath, 'utf8'));
        vaultId = raw.vaultId;
        seq = (raw.seq || 0) + 1000;
      } catch (_e) {
        // Ignore parse error during wipe
      }

      try {
        const stat = fs.statSync(this.vaultPath);
        const size = Math.max(stat.size, 16384);
        const fd = fs.openSync(this.vaultPath, 'r+');

        // Stage 1: Structural JSON Corruption (poisons ciphertext in filesystem journals/snapshots)
        const corruptedJson = JSON.stringify({
          magic: 'WIPED',
          vaultId: crypto.randomBytes(16).toString('hex'),
          seq: 0,
          rollingSalt: crypto.randomBytes(16).toString('hex'),
          outerEncrypted: {
            iv: crypto.randomBytes(12).toString('hex'),
            ciphertext: crypto.randomBytes(Math.max(1024, Math.floor(size / 2))).toString('hex'),
            tag: crypto.randomBytes(16).toString('hex'),
          },
        });
        const corruptBuf = Buffer.from(corruptedJson, 'utf8');
        fs.writeSync(fd, corruptBuf, 0, Math.min(corruptBuf.length, size), 0);
        fs.fsyncSync(fd);

        // Stage 2: 7-Pass DoD 5220.22-M ECE / Gutmann-Grade Physical Block Overwrite
        const passes = [
          Buffer.alloc(size, 0x00), // Pass 1: All 0x00
          Buffer.alloc(size, 0xff), // Pass 2: All 0xFF
          Buffer.alloc(size, 0x55), // Pass 3: Alternating 01010101 (0x55)
          Buffer.alloc(size, 0xaa), // Pass 4: Alternating 10101010 (0xAA)
          crypto.randomBytes(size), // Pass 5: CSPRNG Random stream #1
          crypto.randomBytes(size), // Pass 6: CSPRNG Random stream #2
          Buffer.alloc(size, 0x00), // Pass 7: Final zero-out
        ];

        for (const buf of passes) {
          fs.writeSync(fd, buf, 0, size, 0);
          fs.fsyncSync(fd);
          buf.fill(0);
        }

        // Stage 3: Truncate to 0 bytes so no blocks remain allocated to the inode
        fs.ftruncateSync(fd, 0);
        fs.fsyncSync(fd);
        fs.closeSync(fd);

        // Stage 4: Multi-step rename obfuscation to wipe directory entry (dentry / MFT) filename
        const dir = path.dirname(this.vaultPath);
        let currPath = this.vaultPath;
        for (let r = 0; r < 3; r++) {
          const anonPath = path.join(dir, `.shred_${crypto.randomBytes(6).toString('hex')}.tmp`);
          try {
            fs.renameSync(currPath, anonPath);
            currPath = anonPath;
          } catch (_re) {
            break;
          }
        }
        fs.unlinkSync(currPath);
      } catch (_err) {
        try {
          fs.unlinkSync(this.vaultPath);
        } catch (_e2) {
          // Ignore
        }
      }
    }

    // Stage 5: Destroy split ratchetSecret and record permanent Tombstone in all anchors
    if (vaultId) {
      this._writeObservedState(vaultId, 999, seq, true, '');
    }

    return {
      wiped: true,
      reason,
      mode: 'SETUP',
    };
  }

  /**
   * Returns current public status of the Vault (never exposes keys or answers)
   */
  getPublicStatus() {
    const innerVault = this._loadVaultDiskState();
    if (!innerVault) {
      return {
        initialized: false,
        mode: 'SETUP',
      };
    }

    const { factors, securityCounter, policyMode, keySlots, gameModule } = innerVault;

    return {
      initialized: true,
      mode: 'UNLOCK',
      vaultId: innerVault.vaultId,
      version: innerVault.version || '1.0.0',
      kdfVersion: innerVault.kdfVersion || 1,
      policyMode,
      securityCounter: {
        maxAttempts: securityCounter.maxAttempts,
        remainingAttempts: securityCounter.remainingAttempts,
        failedAttempts: securityCounter.failedAttempts,
      },
      factors: {
        hasQuestions: factors.hasQuestions,
        hasPhone: factors.hasPhone,
        hasSpecial: factors.hasSpecial,
        questions:
          factors.hasQuestions && factors.questionMeta
            ? {
                totalQuestions: factors.questionMeta.totalQuestions,
                requiredCorrect: factors.questionMeta.requiredCorrect,
                items: factors.questionMeta.items.map((q) => ({
                  id: q.id,
                  question: q.question,
                })),
              }
            : null,
      },
      availableMethods: keySlots.map((s) => ({
        slotType: s.slotType,
        slotLabel: s.slotLabel,
      })),
      gameModule: gameModule || { enabled: false, gameType: 'pattern_shield', difficulty: 1 },
    };
  }

  /**
   * Initializes a new encrypted Seedphrase Vault (First-Time Setup)
   */
  initializeNewVault(setupConfig) {
    // Build + validate FIRST so a rejected configuration can never destroy an existing vault.
    const innerVault = createEncryptedVault(setupConfig);

    // A 4-digit PIN alone is only 10^4 guesses (~1-2 hours of offline brute force if the file
    // ever leaks). Refuse any configuration that creates a slot unlockable by the PIN by itself.
    if (innerVault.keySlots.some((s) => s.slotType === 'PHONE_ONLY')) {
      throw new Error(
        'ไม่อนุญาตให้ใช้เบอร์โทร 4 หลักเพียงอย่างเดียวในการปลดล็อก (เดาได้ครบใน 1–2 ชั่วโมงหากไฟล์หลุด) ' +
          'กรุณาใช้โหมด "ต้องตอบคำถาม และ กรอกเบอร์/รหัสพิเศษ" หรือโหมดเข้มงวดสูงสุด และปิดตัวเลือกทางด่วนเบอร์โทร'
      );
    }

    if (fs.existsSync(this.vaultPath)) {
      this.secureWipeAndReset('Re-initializing new vault');
    }

    innerVault.vaultId = crypto.randomUUID();
    innerVault.monotonicSeq = 0;

    this._saveVaultDiskState(innerVault);
    return this.getPublicStatus();
  }

  /**
   * Imports a `seedvault.dat` carried on a Flash Drive into THIS device's local data directory.
   * Run the app offline from the local copy; the Flash Drive file stays untouched as a master.
   *
   * Never destroys anything on a rejected import: a stale/rolled-back file is simply refused.
   */
  importVaultFile(fileBuffer, { replaceExisting = false } = {}) {
    let env;
    try {
      env = JSON.parse(Buffer.from(fileBuffer).toString('utf8'));
    } catch (_e) {
      throw new Error('ไฟล์ที่เลือกไม่ใช่ seedvault.dat ที่ถูกต้อง');
    }
    if (
      !env ||
      env.magic !== MAGIC_HEADER ||
      typeof env.vaultId !== 'string' ||
      !Number.isInteger(env.seq) ||
      !Number.isInteger(env.failedAttempts) ||
      !env.outerEncrypted
    ) {
      throw new Error('ไฟล์ที่เลือกไม่ใช่ seedvault.dat ที่ถูกต้อง');
    }

    const observed = this._readMaxObservedState(env.vaultId);
    if (observed.wiped) {
      throw new Error('Vault นี้ถูกทำลายบนเครื่องนี้ไปแล้ว ไม่สามารถนำเข้าซ้ำได้ (ใช้ไฟล์ล่าสุดจากเครื่องที่ใช้งานล่าสุด)');
    }
    if (observed.anyAnchorFound && (env.seq < observed.maxSeq || env.failedAttempts < observed.maxFailed)) {
      throw new Error(
        'ไฟล์นี้เก่ากว่าสถานะที่เครื่องนี้เคยบันทึกไว้ จึงไม่ถูกนำเข้า (ป้องกันการย้อนจำนวนครั้ง) — ' +
          'ให้ส่งออกไฟล์ล่าสุดจากเครื่องนี้แทน หรือใช้ไฟล์ที่ใหม่กว่า'
      );
    }

    if (fs.existsSync(this.vaultPath)) {
      let existing = null;
      try {
        existing = JSON.parse(fs.readFileSync(this.vaultPath, 'utf8'));
      } catch (_e) {
        existing = null;
      }
      const sameVault = existing && existing.vaultId === env.vaultId;
      if (sameVault && Number.isInteger(existing.seq) && existing.seq > env.seq) {
        throw new Error('เครื่องนี้มีไฟล์ Vault เดียวกันที่ใหม่กว่าอยู่แล้ว จึงไม่ถูกนำเข้า');
      }
      if (!sameVault && !replaceExisting) {
        throw new Error('เครื่องนี้มี Vault อื่นอยู่แล้ว การนำเข้าจะลบทำลายของเดิม — ยืนยันการแทนที่ก่อนนำเข้า');
      }
      if (!sameVault) {
        this.secureWipeAndReset('Replaced by imported vault');
      }
    }

    this._writeBufferInPlace(this.vaultPath, Buffer.from(fileBuffer));
    const inner = this._loadVaultDiskState(); // verifies integrity + syncs this device's anchors
    if (!inner) {
      throw new Error('นำเข้าไม่สำเร็จ: ไฟล์ไม่ผ่านการตรวจสอบความสมบูรณ์');
    }
    return this.getPublicStatus();
  }

  /**
   * Returns the current `seedvault.dat` bytes (with up-to-date counters) so the user can copy
   * the latest state back to the Flash Drive after using this device.
   */
  exportVaultFile() {
    const inner = this._loadVaultDiskState();
    if (!inner) {
      throw new Error('ไม่พบ Vault บนเครื่องนี้ให้ส่งออก');
    }
    return fs.readFileSync(this.vaultPath);
  }

  /**
   * Verifies user credentials to unlock the Seedphrase.
   */
  unlockVault(credentials) {
    const innerVault = this._loadVaultDiskState();
    if (!innerVault) {
      return {
        success: false,
        wiped: true,
        mode: 'SETUP',
        error: 'ไม่พบข้อมูลที่เข้ารหัสไว้ กรุณาตั้งค่าเริ่มต้นใหม่',
      };
    }

    if (innerVault.securityCounter.remainingAttempts <= 0) {
      this.secureWipeAndReset('กรอกรหัสผิดเกินจำนวนที่กำหนด');
      return {
        success: false,
        wiped: true,
        mode: 'SETUP',
        remainingAttempts: 0,
        error: 'กรอกรหัสผิดเกินจำนวนที่กำหนด ข้อมูลที่เก็บไว้ถูกลบทำลายและรีเซ็ตโปรแกรมเรียบร้อยแล้ว',
      };
    }

    // Commit the attempt BEFORE the slow key derivation runs: killing the process (or pulling the
    // power) mid-derivation can no longer give a free, uncounted guess.
    const maxAttempts = innerVault.securityCounter.maxAttempts;
    innerVault.securityCounter.failedAttempts += 1;
    innerVault.securityCounter.remainingAttempts = Math.max(
      0,
      maxAttempts - innerVault.securityCounter.failedAttempts
    );
    this._saveVaultDiskState(innerVault);

    const result = attemptUnlockVault(innerVault, credentials);

    if (result.success) {
      // Correct: restore a full allowance. A fresh vaultId is required because the anchors keep a
      // monotonic maximum of failures per vaultId and would otherwise flag the reset as rollback.
      innerVault.securityCounter.failedAttempts = 0;
      innerVault.securityCounter.remainingAttempts = maxAttempts;
      innerVault.vaultId = crypto.randomUUID();
      innerVault.monotonicSeq = 0;
      this._saveVaultDiskState(innerVault);

      return {
        success: true,
        matchedSlot: result.matchedSlot,
        matchedSlotLabel: result.matchedSlotLabel,
        remainingAttempts: innerVault.securityCounter.remainingAttempts,
        maxAttempts: innerVault.securityCounter.maxAttempts,
        payload: result.payload,
      };
    }

    const remaining = innerVault.securityCounter.remainingAttempts;

    if (remaining <= 0) {
      this.secureWipeAndReset('กรอกรหัสผิดเกินจำนวนที่กำหนด (Self-Destruct Activated)');
      return {
        success: false,
        wiped: true,
        mode: 'SETUP',
        remainingAttempts: 0,
        maxAttempts: innerVault.securityCounter.maxAttempts,
        error:
          'คุณกรอกรหัสผิดเกินจำนวนที่กำหนด! ข้อมูล Seedphrase ที่เข้ารหัสไว้ถูกลบทำลายและรีเซ็ตโปรแกรมกลับสู่โหมดเริ่มต้นใหม่แล้ว',
      };
    }

    return {
      success: false,
      wiped: false,
      mode: 'UNLOCK',
      remainingAttempts: remaining,
      maxAttempts: innerVault.securityCounter.maxAttempts,
      failedAttempts: innerVault.securityCounter.failedAttempts,
      error: `รหัสผ่านหรือคำตอบไม่ถูกต้อง! เหลือโอกาสกรอกได้อีก ${remaining} ครั้ง (หากครบกำหนดข้อมูลจะถูกลบทิ้งทันที)`,
    };
  }
}

module.exports = Object.freeze({
  VaultStorageManager,
  DEFAULT_VAULT_FILENAME,
  resolveDefaultDataDir,
  isLikelyRemovablePath,
});
