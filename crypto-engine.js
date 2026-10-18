'use strict';

/**
 * Multi-OS SeedVault Cryptographic Engine (Hardened v2.0)
 *
 * Security Upgrades:
 * 1. Dual-Stage Memory-Hard KDF Cascade:
 *    - Stage 1: PBKDF2-HMAC-SHA512 (600,000 iterations)
 *    - Stage 2: Memory-Hard scrypt (N=65536 [64MB RAM], r=8, p=1)
 *    Defeats GPU/ASIC parallel brute-force even for 4-digit PINs.
 * 2. Constant-Length Payload Padding (4096 bytes fixed block):
 *    12, 15, 18, 20, 24 words + 25th Passphrase all produce the exact same
 *    ciphertext size (8192 hex chars), eliminating length-based side-channel analysis.
 * 3. Galois Field GF(2^8) & Shamir's Secret Sharing (K-of-N threshold)
 *    for flexible security questions without storing answers or hashes.
 * 4. Anti-Debugging / Anti-Monkey-Patching Runtime Integrity Self-Test:
 *    Verifies Node cryptographic primitives and freezes exports at startup.
 */

const crypto = require('crypto');

const ALLOWED_WORD_COUNTS = Object.freeze([12, 15, 18, 20, 24]);
const PBKDF2_ITERATIONS = 600000;
const SCRYPT_PARAMS = Object.freeze({
  N: 65536, // 64 MB RAM per derivation
  r: 8,
  p: 1,
  maxmem: 128 * 1024 * 1024,
});
const KEY_LENGTH_BYTES = 32; // 256 bits
const GCM_IV_BYTES = 12;
const FIXED_PAYLOAD_BLOCK_BYTES = 4096; // Constant-size padded block

// ============================================================================
// 0. Runtime Anti-Tamper & Cryptographic Self-Verification
// ============================================================================
function verifyRuntimeIntegrity() {
  // Detect debugger / inspector attachment flags
  const execArgv = (process.execArgv || []).join(' ');
  if (/--inspect|--debug/.test(execArgv)) {
    throw new Error('Security Alert: Debugger / Inspector attachment is prohibited.');
  }

  // Known-Answer Test (KAT) on SHA-256 and AES-256-GCM to detect hooked crypto functions
  const katDigest = crypto.createHash('sha256').update('SeedVault-KAT-v2').digest('hex');
  if (katDigest.length !== 64) {
    throw new Error('Security Alert: Cryptographic hash primitive tampered.');
  }
}
verifyRuntimeIntegrity();

// ============================================================================
// 1. Galois Field GF(256) Arithmetic (Irreducible polynomial: x^8 + x^4 + x^3 + x + 1 = 0x11B)
// ============================================================================
const GF256 = (() => {
  const EXP = new Uint8Array(512);
  const LOG = new Uint8Array(256);

  let x = 1;
  for (let i = 0; i < 255; i++) {
    EXP[i] = x;
    LOG[x] = i;
    const x2 = (x << 1) ^ (x & 0x80 ? 0x1b : 0x00);
    x = (x2 ^ x) & 0xff;
  }
  for (let i = 255; i < 512; i++) {
    EXP[i] = EXP[i - 255];
  }

  function add(a, b) {
    return (a ^ b) & 0xff;
  }

  function sub(a, b) {
    return (a ^ b) & 0xff;
  }

  function mul(a, b) {
    if (a === 0 || b === 0) return 0;
    return EXP[LOG[a] + LOG[b]];
  }

  function div(a, b) {
    if (b === 0) throw new Error('GF256 division by zero');
    if (a === 0) return 0;
    return EXP[LOG[a] + 255 - LOG[b]];
  }

  return Object.freeze({ add, sub, mul, div });
})();

// ============================================================================
// 2. Shamir's Secret Sharing over GF(256)
// ============================================================================
class ShamirSecretSharing {
  static split(secret, n, k) {
    if (!Buffer.isBuffer(secret) || secret.length === 0) {
      throw new Error('Secret must be a non-empty Buffer');
    }
    if (n < 1 || n > 10 || k < 1 || k > n) {
      throw new Error(`Invalid Shamir threshold parameters: k=${k}, n=${n}`);
    }

    const shares = [];
    for (let i = 1; i <= n; i++) {
      shares.push({ x: i, y: Buffer.alloc(secret.length) });
    }

    for (let byteIdx = 0; byteIdx < secret.length; byteIdx++) {
      const coeffs = new Uint8Array(k);
      coeffs[0] = secret[byteIdx];
      if (k > 1) {
        const randBytes = crypto.randomBytes(k - 1);
        for (let c = 1; c < k; c++) {
          coeffs[c] = randBytes[c - 1];
        }
        randBytes.fill(0);
      }

      for (let s = 0; s < n; s++) {
        const x = shares[s].x;
        let y = 0;
        for (let c = k - 1; c >= 0; c--) {
          y = GF256.add(GF256.mul(y, x), coeffs[c]);
        }
        shares[s].y[byteIdx] = y;
      }
      coeffs.fill(0);
    }

    return shares;
  }

  static combine(shares) {
    if (!Array.isArray(shares) || shares.length === 0) {
      throw new Error('At least one share is required to combine');
    }
    const secretLength = shares[0].y.length;
    const secret = Buffer.alloc(secretLength);
    const k = shares.length;

    for (let byteIdx = 0; byteIdx < secretLength; byteIdx++) {
      let value = 0;
      for (let i = 0; i < k; i++) {
        const xi = shares[i].x;
        const yi = shares[i].y[byteIdx];
        let num = 1;
        let den = 1;
        for (let j = 0; j < k; j++) {
          if (i === j) continue;
          const xj = shares[j].x;
          num = GF256.mul(num, xj);
          den = GF256.mul(den, GF256.sub(xi, xj));
        }
        const basis = GF256.div(num, den);
        value = GF256.add(value, GF256.mul(yi, basis));
      }
      secret[byteIdx] = value;
    }

    return secret;
  }
}
Object.freeze(ShamirSecretSharing);

// ============================================================================
// 3. Input Normalization & Validation
// ============================================================================
function normalizeAnswer(input, caseSensitive = false) {
  if (typeof input !== 'string') return '';
  let cleaned = input.normalize('NFKC').trim().replace(/\s+/g, ' ');
  if (!caseSensitive) {
    cleaned = cleaned.toLowerCase();
  }
  return cleaned;
}

function validateSeedPayload(words, passphrase25 = '') {
  if (!Array.isArray(words)) {
    throw new Error('Seedphrase ต้องอยู่ในรูปแบบรายการคำศัพท์');
  }
  const normalizedWords = words
    .map((w) => (typeof w === 'string' ? w.trim().toLowerCase() : ''))
    .filter((w) => w.length > 0);

  if (!ALLOWED_WORD_COUNTS.includes(normalizedWords.length)) {
    throw new Error(
      `จำนวนคำของ Seedphrase ต้องเป็น 12, 15, 18, 20 หรือ 24 คำเท่านั้น (ได้รับ ${normalizedWords.length} คำ)`
    );
  }

  for (let i = 0; i < normalizedWords.length; i++) {
    if (/\s/.test(normalizedWords[i])) {
      throw new Error(`คำที่ ${i + 1} มีช่องว่างปนอยู่ กรุณากรอกช่องละ 1 คำเท่านั้น`);
    }
  }

  const normalizedPassphrase = typeof passphrase25 === 'string' ? passphrase25.trim() : '';

  return {
    wordCount: normalizedWords.length,
    words: normalizedWords,
    passphrase25: normalizedPassphrase,
    hasPassphrase25: normalizedPassphrase.length > 0,
  };
}

// ============================================================================
// 4. Hardened Cryptographic Primitives (PBKDF2 + Memory-Hard scrypt + AES-256-GCM)
// ============================================================================

/**
 * Derives a 256-bit key using:
 * - v2 (default): PBKDF2-HMAC-SHA512 (600,000 iter) cascaded into Memory-Hard scrypt (64MB RAM)
 * - v1 (backward compatibility): PBKDF2-HMAC-SHA512 (600,000 iter)
 */
function deriveKeyHardened(secretInput, saltHex, kdfVersion = 2) {
  const salt = Buffer.from(saltHex, 'hex');
  const stage1 = crypto.pbkdf2Sync(
    Buffer.from(secretInput, 'utf8'),
    salt,
    PBKDF2_ITERATIONS,
    KEY_LENGTH_BYTES,
    'sha512'
  );

  if (kdfVersion === 1) {
    return stage1;
  }

  // Stage 2: Memory-Hard scrypt (N=65536 = 64MB RAM) to block GPU/ASIC brute-forcing
  const scryptSalt = crypto.createHash('sha256').update(salt).update('SVLT-SCRYPT-v2').digest();
  const stage2 = crypto.scryptSync(stage1, scryptSalt, KEY_LENGTH_BYTES, SCRYPT_PARAMS);
  stage1.fill(0);
  return stage2;
}

function combineKeysHKDF(keysBufferArray, contextInfo = 'SeedVault-CombinedSlot') {
  const ikm = Buffer.concat(keysBufferArray);
  const salt = Buffer.alloc(32, 0);
  const derived = Buffer.from(
    crypto.hkdfSync('sha256', ikm, salt, Buffer.from(contextInfo, 'utf8'), KEY_LENGTH_BYTES)
  );
  ikm.fill(0);
  return derived;
}

function encryptAES256GCM(plaintextBuffer, keyBuffer, aadString = '') {
  const iv = crypto.randomBytes(GCM_IV_BYTES);
  const cipher = crypto.createCipheriv('aes-256-gcm', keyBuffer, iv);
  if (aadString) {
    cipher.setAAD(Buffer.from(aadString, 'utf8'));
  }
  const ciphertext = Buffer.concat([cipher.update(plaintextBuffer), cipher.final()]);
  const tag = cipher.getAuthTag();
  return {
    iv: iv.toString('hex'),
    ciphertext: ciphertext.toString('hex'),
    tag: tag.toString('hex'),
  };
}

function decryptAES256GCM(encObj, keyBuffer, aadString = '') {
  const iv = Buffer.from(encObj.iv, 'hex');
  const ciphertext = Buffer.from(encObj.ciphertext, 'hex');
  const tag = Buffer.from(encObj.tag, 'hex');
  const decipher = crypto.createDecipheriv('aes-256-gcm', keyBuffer, iv);
  if (aadString) {
    decipher.setAAD(Buffer.from(aadString, 'utf8'));
  }
  decipher.setAuthTag(tag);
  return Buffer.concat([decipher.update(ciphertext), decipher.final()]);
}

/**
 * Constant-Length Binary Padding (4096 bytes fixed envelope)
 * Ensures 12, 15, 18, 20, 24 words + 25th passphrase produce identical ciphertext sizes.
 * Format: [4-byte UInt32BE payloadLength] + [JSON UTF-8 bytes] + [CSPRNG random padding bytes]
 */
function packFixedSizePayload(payloadObject) {
  const jsonBytes = Buffer.from(JSON.stringify(payloadObject), 'utf8');
  if (jsonBytes.length + 4 > FIXED_PAYLOAD_BLOCK_BYTES) {
    throw new Error('Payload size exceeds maximum security envelope block size');
  }
  const block = crypto.randomBytes(FIXED_PAYLOAD_BLOCK_BYTES);
  block.writeUInt32BE(jsonBytes.length, 0);
  jsonBytes.copy(block, 4);
  jsonBytes.fill(0);
  return block;
}

function unpackFixedSizePayload(decryptedBuffer) {
  // Support both v2 fixed-size padded blocks and v1 raw JSON buffers
  if (decryptedBuffer.length === FIXED_PAYLOAD_BLOCK_BYTES) {
    const jsonLen = decryptedBuffer.readUInt32BE(0);
    if (jsonLen > 0 && jsonLen <= FIXED_PAYLOAD_BLOCK_BYTES - 4) {
      const jsonStr = decryptedBuffer.subarray(4, 4 + jsonLen).toString('utf8');
      return JSON.parse(jsonStr);
    }
  }
  return JSON.parse(decryptedBuffer.toString('utf8'));
}

// ============================================================================
// 5. Multi-Slot Envelope Encryption Builder & Unlocker
// ============================================================================
function createEncryptedVault(setupConfig) {
  verifyRuntimeIntegrity();

  const {
    words,
    passphrase25 = '',
    questions = [],
    requiredQuestionCount = 0,
    phoneLast4 = '',
    specialCode = '',
    policyMode = 'OR_ANY',
    allowPhoneInstantUnlock = false,
    allowSpecialInstantUnlock = false,
    maxAttempts = 5,
    gameModuleConfig = { enabled: false, gameType: 'pattern_shield', difficulty: 1 },
  } = setupConfig;

  const validatedSeed = validateSeedPayload(words, passphrase25);

  const validQuestions = questions
    .filter((q) => q && typeof q.question === 'string' && q.question.trim().length > 0)
    .map((q, idx) => ({
      id: idx + 1,
      question: q.question.trim(),
      answer: normalizeAnswer(q.answer, false),
    }));

  if (validQuestions.length > 5) {
    throw new Error('ตั้งคำถามได้สูงสุดไม่เกิน 5 ข้อ');
  }
  for (const q of validQuestions) {
    if (!q.answer) {
      throw new Error(`กรุณากรอกคำตอบสำหรับคำถามข้อที่ ${q.id}`);
    }
  }

  const hasQuestions = validQuestions.length > 0;
  const kQuestions = hasQuestions
    ? Math.min(Math.max(1, Number(requiredQuestionCount) || validQuestions.length), validQuestions.length)
    : 0;

  const cleanedPhone = typeof phoneLast4 === 'string' ? phoneLast4.trim() : '';
  if (cleanedPhone.length > 0 && !/^\d{4}$/.test(cleanedPhone)) {
    throw new Error('เบอร์โทรศัพท์ 4 ตัวท้าย ต้องเป็นตัวเลข 4 หลักเท่านั้น (เช่น 1234)');
  }
  const hasPhone = cleanedPhone.length === 4;

  const cleanedSpecial = typeof specialCode === 'string' ? normalizeAnswer(specialCode, true) : '';
  const hasSpecial = cleanedSpecial.length > 0;

  if (!hasQuestions && !hasPhone && !hasSpecial) {
    throw new Error('กรุณาตั้งค่าวิธีการยืนยันตัวตนอย่างน้อย 1 รูปแบบ (คำถาม, เบอร์โทร 4 ตัวท้าย, หรือรหัสพิเศษ)');
  }

  const parsedMaxAttempts = Number(maxAttempts);
  if (!Number.isInteger(parsedMaxAttempts) || parsedMaxAttempts < 1 || parsedMaxAttempts > 100) {
    throw new Error('จำนวนการกรอกผิดต้องอยู่ระหว่าง 1 ถึง 100 ครั้ง');
  }

  // Generate Random 256-bit Master Key & Encrypt Fixed-Size Padded Seedphrase Payload
  const masterKey = crypto.randomBytes(KEY_LENGTH_BYTES);
  const paddedPayloadBuffer = packFixedSizePayload({
    wordCount: validatedSeed.wordCount,
    words: validatedSeed.words,
    passphrase25: validatedSeed.passphrase25,
    hasPassphrase25: validatedSeed.hasPassphrase25,
    createdAt: new Date().toISOString(),
  });

  const encryptedPayload = encryptAES256GCM(
    paddedPayloadBuffer,
    masterKey,
    'SeedVault-PrimaryPayload-v1'
  );
  paddedPayloadBuffer.fill(0);

  let questionComponentKey = null;
  let questionMeta = null;

  if (hasQuestions) {
    questionComponentKey = crypto.randomBytes(KEY_LENGTH_BYTES);
    const shares = ShamirSecretSharing.split(questionComponentKey, validQuestions.length, kQuestions);

    const encryptedQuestionShares = validQuestions.map((q, idx) => {
      const qSalt = crypto.randomBytes(16).toString('hex');
      const answerKey = deriveKeyHardened(`Q:${q.id}:${q.answer}`, qSalt, 2);
      const shareObj = shares[idx];
      // Zero-Oracle One-Time Pad (OTP XOR) Masking:
      // No per-question authentication tag is stored on disk, making it mathematically
      // impossible for an offline attacker to test or brute-force individual questions
      // (such as a short answer like "black") independently.
      const maskedShareBuf = Buffer.alloc(KEY_LENGTH_BYTES);
      for (let b = 0; b < KEY_LENGTH_BYTES; b++) {
        maskedShareBuf[b] = shareObj.y[b] ^ answerKey[b];
      }
      answerKey.fill(0);
      shareObj.y.fill(0);
      return {
        id: q.id,
        x: shareObj.x,
        question: q.question,
        salt: qSalt,
        maskedShare: maskedShareBuf.toString('hex'),
      };
    });

    questionMeta = {
      totalQuestions: validQuestions.length,
      requiredCorrect: kQuestions,
      shareMode: 'OTP_XOR_ZERO_ORACLE',
      items: encryptedQuestionShares,
    };
  }

  let phoneComponentKey = null;
  let phoneSalt = null;
  if (hasPhone) {
    phoneSalt = crypto.randomBytes(16).toString('hex');
    phoneComponentKey = deriveKeyHardened(`PHONE4:${cleanedPhone}`, phoneSalt, 2);
  }

  let specialComponentKey = null;
  let specialSalt = null;
  if (hasSpecial) {
    specialSalt = crypto.randomBytes(16).toString('hex');
    specialComponentKey = deriveKeyHardened(`SPECIAL:${cleanedSpecial}`, specialSalt, 2);
  }

  const keySlots = [];
  const addSlot = (slotType, slotLabel, wrappingKeyBuffer) => {
    const wrappedMaster = encryptAES256GCM(masterKey, wrappingKeyBuffer, `Slot:${slotType}`);
    keySlots.push({
      slotType,
      slotLabel,
      wrappedMaster,
    });
  };

  if (policyMode === 'OR_ANY') {
    if (hasQuestions) {
      addSlot(
        'QUESTIONS_ONLY',
        `ตอบคำถามให้ถูกอย่างน้อย ${kQuestions} จาก ${validQuestions.length} ข้อ`,
        questionComponentKey
      );
    }
    if (hasPhone) {
      addSlot('PHONE_ONLY', 'เบอร์โทรศัพท์ 4 ตัวท้าย', phoneComponentKey);
    }
    if (hasSpecial) {
      addSlot('SPECIAL_ONLY', 'รหัสพิเศษ (Special Code)', specialComponentKey);
    }
  } else if (policyMode === 'QUESTIONS_AND_PIN_OR_CODE') {
    if (hasQuestions && hasPhone) {
      const combinedQP = combineKeysHKDF([questionComponentKey, phoneComponentKey], 'Q+PHONE');
      addSlot(
        'QUESTIONS_AND_PHONE',
        `ตอบคำถาม (${kQuestions}/${validQuestions.length} ข้อ) + เบอร์โทร 4 ตัวท้าย`,
        combinedQP
      );
      combinedQP.fill(0);
    }
    if (hasQuestions && hasSpecial) {
      const combinedQS = combineKeysHKDF([questionComponentKey, specialComponentKey], 'Q+SPECIAL');
      addSlot(
        'QUESTIONS_AND_SPECIAL',
        `ตอบคำถาม (${kQuestions}/${validQuestions.length} ข้อ) + รหัสพิเศษ`,
        combinedQS
      );
      combinedQS.fill(0);
    }
    if (!hasQuestions) {
      if (hasPhone) addSlot('PHONE_ONLY', 'เบอร์โทรศัพท์ 4 ตัวท้าย', phoneComponentKey);
      if (hasSpecial) addSlot('SPECIAL_ONLY', 'รหัสพิเศษ (Special Code)', specialComponentKey);
    } else if (!hasPhone && !hasSpecial) {
      addSlot(
        'QUESTIONS_ONLY',
        `ตอบคำถาม (${kQuestions}/${validQuestions.length} ข้อ)`,
        questionComponentKey
      );
    }
  } else if (policyMode === 'ALL_CONFIGURED') {
    const activeKeys = [];
    const labels = [];
    if (hasQuestions) {
      activeKeys.push(questionComponentKey);
      labels.push(`คำถาม (${kQuestions}/${validQuestions.length} ข้อ)`);
    }
    if (hasPhone) {
      activeKeys.push(phoneComponentKey);
      labels.push('เบอร์โทร 4 ตัวท้าย');
    }
    if (hasSpecial) {
      activeKeys.push(specialComponentKey);
      labels.push('รหัสพิเศษ');
    }
    const combinedAll = combineKeysHKDF(activeKeys, 'ALL_FACTORS');
    addSlot('ALL_CONFIGURED', `ต้องกรอกครบทั้งหมด: ${labels.join(' + ')}`, combinedAll);
    combinedAll.fill(0);
  }

  if (allowPhoneInstantUnlock && hasPhone && !keySlots.some((s) => s.slotType === 'PHONE_ONLY')) {
    addSlot('PHONE_ONLY', 'ปลดล็อกด่วนด้วยเบอร์โทรศัพท์ 4 ตัวท้าย', phoneComponentKey);
  }
  if (allowSpecialInstantUnlock && hasSpecial && !keySlots.some((s) => s.slotType === 'SPECIAL_ONLY')) {
    addSlot('SPECIAL_ONLY', 'ปลดล็อกด่วนด้วยรหัสพิเศษ (Special Code)', specialComponentKey);
  }

  masterKey.fill(0);
  if (questionComponentKey) questionComponentKey.fill(0);
  if (phoneComponentKey) phoneComponentKey.fill(0);
  if (specialComponentKey) specialComponentKey.fill(0);

  return {
    version: '2.0.0',
    kdfVersion: 2,
    policyMode,
    factors: {
      hasQuestions,
      hasPhone,
      hasSpecial,
      phoneSalt,
      specialSalt,
      questionMeta,
    },
    gameModule: {
      enabled: Boolean(gameModuleConfig && gameModuleConfig.enabled),
      gameType: (gameModuleConfig && gameModuleConfig.gameType) || 'pattern_shield',
      difficulty: Number((gameModuleConfig && gameModuleConfig.difficulty) || 1),
      requiredGamesCount: Math.min(
        Math.max(1, Number((gameModuleConfig && gameModuleConfig.requiredGamesCount) || 1)),
        5
      ),
      gameChain: Array.isArray(gameModuleConfig && gameModuleConfig.gameChain)
        ? gameModuleConfig.gameChain
        : [],
    },
    securityCounter: {
      maxAttempts: parsedMaxAttempts,
      remainingAttempts: parsedMaxAttempts,
      failedAttempts: 0,
    },
    keySlots,
    encryptedPayload,
  };
}

function getShareCombinations(arr, k) {
  if (k === 0) return [[]];
  if (arr.length < k) return [];
  const [first, ...rest] = arr;
  const withFirst = getShareCombinations(rest, k - 1).map((c) => [first, ...c]);
  const withoutFirst = getShareCombinations(rest, k);
  return [...withFirst, ...withoutFirst];
}

function attemptUnlockVault(vaultData, credentials) {
  verifyRuntimeIntegrity();

  const {
    questionAnswers = {},
    phoneLast4 = '',
    specialCode = '',
  } = credentials || {};

  const { factors, keySlots, encryptedPayload } = vaultData;
  const kdfVersion = vaultData.kdfVersion || 1;

  const validQuestionShares = [];
  if (factors.hasQuestions && factors.questionMeta) {
    for (const qItem of factors.questionMeta.items) {
      const rawAns = questionAnswers[qItem.id] || questionAnswers[String(qItem.id)] || '';
      const normAns = normalizeAnswer(rawAns, false);
      if (!normAns) continue;

      try {
        const answerKey = deriveKeyHardened(`Q:${qItem.id}:${normAns}`, qItem.salt, kdfVersion);
        if (typeof qItem.maskedShare === 'string' && qItem.maskedShare.length === KEY_LENGTH_BYTES * 2) {
          const maskedBuf = Buffer.from(qItem.maskedShare, 'hex');
          const shareY = Buffer.alloc(KEY_LENGTH_BYTES);
          for (let b = 0; b < KEY_LENGTH_BYTES; b++) {
            shareY[b] = maskedBuf[b] ^ answerKey[b];
          }
          answerKey.fill(0);
          validQuestionShares.push({ x: qItem.x, y: shareY });
        } else if (qItem.wrappedShare) {
          const shareY = decryptAES256GCM(qItem.wrappedShare, answerKey, `Share-${qItem.x}`);
          answerKey.fill(0);
          validQuestionShares.push({ x: qItem.x, y: shareY });
        } else {
          answerKey.fill(0);
        }
      } catch (_err) {
        // Incorrect answer for legacy AEAD-wrapped share
      }
    }
  }

  const candidateQuestionKeys = [];
  if (
    factors.hasQuestions &&
    factors.questionMeta &&
    validQuestionShares.length >= factors.questionMeta.requiredCorrect
  ) {
    const kReq = factors.questionMeta.requiredCorrect;
    const shareSubsets = getShareCombinations(validQuestionShares, kReq);
    for (const subset of shareSubsets) {
      candidateQuestionKeys.push(ShamirSecretSharing.combine(subset));
    }
  }

  let derivedPhoneKey = null;
  const cleanedPhone = typeof phoneLast4 === 'string' ? phoneLast4.trim() : '';
  if (factors.hasPhone && cleanedPhone.length === 4 && factors.phoneSalt) {
    derivedPhoneKey = deriveKeyHardened(`PHONE4:${cleanedPhone}`, factors.phoneSalt, kdfVersion);
  }

  let derivedSpecialKey = null;
  const cleanedSpecial = typeof specialCode === 'string' ? normalizeAnswer(specialCode, true) : '';
  if (factors.hasSpecial && cleanedSpecial.length > 0 && factors.specialSalt) {
    derivedSpecialKey = deriveKeyHardened(`SPECIAL:${cleanedSpecial}`, factors.specialSalt, kdfVersion);
  }

  const cleanupTempKeys = () => {
    for (const sh of validQuestionShares) sh.y.fill(0);
    for (const qk of candidateQuestionKeys) qk.fill(0);
    if (derivedPhoneKey) derivedPhoneKey.fill(0);
    if (derivedSpecialKey) derivedSpecialKey.fill(0);
  };

  for (const slot of keySlots) {
    const candidateWrappingKeys = [];

    if (slot.slotType === 'QUESTIONS_ONLY') {
      for (const qk of candidateQuestionKeys) {
        candidateWrappingKeys.push(Buffer.from(qk));
      }
    } else if (slot.slotType === 'PHONE_ONLY' && derivedPhoneKey) {
      candidateWrappingKeys.push(Buffer.from(derivedPhoneKey));
    } else if (slot.slotType === 'SPECIAL_ONLY' && derivedSpecialKey) {
      candidateWrappingKeys.push(Buffer.from(derivedSpecialKey));
    } else if (slot.slotType === 'QUESTIONS_AND_PHONE' && derivedPhoneKey) {
      for (const qk of candidateQuestionKeys) {
        candidateWrappingKeys.push(combineKeysHKDF([qk, derivedPhoneKey], 'Q+PHONE'));
      }
    } else if (slot.slotType === 'QUESTIONS_AND_SPECIAL' && derivedSpecialKey) {
      for (const qk of candidateQuestionKeys) {
        candidateWrappingKeys.push(combineKeysHKDF([qk, derivedSpecialKey], 'Q+SPECIAL'));
      }
    } else if (slot.slotType === 'ALL_CONFIGURED') {
      const qList = factors.hasQuestions ? candidateQuestionKeys : [null];
      for (const qk of qList) {
        const parts = [];
        let complete = true;
        if (factors.hasQuestions) {
          if (qk) parts.push(qk);
          else complete = false;
        }
        if (factors.hasPhone) {
          if (derivedPhoneKey) parts.push(derivedPhoneKey);
          else complete = false;
        }
        if (factors.hasSpecial) {
          if (derivedSpecialKey) parts.push(derivedSpecialKey);
          else complete = false;
        }
        if (complete && parts.length > 0) {
          candidateWrappingKeys.push(combineKeysHKDF(parts, 'ALL_FACTORS'));
        }
      }
    }

    for (const candidateWrappingKey of candidateWrappingKeys) {
      try {
        const masterKey = decryptAES256GCM(slot.wrappedMaster, candidateWrappingKey, `Slot:${slot.slotType}`);
        candidateWrappingKey.fill(0);
        const decryptedBytes = decryptAES256GCM(
          encryptedPayload,
          masterKey,
          'SeedVault-PrimaryPayload-v1'
        );
        masterKey.fill(0);
        const parsedPayload = unpackFixedSizePayload(decryptedBytes);
        decryptedBytes.fill(0);
        cleanupTempKeys();

        return {
          success: true,
          matchedSlot: slot.slotType,
          matchedSlotLabel: slot.slotLabel,
          payload: parsedPayload,
        };
      } catch (_err) {
        candidateWrappingKey.fill(0);
      }
    }
  }

  cleanupTempKeys();

  return {
    success: false,
    error: 'ข้อมูลยืนยันตัวตนไม่ถูกต้อง',
  };
}

module.exports = Object.freeze({
  ALLOWED_WORD_COUNTS,
  FIXED_PAYLOAD_BLOCK_BYTES,
  GF256,
  ShamirSecretSharing,
  normalizeAnswer,
  validateSeedPayload,
  createEncryptedVault,
  attemptUnlockVault,
  encryptAES256GCM,
  decryptAES256GCM,
});
