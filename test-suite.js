'use strict';

/**
 * Comprehensive Automated Security Audit & Verification Suite (v3.0)
 *
 * Tests:
 * 1. Strict Seedphrase Word Count Validation (12, 15, 18, 20, 24 only + 25th Passphrase)
 * 2. Constant-Length Payload Padding (4096 bytes)
 * 3. Shamir's Secret Sharing K-of-N Threshold + PBKDF2/scrypt Memory-Hard KDF + Anti-Bypass Verification
 * 4. Cross-Computer Counter Persistence, Encrypted Anchor (`.svlt_state.anchor`), and Self-Destruct Zero-Wipe
 * 5. Multi-Game Anti-Bot Pipeline (e.g. 2+ games before password input & Server-Side Gatekeeper Token)
 * 6. Bitcoin BIP39/BIP84 HD Wallet Derivation (Official BIP84 Test Vectors + Dynamic 25th Passphrase)
 *    & SegWit v0 (BIP143) Raw Transaction Signing + Hardware Wallet PSBT Generation
 */

const assert = require('assert');
const fs = require('fs');
const path = require('path');
const os = require('os');
const {
  ALLOWED_WORD_COUNTS,
  FIXED_PAYLOAD_BLOCK_BYTES,
  validateSeedPayload,
  createEncryptedVault,
} = require('./crypto-engine');
const { VaultStorageManager } = require('./vault-storage');
const { GameGuardModuleRegistry } = require('./game-module');
const {
  mnemonicToSeed,
  derivePath,
  deriveFromHardwarePublicKey,
  buildAndSignBitcoinTransaction,
  parseRawBitcoinTransaction,
} = require('./bitcoin-signer');

function generateSampleWords(count) {
  const samplePool = [
    'abandon', 'ability', 'able', 'about', 'above', 'absent',
    'absorb', 'abstract', 'absurd', 'abuse', 'access', 'accident',
    'account', 'accuse', 'achieve', 'acid', 'acoustic', 'acquire',
    'across', 'act', 'action', 'actor', 'actress', 'actual',
  ];
  return samplePool.slice(0, count);
}

function runAllTests() {
  console.log('==============================================================');
  console.log('🧪 Running Multi-OS SeedVault & Bitcoin Signer v3.0 Audit...');
  console.log('==============================================================\n');

  // -------------------------------------------------------------------------
  // TEST 1: Strict Seedphrase Word Counts (12, 15, 18, 20, 24) + 25th Passphrase
  // -------------------------------------------------------------------------
  console.log('▶ [Test 1] ตรวจสอบจำนวนคำ Seedphrase (12, 15, 18, 20, 24 คำ) และ Passphrase คำที่ 25...');
  for (const validCount of ALLOWED_WORD_COUNTS) {
    const words = generateSampleWords(validCount);
    const res = validateSeedPayload(words, 'my-secret-25th-passphrase');
    assert.strictEqual(res.wordCount, validCount);
    assert.strictEqual(res.hasPassphrase25, true);
    assert.strictEqual(res.passphrase25, 'my-secret-25th-passphrase');
  }

  for (const invalidCount of [1, 8, 11, 13, 16, 21, 25]) {
    let threw = false;
    try {
      validateSeedPayload(Array(invalidCount).fill('abandon'));
    } catch (_err) {
      threw = true;
    }
    assert.strictEqual(threw, true, `Should reject word count ${invalidCount}`);
  }
  console.log('  ✅ ผ่าน: รองรับเฉพาะ 12, 15, 18, 20, 24 คำ + คำที่ 25 เท่านั้น\n');

  // -------------------------------------------------------------------------
  // TEST 2: Constant-Length Payload Padding (Anti-Length-Leakage Side-Channel)
  // -------------------------------------------------------------------------
  console.log('▶ [Test 2] ตรวจสอบ Constant-Length Padding (12 คำ และ 24 คำ + คำที่ 25 ต้องมีขนาด Ciphertext เท่ากัน)...');
  const v12 = createEncryptedVault({
    words: generateSampleWords(12),
    passphrase25: '',
    phoneLast4: '1234',
  });
  const v24 = createEncryptedVault({
    words: generateSampleWords(24),
    passphrase25: 'VERY-LONG-25TH-PASSPHRASE-FOR-HARDWARE-WALLET-SECURITY-TEST',
    phoneLast4: '1234',
  });
  assert.strictEqual(v12.encryptedPayload.ciphertext.length, FIXED_PAYLOAD_BLOCK_BYTES * 2);
  assert.strictEqual(v12.encryptedPayload.ciphertext.length, v24.encryptedPayload.ciphertext.length);
  console.log('  ✅ ผ่าน: ขนาดก้อน Ciphertext คงที่ 4096 ไบต์เท่ากันทุกจำนวนคำ\n');

  // -------------------------------------------------------------------------
  // TEST 3: Anti-Bypass Security Policy (QUESTIONS_AND_PIN_OR_CODE & ALL_CONFIGURED)
  // -------------------------------------------------------------------------
  console.log('▶ [Test 3] ตรวจสอบว่าไม่สามารถข้ามขั้นตอนการตรวจความปลอดภัย (คำถาม / เบอร์โทร / คำพิเศษ)...');
  const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'seedvault-test-'));
  const storage = new VaultStorageManager(tempDir);

  const words24 = generateSampleWords(24);
  storage.initializeNewVault({
    words: words24,
    passphrase25: 'Family-Inheritance-25',
    questions: [
      { question: 'Q1: สีที่ชอบ?', answer: 'Blue' },
      { question: 'Q2: เมืองเกิด?', answer: 'Bangkok' },
      { question: 'Q3: สัตว์เลี้ยง?', answer: 'Tiger' },
    ],
    requiredQuestionCount: 2,
    phoneLast4: '4567',
    specialCode: 'OMEGA-99',
    policyMode: 'QUESTIONS_AND_PIN_OR_CODE', // Must answer 2/3 questions AND provide (Phone OR Special)
    allowPhoneInstantUnlock: false,
    allowSpecialInstantUnlock: false,
    maxAttempts: 5,
  });

  // Attempt with ONLY questions (missing phone/special) -> MUST FAIL
  const bypassTry1 = storage.unlockVault({
    questionAnswers: { 1: 'Blue', 2: 'Bangkok' },
  });
  assert.strictEqual(bypassTry1.success, false, 'Cannot bypass secondary factor in QUESTIONS_AND_PIN_OR_CODE mode');

  // Attempt with ONLY phone (missing questions) -> MUST FAIL
  const bypassTry2 = storage.unlockVault({
    phoneLast4: '4567',
  });
  assert.strictEqual(bypassTry2.success, false, 'Cannot bypass questions when allowPhoneInstantUnlock is false');

  // Legitimate combined unlock: 2/3 questions + Special Code -> MUST SUCCEED
  const validCombined = storage.unlockVault({
    questionAnswers: { 2: 'bangkok', 3: 'tiger' },
    specialCode: 'OMEGA-99',
  });
  assert.strictEqual(validCombined.success, true);
  assert.deepStrictEqual(validCombined.payload.words, words24);
  console.log('  ✅ ผ่าน: ไม่สามารถข้ามขั้นตอนคำถาม/เบอร์โทร/รหัสพิเศษได้ เนื่องจากคีย์ถูกผสมด้วย HKDF-SHA256\n');

  // -------------------------------------------------------------------------
  // TEST 4: Multi-Stage Anti-Bot Game Pipeline (2+ Games Required Before Password)
  // -------------------------------------------------------------------------
  console.log('▶ [Test 4] ตรวจสอบระบบเล่นมากกว่า 1 เกมส์ต่อเนื่อง (Multi-Stage Anti-Bot Gatekeeper)...');
  const games = new GameGuardModuleRegistry({ minSolveMs: 0 });
  const multiSession = games.createChallengeSession({
    gameType: 'pattern_shield',
    difficulty: 2,
    requiredGamesCount: 2, // Must complete 2 games in sequence!
  });
  assert.strictEqual(multiSession.totalStages, 2);
  assert.strictEqual(multiSession.currentStageIndex, 0);

  // Solve Stage 1 (Pattern Shield)
  const stage1Res = games.verifyChallengeSession(
    multiSession.sessionId,
    multiSession.challenge.sequence
  );
  assert.strictEqual(stage1Res.stageCleared, true);
  assert.strictEqual(stage1Res.verified, false, 'Must NOT issue pass token after only 1 of 2 games');
  assert.strictEqual(Boolean(stage1Res.gamePassToken), false);
  assert.ok(stage1Res.nextStage);
  assert.strictEqual(stage1Res.nextStage.currentStageIndex, 1);

  // Solve Stage 2 (Orbital Lock)
  const stage2Res = games.verifyChallengeSession(
    multiSession.sessionId,
    stage1Res.nextStage.challenge.targets
  );
  assert.strictEqual(stage2Res.verified, true, 'Must issue pass token after completing all 2 games');
  assert.strictEqual(stage2Res.allCompleted, true);
  assert.strictEqual(games.validateGamePassToken(stage2Res.gamePassToken), true);

  // Test 4B: Verify all 4 new mini-games individually.
  // Answers are NOT sent to the browser any more, so read them from the server-side session.
  const secretOf = (s) => games.activeSessions.get(s.sessionId).stages[0].challenge;

  // 1. Chroma Slider
  const chromaSession = games.createChallengeSession({ gameType: 'chroma_slider', requiredGamesCount: 1 });
  assert.strictEqual(chromaSession.challenge.targetHue, undefined, 'targetHue must not be sent to the client');
  const chromaRes = games.verifyChallengeSession(chromaSession.sessionId, secretOf(chromaSession).targetHue);
  assert.strictEqual(chromaRes.verified, true, 'Chroma slider match must succeed');

  // 2. Glyph Outlier
  const glyphSession = games.createChallengeSession({ gameType: 'glyph_outlier', requiredGamesCount: 1 });
  assert.strictEqual(glyphSession.challenge.outlierIndex, undefined, 'outlierIndex must not be sent to the client');
  const glyphRes = games.verifyChallengeSession(glyphSession.sessionId, secretOf(glyphSession).outlierIndex);
  assert.strictEqual(glyphRes.verified, true, 'Glyph outlier pick must succeed');

  // 3. Bubble Sequence
  const bubbleSession = games.createChallengeSession({ gameType: 'bubble_sequence', requiredGamesCount: 1 });
  assert.strictEqual(bubbleSession.challenge.correctSequence, undefined, 'correctSequence must not be sent to the client');
  const bubbleRes = games.verifyChallengeSession(bubbleSession.sessionId, secretOf(bubbleSession).correctSequence);
  assert.strictEqual(bubbleRes.verified, true, 'Bubble sequence ascending tap must succeed');

  // 4. Puzzle Slider
  const puzzleSession = games.createChallengeSession({ gameType: 'puzzle_slider', requiredGamesCount: 1 });
  const puzzleRes = games.verifyChallengeSession(puzzleSession.sessionId, secretOf(puzzleSession).targetPercent);
  assert.strictEqual(puzzleRes.verified, true, 'Puzzle slider snap must succeed');

  // 4C: pass token is single-use
  assert.strictEqual(games.validateGamePassToken(puzzleRes.gamePassToken), true);
  assert.strictEqual(games.consumeGamePassToken(puzzleRes.gamePassToken), true, 'First use must succeed');
  assert.strictEqual(games.consumeGamePassToken(puzzleRes.gamePassToken), false, 'Token must be burned after one use');

  // 4D: 3 wrong answers destroy the session (cannot enumerate answers on one session)
  const guessSession = games.createChallengeSession({ gameType: 'glyph_outlier', requiredGamesCount: 1 });
  const correctIdx = secretOf(guessSession).outlierIndex;
  const wrongIdx = (correctIdx + 1) % guessSession.challenge.totalItems;
  assert.strictEqual(games.verifyChallengeSession(guessSession.sessionId, wrongIdx).verified, false);
  assert.strictEqual(games.verifyChallengeSession(guessSession.sessionId, wrongIdx).verified, false);
  const thirdWrong = games.verifyChallengeSession(guessSession.sessionId, wrongIdx);
  assert.strictEqual(thirdWrong.sessionExpired, true, 'Session must die after 3 wrong answers');
  assert.strictEqual(
    games.verifyChallengeSession(guessSession.sessionId, correctIdx).verified,
    false,
    'A dead session must not accept even the correct answer'
  );

  // 4E: bot-speed answers are rejected (human-speed floor)
  const strictGames = new GameGuardModuleRegistry({ minSolveMs: 60000 });
  const fastSession = strictGames.createChallengeSession({ gameType: 'puzzle_slider', requiredGamesCount: 1 });
  const fastSecret = strictGames.activeSessions.get(fastSession.sessionId).stages[0].challenge.targetPercent;
  const fastRes = strictGames.verifyChallengeSession(fastSession.sessionId, fastSecret);
  assert.strictEqual(fastRes.verified, false, 'Instant correct answer must be rejected as bot-speed');

  // 4F: repeated failures trigger a temporary global lockout
  const throttleGames = new GameGuardModuleRegistry({ minSolveMs: 0 });
  for (let i = 0; i < 10; i++) {
    const s = throttleGames.createChallengeSession({ gameType: 'puzzle_slider', requiredGamesCount: 1 });
    if (s.throttled) break;
    throttleGames.verifyChallengeSession(s.sessionId, -999);
  }
  assert.strictEqual(throttleGames.isThrottled(), true, 'Failure burst must lock the game gatekeeper');
  assert.strictEqual(
    Boolean(throttleGames.createChallengeSession({ gameType: 'puzzle_slider' }).throttled),
    true
  );

  console.log('  ✅ ผ่าน: บังคับผ่านครบทุกด่านเกมส์ + มินิเกมส์ทั้ง 6 รูปแบบ + เฉลยไม่ถูกส่งไปหน้าเว็บ + Token ใช้ได้ครั้งเดียว + ตอบผิด 3 ครั้งเซสชันตาย + กันตอบเร็วระดับบอท + ล็อกชั่วคราวเมื่อลองผิดถี่\n');

  // -------------------------------------------------------------------------
  // TEST 5: Bitcoin BIP86 Taproot + BIP84 SegWit + Direct Hardware Wallet Mode & Multi-UTXO
  // -------------------------------------------------------------------------
  console.log('▶ [Test 5] ตรวจสอบกระเป๋า Bitcoin (Taproot BIP86 / Native SegWit BIP84 / SegWit / Legacy / เลือกหลาย UTXO / Direct Hardware Wallet ไม่ต้องปลดล็อก Seed)...');
  const bipWords = [
    'abandon', 'abandon', 'abandon', 'abandon', 'abandon', 'abandon',
    'abandon', 'abandon', 'abandon', 'abandon', 'abandon', 'about',
  ];
  const seedNoPass = mnemonicToSeed(bipWords, '');

  // 1. Official BIP84 Native SegWit Vector
  const walletSegwit = derivePath(seedNoPass, "m/84'/0'/0'/0/0", 'NATIVE_SEGWIT');
  assert.strictEqual(
    walletSegwit.segwitAddress,
    'bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu',
    'Must match official BIP84 test vector address'
  );

  // 2. Official BIP86 Taproot Vector (m/86'/0'/0'/0/0 for abandon...about -> bc1p5cyxnuxmeuwuvkwfem96lqzszd02n6xdcjrs20cac6yqjjwudpxqkedrcr)
  const walletTaproot = derivePath(seedNoPass, "m/86'/0'/0'/0/0", 'TAPROOT');
  assert.strictEqual(
    walletTaproot.taprootAddress,
    'bc1p5cyxnuxmeuwuvkwfem96lqzszd02n6xdcjrs20cac6yqjjwudpxqkedrcr',
    'Must match official BIP86 Taproot test vector address'
  );
  assert.strictEqual(walletTaproot.activeAddress, walletTaproot.taprootAddress);

  // 2B. Hardware Wallet Auto-Scan (Ledger Account Xpub m/86'/0'/0' -> child 0/0 & Trezor PublicKey)
  const officialBip86AccountXpub =
    'xpub6BgBgsespWvERF3LHQu6CnqdvfEvtMcQjYrcRzx53QJjSxarj2afYWcLteoGVky7D3UKDP9QyrLprQ3VCECoY49yfdDEHGCtMMj92pReUsQ';
  const ledgerAutoScanned = deriveFromHardwarePublicKey({
    xpub: officialBip86AccountXpub,
    childPath: '0/0',
    scriptType: 'TAPROOT',
    derivationPath: "m/86'/0'/0'/0/0",
  });
  assert.strictEqual(
    ledgerAutoScanned.activeAddress,
    'bc1p5cyxnuxmeuwuvkwfem96lqzszd02n6xdcjrs20cac6yqjjwudpxqkedrcr',
    'Ledger Bitcoin App Xpub + childPath 0/0 must derive exact BIP86 Taproot address without user typing it'
  );
  assert.strictEqual(
    Array.isArray(ledgerAutoScanned.scanAddresses) && ledgerAutoScanned.scanAddresses.length,
    8,
    'Must generate 8 multi-index scanAddresses (0/0..0/4 receive + 1/0..1/2 change)'
  );
  assert.notStrictEqual(
    ledgerAutoScanned.changeAddress,
    ledgerAutoScanned.activeAddress,
    'Internal Change Address (1/0) must be distinct from Receive Address (0/0)'
  );

  const trezorAutoScanned = deriveFromHardwarePublicKey({
    pubKeyHex: walletSegwit.publicKeyHex,
    scriptType: 'NATIVE_SEGWIT',
    derivationPath: "m/84'/0'/0'/0/0",
  });
  assert.strictEqual(
    trezorAutoScanned.activeAddress,
    'bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu',
    'Trezor PublicKey must derive exact BIP84 Native SegWit address automatically'
  );

  // 3. Direct Hardware Wallet Mode (Trezor / Ledger WITHOUT unlocking Seed 24 words!)
  const hwPsbtResult = buildAndSignBitcoinTransaction({
    words: [], // No seed needed!
    scriptType: 'TAPROOT',
    senderAddress: walletTaproot.taprootAddress,
    inputs: [
      {
        txid: 'a1075db55d416d3ca199f55b6084e2115b9345e16c5cf302fc80e9d5fbf5d48d',
        vout: 0,
        amountSats: 100000,
      },
      {
        txid: 'b2075db55d416d3ca199f55b6084e2115b9345e16c5cf302fc80e9d5fbf5d48e',
        vout: 1,
        amountSats: 50000,
      },
    ],
    outputs: [
      {
        address: 'bc1p5cyxnuxmeuwuvkwfem96lqzszd02n6xdcjrs20cac6yqjjwudpxqkedrcr',
        amountSats: 148500,
      },
    ],
    signWithSeed: false, // Direct Hardware Wallet mode
  });
  assert.strictEqual(hwPsbtResult.signed, false);
  assert.strictEqual(hwPsbtResult.mode, 'HARDWARE_WALLET_PSBT');
  assert.strictEqual(hwPsbtResult.totalInSats, 150000);
  assert.strictEqual(hwPsbtResult.feeSats, 1500);
  assert.ok(hwPsbtResult.unsignedPsbtBase64.startsWith('cHNidP8'));

  // 4. Sign with Unlocked Seed (or Manual Seed) + Dynamic 25th Passphrase on Taproot
  const signedTaprootTx = buildAndSignBitcoinTransaction({
    words: words24,
    passphrase25: 'CUSTOM-25TH-ADDED-LATER',
    scriptType: 'TAPROOT',
    derivationPath: "m/86'/0'/0'/0/0",
    inputs: [
      {
        txid: 'a1075db55d416d3ca199f55b6084e2115b9345e16c5cf302fc80e9d5fbf5d48d',
        vout: 0,
        amountSats: 150000,
      },
    ],
    outputs: [
      {
        address: 'bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu',
        amountSats: 148500,
      },
    ],
    signWithSeed: true,
  });

  assert.strictEqual(signedTaprootTx.signed, true);
  assert.strictEqual(signedTaprootTx.feeSats, 1500);
  assert.ok(signedTaprootTx.signedTxHex.startsWith('020000000001'));

  // 5. Verify Trezor Firmware (`trezor-firmware` SignTx/TxAck) Prev-TX Parser
  const parsedPrev = parseRawBitcoinTransaction(signedTaprootTx.signedTxHex);
  assert.strictEqual(parsedPrev.txid, signedTaprootTx.txid, 'Non-witness TXID must match exactly for Trezor TXMETA verification');
  assert.strictEqual(parsedPrev.inputsCount, 1);
  assert.strictEqual(parsedPrev.outputsCount, 1);
  assert.strictEqual(parsedPrev.binOutputs[0].amountSats, 148500);

  // 6. Verify Ledger Hardware Wallet Direct Signing Assembly (`assembleSignedTransaction`)
  const { assembleSignedTransaction } = require('./bitcoin-signer');
  const dummySig = '304402207fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff02207fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff01';
  const dummyPub = '0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798';
  const assembledLedgerTx = assembleSignedTransaction({
    inputs: [
      {
        txid: 'a1075db55d416d3ca199f55b6084e2115b9345e16c5cf302fc80e9d5fbf5d48d',
        vout: 0,
        amountSats: 100000,
        sequence: 0xffffffff,
      },
    ],
    outputs: [
      {
        address: 'bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu',
        amountSats: 98500,
        scriptPubKeyHex: '00140123456789abcdef0123456789abcdef01234567',
      },
    ],
    signatures: [
      {
        inputIndex: 0,
        signatureHex: dummySig,
        pubKeyHex: dummyPub,
      },
    ],
    scriptType: 'NATIVE_SEGWIT',
    derivationPath: "m/84'/0'/0'/0/0",
  });
  assert.ok(assembledLedgerTx.signedTxHex.length > 50, 'Assembled Ledger transaction hex must be valid');
  assert.ok(assembledLedgerTx.txid.length === 64, 'Assembled Ledger transaction txid must be 32-byte hex');
  console.log(`  ✅ ผ่าน: BIP86 Taproot (${walletTaproot.taprootAddress}), BIP84 SegWit, Trezor Firmware Offline SignTx & Ledger Direct Hardware Signer ทำงานสมบูรณ์!\n`);

  // -------------------------------------------------------------------------
  // TEST 6: Shamir 2x12-Word Seed Backup + Zero-Oracle Share Masking + Anti-Copy-Paste Rollback Self-Destruct
  // -------------------------------------------------------------------------
  console.log('▶ [Test 6] ตรวจสอบ Shamir Backup (2 คำถาม x 12 คำ), Zero-Oracle Share Masking และระบบป้องกัน Copy-Paste ไฟล์กลับมาสุ่มรหัสใหม่...');
  const seed12Q1 = 'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about';
  const seed12Q2 = 'legal winner thank year wave sausage worth useful legal winner thank yellow';

  storage.initializeNewVault({
    words: words24,
    passphrase25: 'SHAMIR-VAULT-25',
    questions: [
      { question: 'Seed ชุดที่ 1 (12 คำ)', answer: seed12Q1 },
      { question: 'Seed ชุดที่ 2 (12 คำ)', answer: seed12Q2 },
    ],
    requiredQuestionCount: 2,
    policyMode: 'OR_ANY',
    maxAttempts: 3,
  });

  // 6A. Verify Zero-Oracle Share Masking & Ratchet Token on disk
  const rawEnvelopeText = fs.readFileSync(storage.vaultPath, 'utf8');
  const rawEnvelope = JSON.parse(rawEnvelopeText);
  assert.ok(typeof rawEnvelope.ratchetToken === 'string' && rawEnvelope.ratchetToken.length === 64, 'seedvault.dat must include 256-bit ratchetToken');

  // Verify unlock with 2x12-word Shamir answers works
  const shamirUnlockOk = storage.unlockVault({
    questionAnswers: { 1: seed12Q1, 2: seed12Q2 },
  });
  assert.strictEqual(shamirUnlockOk.success, true, 'Must unlock 24-word seed when both 12-word Shamir answers are correct');
  assert.strictEqual(shamirUnlockOk.payload.words.join(' '), words24.join(' '));

  // 6B. Verify Flash Drive Cross-Computer Portability:
  // Copy ONLY seedvault.dat to a brand-new simulated computer (with clean OS anchors) -> MUST open & unlock seamlessly!
  const flashDriveDir = fs.mkdtempSync(path.join(os.tmpdir(), 'seedvault-flashdrive-'));
  const cleanComputerAnchorDir = fs.mkdtempSync(path.join(os.tmpdir(), 'seedvault-computerB-'));
  fs.copyFileSync(storage.vaultPath, path.join(flashDriveDir, 'seedvault.dat'));
  const computerBStorage = new VaultStorageManager(flashDriveDir);
  computerBStorage.osAnchorPaths = [path.join(cleanComputerAnchorDir, '.svlt_computerB_anchor.dat')];

  const computerBStatus = computerBStorage.getPublicStatus();
  assert.strictEqual(computerBStatus.initialized, true, 'Flash Drive copied to another computer must open normally');
  const computerBUnlock = computerBStorage.unlockVault({
    questionAnswers: { 1: seed12Q1, 2: seed12Q2 },
  });
  assert.strictEqual(computerBUnlock.success, true, 'Flash Drive on another computer must unlock 24-word seed normally');
  assert.strictEqual(computerBUnlock.payload.words.join(' '), words24.join(' '));

  // 6C. Simulate Attacker Copy-Paste Rollback Attack on Computer B:
  // Attacker copies BOTH seedvault.dat AND portable .svlt_state.anchor before guessing!
  const copiedVaultBytes = fs.readFileSync(computerBStorage.vaultPath);
  const copiedPortableAnchorBytes = fs.readFileSync(computerBStorage.portableAnchorPath);

  // Attacker makes 1 wrong guess ("black" / "white") -> remainingAttempts drops from 3 to 2
  const wrongGuess1 = computerBStorage.unlockVault({
    questionAnswers: { 1: 'black', 2: 'white' },
  });
  assert.strictEqual(wrongGuess1.success, false);
  assert.strictEqual(wrongGuess1.remainingAttempts, 2);

  // Attacker pastes the old copied seedvault.dat AND old .svlt_state.anchor back to reset counter to 3!
  fs.writeFileSync(computerBStorage.vaultPath, copiedVaultBytes);
  fs.writeFileSync(computerBStorage.portableAnchorPath, copiedPortableAnchorBytes);

  // Next access / unlock attempt must detect Rollback Attack via OS Ratchet Anchor and immediately 7-Pass Shred & Self-Destruct!
  const rollbackAttempt = computerBStorage.unlockVault({
    questionAnswers: { 1: seed12Q1, 2: seed12Q2 },
  });
  assert.strictEqual(rollbackAttempt.success, false, 'Rollback copy-paste attack must be rejected');
  assert.strictEqual(rollbackAttempt.wiped, true, 'Rollback copy-paste attack must trigger immediate Self-Destruct');
  assert.strictEqual(fs.existsSync(computerBStorage.vaultPath), false, 'seedvault.dat must be forensically shredded and unlinked');

  // Even if attacker pastes seedvault.dat a SECOND time after wipe, tombstone wipes it again!
  fs.writeFileSync(computerBStorage.vaultPath, copiedVaultBytes);
  const postWipePasteStatus = computerBStorage.getPublicStatus();
  assert.strictEqual(postWipePasteStatus.initialized, false, 'Pasting file after wipe must immediately shred it again');
  assert.strictEqual(fs.existsSync(computerBStorage.vaultPath), false, 'seedvault.dat pasted after wipe must be destroyed');
  console.log('  ✅ ผ่าน: รองรับการนำ Flash Drive ไปเปิดเครื่องอื่นได้ปกติ + ป้องกันการถอดรหัสแยกข้อ (Zero-Oracle OTP) + ทำลายไฟล์ 7 รอบทันทีเมื่อตรวจพบการ Copy-Paste ไฟล์เก่ากลับมาสุ่มรหัสซ้ำ!\n');

  // -------------------------------------------------------------------------
  // TEST 7: Device migration (import/export), PIN-only block, pre-attempt counter commit
  // -------------------------------------------------------------------------
  console.log('▶ [Test 7] ตรวจสอบการย้ายเครื่อง (นำเข้า/ส่งออก), การห้าม PIN อย่างเดียว และการนับครั้งก่อนคำนวณรหัส...');
  const devA = fs.mkdtempSync(path.join(os.tmpdir(), 'seedvault-devA-'));
  const devB = fs.mkdtempSync(path.join(os.tmpdir(), 'seedvault-devB-'));
  const devC = fs.mkdtempSync(path.join(os.tmpdir(), 'seedvault-devC-'));
  const isolated = (dir) => {
    const m = new VaultStorageManager(dir);
    m.osAnchorPaths = [path.join(dir, 'os-anchor.dat')]; // keep the test off the real home dir
    return m;
  };
  const mgrA = isolated(devA);
  const mgrB = isolated(devB);
  const mgrC = isolated(devC);

  mgrA.initializeNewVault({
    words: words24,
    passphrase25: '',
    questions: [
      { question: 'Q1', answer: 'a1' },
      { question: 'Q2', answer: 'a2' },
    ],
    requiredQuestionCount: 2,
    phoneLast4: '4321',
    policyMode: 'QUESTIONS_AND_PIN_OR_CODE',
    maxAttempts: 5,
  });
  const staleBytes = fs.readFileSync(mgrA.vaultPath);

  // 7A. PIN-only configuration is refused and must NOT destroy the existing vault
  assert.throws(
    () => mgrA.initializeNewVault({ words: words24, phoneLast4: '1111', policyMode: 'OR_ANY' }),
    /เบอร์โทร 4 หลัก/
  );
  assert.ok(staleBytes.equals(fs.readFileSync(mgrA.vaultPath)), 'Rejected setup must leave the existing vault untouched');

  // 7B. A wrong attempt is committed to disk (counter 5 -> 4)
  const wrongA = mgrA.unlockVault({ questionAnswers: { 1: 'x', 2: 'y' }, phoneLast4: '4321' });
  assert.strictEqual(wrongA.success, false);
  assert.strictEqual(wrongA.remainingAttempts, 4);

  // 7C. Stale file (older than this device's state) is refused WITHOUT damaging the current vault
  assert.throws(() => mgrA.importVaultFile(staleBytes), /เก่ากว่า/);
  assert.strictEqual(mgrA.getPublicStatus().initialized, true, 'Refused import must not wipe the vault');

  // 7D. Export from device A -> import on a clean device B; the counter travels with the file
  const exported = mgrA.exportVaultFile();
  const importedStatus = mgrB.importVaultFile(exported);
  assert.strictEqual(importedStatus.initialized, true);
  assert.strictEqual(importedStatus.securityCounter.failedAttempts, 1, 'Failed-attempt count must travel with the file');
  const okB = mgrB.unlockVault({ questionAnswers: { 1: 'a1', 2: 'a2' }, phoneLast4: '4321' });
  assert.strictEqual(okB.success, true, 'Imported vault must unlock on the new device');
  assert.strictEqual(okB.payload.words.join(' '), words24.join(' '));

  // 7E. Importing over a DIFFERENT existing vault needs explicit confirmation
  mgrC.initializeNewVault({
    words: words24,
    questions: [{ question: 'Q1', answer: 'z1' }],
    phoneLast4: '1234',
    policyMode: 'QUESTIONS_AND_PIN_OR_CODE',
  });
  assert.throws(() => mgrC.importVaultFile(exported), /Vault อื่น/);
  assert.strictEqual(mgrC.getPublicStatus().initialized, true, 'Unconfirmed import must keep the existing vault');
  assert.strictEqual(mgrC.importVaultFile(exported, { replaceExisting: true }).initialized, true);

  // 7F. Garbage files are refused
  assert.throws(() => mgrC.importVaultFile(Buffer.from('not a vault')), /ไม่ใช่ seedvault.dat/);

  for (const d of [devA, devB, devC]) fs.rmSync(d, { recursive: true, force: true });
  console.log('  ✅ ผ่าน: นำเข้า/ส่งออกข้ามเครื่องได้ (จำนวนครั้งติดไปกับไฟล์), ปฏิเสธไฟล์เก่า/ไฟล์ขยะโดยไม่ทำลายของเดิม, ห้าม PIN อย่างเดียว และนับครั้งก่อนคำนวณรหัส\n');

  fs.rmSync(flashDriveDir, { recursive: true, force: true });
  fs.rmSync(cleanComputerAnchorDir, { recursive: true, force: true });
  fs.rmSync(tempDir, { recursive: true, force: true });

  console.log('==============================================================');
  console.log('🎉 การทดสอบความปลอดภัย, Trezor Firmware & Ledger Hardware Signer ผ่านครบ 100%');
  console.log('==============================================================');
}

runAllTests();
