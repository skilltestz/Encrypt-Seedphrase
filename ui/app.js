'use strict';

(() => {
  // State
  let selectedWordCount = 24;
  let setupQuestions = [{ question: '', answer: '' }];
  let currentVaultStatus = null;
  let activeGameSession = null;
  let currentGamePassToken = null;
  let wordsMasked = false;
  let lastDecryptedPayload = null;
  let autoLockTimer = null;

  // Bitcoin Studio State
  let currentKeySourceMode = 'VAULT_SEED'; // 'VAULT_SEED' | 'MANUAL_SEED' | 'HARDWARE_USB'
  let currentScriptType = 'NATIVE_SEGWIT'; // 'TAPROOT' | 'NATIVE_SEGWIT' | 'NESTED_SEGWIT' | 'LEGACY'
  let utxoItems = [
    { selected: true, txid: '', vout: 0, amountSats: 100000 },
  ];

  const SCRIPT_LABELS = {
    TAPROOT: 'Taproot (bc1p...)',
    NATIVE_SEGWIT: 'Native SegWit (bc1q...)',
    NESTED_SEGWIT: 'Nested SegWit (3...)',
    LEGACY: 'Legacy (1...)',
  };

  function getCsrfToken() {
    const meta = document.querySelector('meta[name="seedvault-token"]');
    return meta ? meta.getAttribute('content') || '' : '';
  }

  function apiPost(url, bodyObj) {
    return fetch(url, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-SeedVault-Token': getCsrfToken(),
      },
      body: JSON.stringify(bodyObj),
    });
  }

  // Elements
  const alertBanner = document.getElementById('alertBanner');
  const setupView = document.getElementById('setupView');
  const unlockView = document.getElementById('unlockView');
  const decryptedView = document.getElementById('decryptedView');
  const openDirectHwModeTopBtn = document.getElementById('openDirectHwModeTopBtn');
  const openDirectHwFromUnlockBtn = document.getElementById('openDirectHwFromUnlockBtn');
  const backToUnlockScreenBtn = document.getElementById('backToUnlockScreenBtn');
  const unlockedSeedDisplayCard = document.getElementById('unlockedSeedDisplayCard');
  const directHwModeBanner = document.getElementById('directHwModeBanner');

  // Setup Form Elements
  const setupForm = document.getElementById('setupForm');
  const seedWordsGrid = document.getElementById('seedWordsGrid');
  const enablePassphrase25 = document.getElementById('enablePassphrase25');
  const passphrase25Container = document.getElementById('passphrase25Container');
  const passphrase25Input = document.getElementById('passphrase25Input');
  const questionsContainer = document.getElementById('questionsContainer');
  const addQuestionBtn = document.getElementById('addQuestionBtn');
  const requiredQuestionCount = document.getElementById('requiredQuestionCount');
  const questionThresholdBox = document.getElementById('questionThresholdBox');

  const enablePhoneFactor = document.getElementById('enablePhoneFactor');
  const phoneFactorInputWrap = document.getElementById('phoneFactorInputWrap');
  const setupPhoneLast4 = document.getElementById('setupPhoneLast4');

  const enableSpecialFactor = document.getElementById('enableSpecialFactor');
  const specialFactorInputWrap = document.getElementById('specialFactorInputWrap');
  const setupSpecialCode = document.getElementById('setupSpecialCode');

  const policyModeSelect = document.getElementById('policyModeSelect');
  const fastTrackOptions = document.getElementById('fastTrackOptions');
  const allowPhoneInstantUnlock = document.getElementById('allowPhoneInstantUnlock');
  const allowSpecialInstantUnlock = document.getElementById('allowSpecialInstantUnlock');
  const maxAttemptsInput = document.getElementById('maxAttemptsInput');

  const enableGameModule = document.getElementById('enableGameModule');
  const gameModuleSettings = document.getElementById('gameModuleSettings');
  const requiredGamesCountSelect = document.getElementById('requiredGamesCountSelect');
  const gameTypeSelect = document.getElementById('gameTypeSelect');
  const gameDifficultySelect = document.getElementById('gameDifficultySelect');

  // Unlock Elements
  const remainingAttemptsDisplay = document.getElementById('remainingAttemptsDisplay');
  const maxAttemptsDisplay = document.getElementById('maxAttemptsDisplay');
  const openResetModalBtn = document.getElementById('openResetModalBtn');
  const gameShieldCard = document.getElementById('gameShieldCard');
  const gameTitleDisplay = document.getElementById('gameTitleDisplay');
  const gameStageProgressBadge = document.getElementById('gameStageProgressBadge');
  const gameStageContainer = document.getElementById('gameStageContainer');
  const unlockCredentialsCard = document.getElementById('unlockCredentialsCard');
  const unlockPolicyDescription = document.getElementById('unlockPolicyDescription');
  const availableMethodsBar = document.getElementById('availableMethodsBar');
  const unlockForm = document.getElementById('unlockForm');
  const unlockQuestionsBlock = document.getElementById('unlockQuestionsBlock');
  const unlockQuestionRuleText = document.getElementById('unlockQuestionRuleText');
  const unlockQuestionsList = document.getElementById('unlockQuestionsList');
  const unlockPhoneBlock = document.getElementById('unlockPhoneBlock');
  const unlockPhoneInput = document.getElementById('unlockPhoneInput');
  const unlockSpecialBlock = document.getElementById('unlockSpecialBlock');
  const unlockSpecialInput = document.getElementById('unlockSpecialInput');

  // Decrypted View Elements
  const decryptedWordCount = document.getElementById('decryptedWordCount');
  const unlockedBySlotText = document.getElementById('unlockedBySlotText');
  const decryptedWordsGrid = document.getElementById('decryptedWordsGrid');
  const decryptedPassphraseBox = document.getElementById('decryptedPassphraseBox');
  const decryptedPassphraseValue = document.getElementById('decryptedPassphraseValue');
  const toggleMaskWordsBtn = document.getElementById('toggleMaskWordsBtn');
  const copyAllWordsBtn = document.getElementById('copyAllWordsBtn');
  const lockVaultNowBtn = document.getElementById('lockVaultNowBtn');

  // Bitcoin Studio Elements
  const modeVaultSeedBtn = document.getElementById('modeVaultSeedBtn');
  const modeManualSeedBtn = document.getElementById('modeManualSeedBtn');
  const modeHardwareUsbBtn = document.getElementById('modeHardwareUsbBtn');
  const manualSeedImportPanel = document.getElementById('manualSeedImportPanel');
  const manualSeedTextarea = document.getElementById('manualSeedTextarea');
  const hardwareUsbPanel = document.getElementById('hardwareUsbPanel');
  const connectLedgerUsbBtn = document.getElementById('connectLedgerUsbBtn');
  const connectTrezorUsbBtn = document.getElementById('connectTrezorUsbBtn');
  const hardwareUsbStatusText = document.getElementById('hardwareUsbStatusText');
  const hwWalletAddressInput = document.getElementById('hwWalletAddressInput');
  const trezorPassphraseInput = document.getElementById('trezorPassphraseInput');
  const toggleTrezorPassBtn = document.getElementById('toggleTrezorPassBtn');
  const trezorPassOnDeviceCheckbox = document.getElementById('trezorPassOnDeviceCheckbox');
  const rescanHardwareAddressBtn = document.getElementById('rescanHardwareAddressBtn');
  const verifyAddressOnTrezorBtn = document.getElementById('verifyAddressOnTrezorBtn');
  const trezorPinModal = document.getElementById('trezorPinModal');
  const trezorPinDisplayInput = document.getElementById('trezorPinDisplayInput');
  const trezorPinClearBtn = document.getElementById('trezorPinClearBtn');
  const trezorPinCancelBtn = document.getElementById('trezorPinCancelBtn');
  const trezorPinSubmitBtn = document.getElementById('trezorPinSubmitBtn');

  const seedDerivationControls = document.getElementById('seedDerivationControls');
  const signingPassphrase25Input = document.getElementById('signingPassphrase25Input');
  const btcDerivationPathInput = document.getElementById('btcDerivationPathInput');
  const deriveWalletBtn = document.getElementById('deriveWalletBtn');
  const derivedWalletInfoBox = document.getElementById('derivedWalletInfoBox');
  const activeScriptNameLabel = document.getElementById('activeScriptNameLabel');
  const btcActiveAddressDisplay = document.getElementById('btcActiveAddressDisplay');
  const btcTaprootSegwitDisplay = document.getElementById('btcTaprootSegwitDisplay');
  const btcLegacyFingerprintDisplay = document.getElementById('btcLegacyFingerprintDisplay');

  const scanBlockchainUtxoBtn = document.getElementById('scanBlockchainUtxoBtn');
  const exportOfflineUtxoBtn = document.getElementById('exportOfflineUtxoBtn');
  const importOfflineUtxoBtn = document.getElementById('importOfflineUtxoBtn');
  const importOfflineUtxoFileInput = document.getElementById('importOfflineUtxoFileInput');
  const addCustomUtxoRowBtn = document.getElementById('addCustomUtxoRowBtn');
  const utxoTableBody = document.getElementById('utxoTableBody');
  const selectedUtxoCountText = document.getElementById('selectedUtxoCountText');
  const selectedUtxoTotalSatsText = document.getElementById('selectedUtxoTotalSatsText');

  const btcSignForm = document.getElementById('btcSignForm');
  const destAddressInput = document.getElementById('destAddressInput');
  const sendAmountSatsInput = document.getElementById('sendAmountSatsInput');
  const sendAmountUnitSelect = document.getElementById('sendAmountUnitSelect');
  const sendAmountConversionHint = document.getElementById('sendAmountConversionHint');
  const feeSatsInput = document.getElementById('feeSatsInput');
  const changeAddressInput = document.getElementById('changeAddressInput');
  const changePathHintText = document.getElementById('changePathHintText');
  const changeAmountSatsInput = document.getElementById('changeAmountSatsInput');

  const signedTxOutputPanel = document.getElementById('signedTxOutputPanel');
  const signedTxFeeBadge = document.getElementById('signedTxFeeBadge');
  const signedTxidDisplay = document.getElementById('signedTxidDisplay');
  const signedHexBlock = document.getElementById('signedHexBlock');
  const signedRawTxHexArea = document.getElementById('signedRawTxHexArea');
  const unsignedPsbtArea = document.getElementById('unsignedPsbtArea');
  const copySignedHexBtn = document.getElementById('copySignedHexBtn');
  const saveSignedHexFileBtn = document.getElementById('saveSignedHexFileBtn');
  const copyPsbtBtn = document.getElementById('copyPsbtBtn');
  const broadcastTxBtn = document.getElementById('broadcastTxBtn');

  let currentWalletDerivedState = {
    activeAddress: '',
    changeAddress: '',
    changePath: "m/84'/0'/0'/1/0",
    taprootAddress: '',
    segwitAddress: '',
    nestedSegwitAddress: '',
    legacyAddress: '',
  };

  // Reset Modal Elements
  const resetConfirmModal = document.getElementById('resetConfirmModal');
  const resetConfirmStep1 = document.getElementById('resetConfirmStep1');
  const resetConfirmStep2 = document.getElementById('resetConfirmStep2');
  const cancelResetBtn1 = document.getElementById('cancelResetBtn1');
  const cancelResetBtn2 = document.getElementById('cancelResetBtn2');
  const proceedResetStep2Btn = document.getElementById('proceedResetStep2Btn');
  const resetConfirmTextInput = document.getElementById('resetConfirmTextInput');
  const confirmFinalResetBtn = document.getElementById('confirmFinalResetBtn');

  function showAlert(message, type = 'error') {
    alertBanner.textContent = message;
    alertBanner.className = `alert-banner ${type}`;
    alertBanner.classList.remove('hidden');
    window.scrollTo({ top: 0, behavior: 'smooth' });
  }

  function hideAlert() {
    alertBanner.classList.add('hidden');
  }

  function escapeHtml(str) {
    return String(str || '')
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;');
  }

  // =========================================================================
  // 1. Setup Mode Rendering (12, 15, 18, 20, 24 Words + Questions 1-5)
  // =========================================================================
  function renderSeedInputs(count) {
    selectedWordCount = Number(count);
    document.querySelectorAll('.wc-btn').forEach((btn) => {
      btn.classList.toggle('active', Number(btn.dataset.count) === selectedWordCount);
    });

    const existingValues = Array.from(seedWordsGrid.querySelectorAll('.seed-word-input')).map(
      (el) => el.value
    );

    seedWordsGrid.innerHTML = '';
    for (let i = 1; i <= selectedWordCount; i++) {
      const wrap = document.createElement('div');
      wrap.className = 'seed-word-item';

      const idxSpan = document.createElement('span');
      idxSpan.className = 'seed-word-index';
      idxSpan.textContent = `${i}.`;

      const inp = document.createElement('input');
      inp.type = 'text';
      inp.className = 'seed-word-input';
      inp.placeholder = `คำที่ ${i}`;
      inp.dataset.index = String(i - 1);
      inp.autocomplete = 'off';
      inp.spellcheck = false;
      if (existingValues[i - 1]) {
        inp.value = existingValues[i - 1];
      }

      inp.addEventListener('paste', (e) => {
        const text = (e.clipboardData || window.clipboardData).getData('text');
        if (!text) return;
        const tokens = text.trim().split(/\s+/).filter(Boolean);
        if ([12, 15, 18, 20, 24].includes(tokens.length)) {
          e.preventDefault();
          renderSeedInputs(tokens.length);
          const allInputs = seedWordsGrid.querySelectorAll('.seed-word-input');
          tokens.forEach((word, idx) => {
            if (allInputs[idx]) allInputs[idx].value = word.toLowerCase();
          });
        }
      });

      wrap.appendChild(idxSpan);
      wrap.appendChild(inp);
      seedWordsGrid.appendChild(wrap);
    }
  }

  function renderSetupQuestions() {
    questionsContainer.innerHTML = '';
    setupQuestions.forEach((item, index) => {
      const row = document.createElement('div');
      row.className = 'question-row';

      const qDiv = document.createElement('div');
      qDiv.innerHTML = `
        <label class="input-label">คำถามข้อที่ ${index + 1}:</label>
        <input type="text" class="text-input q-text" placeholder="เช่น ชื่อสัตว์เลี้ยงตัวแรกของคุณ?" value="${escapeHtml(item.question)}" autocomplete="off" />
      `;

      const aDiv = document.createElement('div');
      aDiv.innerHTML = `
        <label class="input-label">คำตอบข้อที่ ${index + 1}:</label>
        <input type="text" class="text-input q-ans" placeholder="คำตอบ..." value="${escapeHtml(item.answer)}" autocomplete="off" />
      `;

      const delBtn = document.createElement('button');
      delBtn.type = 'button';
      delBtn.className = 'btn btn-secondary btn-sm';
      delBtn.textContent = 'ลบข้อนี้';
      delBtn.addEventListener('click', () => {
        syncQuestionsFromDOM();
        setupQuestions.splice(index, 1);
        renderSetupQuestions();
      });

      row.appendChild(qDiv);
      row.appendChild(aDiv);
      row.appendChild(delBtn);
      questionsContainer.appendChild(row);
    });

    addQuestionBtn.disabled = setupQuestions.length >= 5;
    updateThresholdDropdown();
  }

  function syncQuestionsFromDOM() {
    const rows = questionsContainer.querySelectorAll('.question-row');
    setupQuestions = Array.from(rows).map((row) => ({
      question: row.querySelector('.q-text').value,
      answer: row.querySelector('.q-ans').value,
    }));
  }

  function updateThresholdDropdown() {
    const count = setupQuestions.length;
    if (count === 0) {
      questionThresholdBox.classList.add('hidden');
      return;
    }
    questionThresholdBox.classList.remove('hidden');
    const prevVal = Number(requiredQuestionCount.value) || count;
    requiredQuestionCount.innerHTML = '';
    for (let k = 1; k <= count; k++) {
      const opt = document.createElement('option');
      opt.value = String(k);
      opt.textContent =
        k === count
          ? `ต้องตอบถูกทุกข้อ (${count} จาก ${count} ข้อ)`
          : `ตอบถูกอย่างน้อย ${k} ข้อ จาก ${count} ข้อ (Shamir ${k}-of-${count})`;
      requiredQuestionCount.appendChild(opt);
    }
    requiredQuestionCount.value = String(Math.min(prevVal, count));
  }

  document.querySelectorAll('.wc-btn').forEach((btn) => {
    btn.addEventListener('click', () => renderSeedInputs(Number(btn.dataset.count)));
  });

  enablePassphrase25.addEventListener('change', () => {
    passphrase25Container.classList.toggle('hidden', !enablePassphrase25.checked);
    if (!enablePassphrase25.checked) passphrase25Input.value = '';
  });

  addQuestionBtn.addEventListener('click', () => {
    syncQuestionsFromDOM();
    if (setupQuestions.length < 5) {
      setupQuestions.push({ question: '', answer: '' });
      renderSetupQuestions();
    }
  });

  enablePhoneFactor.addEventListener('change', () => {
    phoneFactorInputWrap.classList.toggle('hidden', !enablePhoneFactor.checked);
    if (!enablePhoneFactor.checked) setupPhoneLast4.value = '';
  });

  enableSpecialFactor.addEventListener('change', () => {
    specialFactorInputWrap.classList.toggle('hidden', !enableSpecialFactor.checked);
    if (!enableSpecialFactor.checked) setupSpecialCode.value = '';
  });

  policyModeSelect.addEventListener('change', () => {
    const isStrict = policyModeSelect.value !== 'OR_ANY';
    fastTrackOptions.classList.toggle('hidden', !isStrict);
  });

  enableGameModule.addEventListener('change', () => {
    gameModuleSettings.classList.toggle('hidden', !enableGameModule.checked);
  });

  setupForm.addEventListener('submit', async (e) => {
    e.preventDefault();
    hideAlert();
    syncQuestionsFromDOM();

    const words = Array.from(seedWordsGrid.querySelectorAll('.seed-word-input')).map((el) =>
      el.value.trim()
    );
    const emptyIdx = words.findIndex((w) => !w);
    if (emptyIdx !== -1) {
      showAlert(`กรุณากรอกคำศัพท์ Seedphrase ให้ครบทุกช่อง (ช่องที่ ${emptyIdx + 1} ยังว่างอยู่)`);
      return;
    }

    const activeQuestions = setupQuestions.filter(
      (q) => q.question.trim().length > 0 || q.answer.trim().length > 0
    );

    const payload = {
      words,
      passphrase25: enablePassphrase25.checked ? passphrase25Input.value.trim() : '',
      questions: activeQuestions,
      requiredQuestionCount: Number(requiredQuestionCount.value) || activeQuestions.length,
      phoneLast4: enablePhoneFactor.checked ? setupPhoneLast4.value.trim() : '',
      specialCode: enableSpecialFactor.checked ? setupSpecialCode.value : '',
      policyMode: policyModeSelect.value,
      allowPhoneInstantUnlock: allowPhoneInstantUnlock.checked,
      allowSpecialInstantUnlock: allowSpecialInstantUnlock.checked,
      maxAttempts: Number(maxAttemptsInput.value) || 5,
      gameModuleConfig: {
        enabled: enableGameModule.checked,
        gameType: gameTypeSelect.value,
        difficulty: Number(gameDifficultySelect.value) || 1,
        requiredGamesCount: Number(requiredGamesCountSelect.value) || 1,
      },
    };

    try {
      const res = await apiPost('/api/setup', payload);
      const data = await res.json();
      if (!res.ok || !data.ok) {
        showAlert(data.error || 'เกิดข้อผิดพลาดในการตั้งค่า');
        return;
      }

      seedWordsGrid.querySelectorAll('.seed-word-input').forEach((inp) => (inp.value = ''));
      passphrase25Input.value = '';
      setupPhoneLast4.value = '';
      setupSpecialCode.value = '';

      showAlert('เข้ารหัสและบันทึก Seedphrase สำเร็จแล้ว! เข้าสู่โหมดพร้อมใช้งาน', 'success');
      await refreshAppStatus();
    } catch (err) {
      showAlert(`ไม่สามารถติดต่อระบบหลังบ้านได้: ${err.message}`);
    }
  });

  // =========================================================================
  // 2. Unlock View & Multi-Stage Game Shield Pipeline
  // =========================================================================
  async function renderUnlockView(status) {
    currentVaultStatus = status;
    currentGamePassToken = null;
    setupView.classList.add('hidden');
    decryptedView.classList.add('hidden');
    unlockView.classList.remove('hidden');

    remainingAttemptsDisplay.textContent = String(status.securityCounter.remainingAttempts);
    maxAttemptsDisplay.textContent = String(status.securityCounter.maxAttempts);

    availableMethodsBar.innerHTML = '';
    (status.availableMethods || []).forEach((m) => {
      const badge = document.createElement('span');
      badge.className = 'method-badge';
      badge.textContent = `✓ ${m.slotLabel}`;
      availableMethodsBar.appendChild(badge);
    });

    unlockPolicyDescription.textContent =
      'คุณสามารถเลือกกรอกรหัสผ่านตามเงื่อนไขด้านล่างเพื่อปลดล็อก Seed 24 คำ หรือกดปุ่มด้านบนเพื่อเสียบ Trezor/Ledger ใช้งานโดยไม่ต้องปลดล็อก Seed';

    if (status.factors.hasQuestions && status.factors.questions) {
      unlockQuestionsBlock.classList.remove('hidden');
      const qMeta = status.factors.questions;
      unlockQuestionRuleText.textContent = `ต้องตอบถูกอย่างน้อย ${qMeta.requiredCorrect} จาก ${qMeta.totalQuestions} ข้อ`;
      unlockQuestionsList.innerHTML = '';
      qMeta.items.forEach((qItem) => {
        const div = document.createElement('div');
        div.innerHTML = `
          <label class="input-label">ข้อที่ ${qItem.id}: ${escapeHtml(qItem.question)}</label>
          <input type="password" class="text-input unlock-q-ans" data-qid="${qItem.id}" placeholder="กรอกคำตอบข้อที่ ${qItem.id}..." autocomplete="off" />
        `;
        unlockQuestionsList.appendChild(div);
      });
    } else {
      unlockQuestionsBlock.classList.add('hidden');
      unlockQuestionsList.innerHTML = '';
    }

    if (status.factors.hasPhone) {
      unlockPhoneBlock.classList.remove('hidden');
      unlockPhoneInput.value = '';
    } else {
      unlockPhoneBlock.classList.add('hidden');
    }

    if (status.factors.hasSpecial) {
      unlockSpecialBlock.classList.remove('hidden');
      unlockSpecialInput.value = '';
    } else {
      unlockSpecialBlock.classList.add('hidden');
    }

    if (status.gameModule && status.gameModule.enabled) {
      unlockCredentialsCard.classList.add('hidden');
      gameShieldCard.classList.remove('hidden');
      await startGameChallenge(status.gameModule);
    } else {
      gameShieldCard.classList.add('hidden');
      unlockCredentialsCard.classList.remove('hidden');
    }
  }

  async function startGameChallenge(gameConfig) {
    try {
      const res = await apiPost('/api/game/start', {
        gameType: gameConfig.gameType,
        difficulty: gameConfig.difficulty,
        requiredGamesCount: gameConfig.requiredGamesCount || 1,
        gameChain: gameConfig.gameChain || [],
      });
      const data = await res.json();
      if (!data.ok) return;

      activeGameSession = data.session;
      renderInteractiveGameStage(activeGameSession);
    } catch (_e) {
      showAlert('ไม่สามารถโหลดด่านเกมป้องกันได้ กรุณารีเฟรชหน้าจอ');
    }
  }

  function renderInteractiveGameStage(session) {
    gameStageContainer.innerHTML = '';
    gameTitleDisplay.textContent = session.gameName;
    const stageNum = (session.currentStageIndex || 0) + 1;
    const totalStages = session.totalStages || 1;
    gameStageProgressBadge.textContent = `ด่านที่ ${stageNum} / ${totalStages}`;

    const handleVerificationResponse = async (vData) => {
      if (vData.verified && vData.allCompleted) {
        currentGamePassToken = vData.gamePassToken;
        hideAlert();
        showAlert(`ผ่านภารกิจป้องกัน Bot ครบทั้ง ${totalStages} ด่านแล้ว! สามารถกรอกรหัสผ่านได้`, 'success');
        gameShieldCard.classList.add('hidden');
        unlockCredentialsCard.classList.remove('hidden');
      } else if (vData.stageCleared && vData.nextStage) {
        showAlert(
          `ผ่านด่านที่ ${stageNum}/${totalStages} แล้ว! กำลังเข้าสู่ด่านถัดไป...`,
          'success'
        );
        activeGameSession = vData.nextStage;
        renderInteractiveGameStage(activeGameSession);
      } else {
        showAlert(vData.error || 'ยังไม่ผ่านภารกิจด่านนี้ กำลังสุ่มโจทย์ใหม่...', 'warning');
        await startGameChallenge(currentVaultStatus.gameModule);
      }
    };

    if (session.gameType === 'pattern_shield') {
      const seq = session.challenge.sequence;
      const userClicks = [];
      let acceptingInput = false;

      const info = document.createElement('p');
      info.textContent = `จำลำดับโหนดพลังงานทั้ง ${seq.length} จุด แล้วกดตามลำดับให้ถูกต้อง`;

      const grid = document.createElement('div');
      grid.className = 'matrix-grid';
      const cells = [];

      for (let i = 0; i < 16; i++) {
        const cell = document.createElement('button');
        cell.type = 'button';
        cell.className = 'matrix-cell';
        cell.addEventListener('click', async () => {
          if (!acceptingInput) return;
          cell.classList.add('user-hit');
          setTimeout(() => cell.classList.remove('user-hit'), 220);
          userClicks.push(i);

          if (userClicks.length === seq.length) {
            acceptingInput = false;
            const verifyRes = await apiPost('/api/game/verify', {
              sessionId: session.sessionId,
              submission: userClicks,
            });
            const vData = await verifyRes.json();
            await handleVerificationResponse(vData);
          }
        });
        cells.push(cell);
        grid.appendChild(cell);
      }

      const replayBtn = document.createElement('button');
      replayBtn.type = 'button';
      replayBtn.className = 'btn btn-secondary btn-sm';
      replayBtn.textContent = '🔄 แสดงลำดับแสงอีกครั้ง';

      const playSequence = () => {
        acceptingInput = false;
        userClicks.length = 0;
        seq.forEach((cellIdx, step) => {
          setTimeout(() => {
            cells[cellIdx].classList.add('lit');
            setTimeout(() => {
              cells[cellIdx].classList.remove('lit');
              if (step === seq.length - 1) {
                acceptingInput = true;
              }
            }, 350);
          }, step * 520 + 300);
        });
      };

      replayBtn.addEventListener('click', playSequence);
      gameStageContainer.appendChild(info);
      gameStageContainer.appendChild(grid);
      gameStageContainer.appendChild(replayBtn);
      playSequence();
    } else if (session.gameType === 'orbital_lock') {
      const targets = session.challenge.targets;
      const sliders = [];

      const info = document.createElement('p');
      info.textContent = 'ปรับองศาวงแหวนทั้ง 3 ชั้นให้ตรงกับพิกัดเป้าหมายเพื่อผ่านด่าน';
      gameStageContainer.appendChild(info);

      targets.forEach((t, idx) => {
        const row = document.createElement('div');
        row.style.width = '100%';
        row.style.maxWidth = '420px';
        row.innerHTML = `
          <label class="input-label">วงแหวนที่ ${idx + 1} (เป้าหมาย: ${t}°): <span class="val-lbl">0°</span></label>
          <input type="range" min="0" max="359" value="0" class="full-width" />
        `;
        const rng = row.querySelector('input');
        const lbl = row.querySelector('.val-lbl');
        rng.addEventListener('input', () => {
          lbl.textContent = `${rng.value}°`;
        });
        sliders.push(rng);
        gameStageContainer.appendChild(row);
      });

      const verifyBtn = document.createElement('button');
      verifyBtn.type = 'button';
      verifyBtn.className = 'btn btn-primary mt-10';
      verifyBtn.textContent = 'ยืนยันพิกัดวงแหวน';
      verifyBtn.addEventListener('click', async () => {
        const angles = sliders.map((s) => Number(s.value));
        const verifyRes = await apiPost('/api/game/verify', {
          sessionId: session.sessionId,
          submission: angles,
        });
        const vData = await verifyRes.json();
        await handleVerificationResponse(vData);
      });
      gameStageContainer.appendChild(verifyBtn);
    } else if (session.gameType === 'chroma_slider') {
      const ch = session.challenge;
      const targetSample = ch.colorSample;

      const info = document.createElement('p');
      info.textContent = 'เลื่อนแถบสีด้านล่างเพื่อให้กล่อง "สีของคุณ" ตรงกับ "สีเป้าหมาย"';
      gameStageContainer.appendChild(info);

      const compBox = document.createElement('div');
      compBox.className = 'color-match-wrapper';
      compBox.innerHTML = `
        <div class="color-box-item">
          <div class="color-swatch target-swatch" style="background-color: ${targetSample};"></div>
          <span class="color-box-label">🎯 สีเป้าหมาย</span>
        </div>
        <div class="color-box-item">
          <div class="color-swatch user-swatch" id="userColorSwatch" style="background-color: hsl(0, 85%, 55%);"></div>
          <span class="color-box-label">🎨 สีของคุณ</span>
        </div>
      `;
      gameStageContainer.appendChild(compBox);

      const sliderWrap = document.createElement('div');
      sliderWrap.className = 'mt-12';
      sliderWrap.style.width = '100%';
      sliderWrap.style.maxWidth = '420px';
      sliderWrap.innerHTML = `
        <input type="range" min="0" max="360" value="0" class="full-width chroma-range" id="chromaRangeInput" />
      `;
      const range = sliderWrap.querySelector('#chromaRangeInput');
      const userSwatch = compBox.querySelector('#userColorSwatch');
      range.addEventListener('input', () => {
        userSwatch.style.backgroundColor = `hsl(${range.value}, 85%, 55%)`;
      });
      gameStageContainer.appendChild(sliderWrap);

      const verifyBtn = document.createElement('button');
      verifyBtn.type = 'button';
      verifyBtn.className = 'btn btn-primary mt-12';
      verifyBtn.textContent = 'ยืนยันเฉดสี';
      verifyBtn.addEventListener('click', async () => {
        const verifyRes = await apiPost('/api/game/verify', {
          sessionId: session.sessionId,
          submission: Number(range.value),
        });
        const vData = await verifyRes.json();
        await handleVerificationResponse(vData);
      });
      gameStageContainer.appendChild(verifyBtn);
    } else if (session.gameType === 'glyph_outlier') {
      const ch = session.challenge;
      const info = document.createElement('p');
      info.textContent = 'แตะเลือกสัญลักษณ์ 1 ชิ้นที่ไม่เข้าพวก เพื่อยืนยันว่าคุณคือมนุษย์';
      gameStageContainer.appendChild(info);

      const grid = document.createElement('div');
      grid.className = 'outlier-glyph-grid';
      ch.items.forEach((item) => {
        const btn = document.createElement('button');
        btn.type = 'button';
        btn.className = 'glyph-tile-btn';
        btn.textContent = item.icon;
        btn.addEventListener('click', async () => {
          btn.classList.add('selected');
          const verifyRes = await apiPost('/api/game/verify', {
            sessionId: session.sessionId,
            submission: item.id,
          });
          const vData = await verifyRes.json();
          await handleVerificationResponse(vData);
        });
        grid.appendChild(btn);
      });
      gameStageContainer.appendChild(grid);
    } else if (session.gameType === 'bubble_sequence') {
      const ch = session.challenge;
      const userSequence = [];
      const info = document.createElement('p');
      info.innerHTML = `แตะฟองตัวเลขเรียงจาก <strong>น้อยไปมาก</strong> (${ch.correctSequence.join(' ➔ ')})`;
      gameStageContainer.appendChild(info);

      const wrap = document.createElement('div');
      wrap.className = 'bubble-seq-wrapper';

      ch.bubbles.forEach((b) => {
        const bubbleBtn = document.createElement('button');
        bubbleBtn.type = 'button';
        bubbleBtn.className = 'bubble-seq-btn';
        bubbleBtn.textContent = b.value;
        bubbleBtn.addEventListener('click', async () => {
          if (bubbleBtn.classList.contains('popped')) return;
          bubbleBtn.classList.add('popped');
          userSequence.push(b.value);

          if (userSequence.length === ch.count) {
            const verifyRes = await apiPost('/api/game/verify', {
              sessionId: session.sessionId,
              submission: userSequence,
            });
            const vData = await verifyRes.json();
            await handleVerificationResponse(vData);
          }
        });
        wrap.appendChild(bubbleBtn);
      });
      gameStageContainer.appendChild(wrap);

      const resetBtn = document.createElement('button');
      resetBtn.type = 'button';
      resetBtn.className = 'btn btn-secondary btn-sm mt-12';
      resetBtn.textContent = '🔄 รีเซ็ตลำดับการกด';
      resetBtn.addEventListener('click', () => {
        userSequence.length = 0;
        wrap.querySelectorAll('.bubble-seq-btn').forEach((b) => b.classList.remove('popped'));
      });
      gameStageContainer.appendChild(resetBtn);
    } else if (session.gameType === 'puzzle_slider') {
      const ch = session.challenge;
      const targetX = ch.targetPercent;
      const tolerance = ch.tolerance;

      const info = document.createElement('p');
      info.textContent = 'ลากแถบกุญแจให้เข้าไปล็อกในช่องเป้าหมายสีทอง';
      gameStageContainer.appendChild(info);

      const track = document.createElement('div');
      track.className = 'puzzle-track-container';
      track.innerHTML = `
        <div class="puzzle-track-line">
          <div class="puzzle-target-slot" style="left: ${targetX}%;"></div>
        </div>
        <input type="range" min="0" max="100" value="0" class="puzzle-range-input" />
        <div class="puzzle-status-indicator mt-8"><span class="lock-status-badge">กำลังลาก...</span></div>
      `;
      const rng = track.querySelector('.puzzle-range-input');
      const badge = track.querySelector('.lock-status-badge');
      const targetSlot = track.querySelector('.puzzle-target-slot');

      rng.addEventListener('input', () => {
        const val = Number(rng.value);
        const inRange = Math.abs(val - targetX) <= tolerance;
        if (inRange) {
          badge.textContent = '✨ ตรงเป้าหมายแล้ว! (พร้อมยืนยัน)';
          badge.className = 'lock-status-badge in-slot';
          targetSlot.classList.add('aligned');
        } else {
          badge.textContent = `พิกัดปัจจุบัน: ${val}% (เป้าหมาย: ~${targetX}%)`;
          badge.className = 'lock-status-badge';
          targetSlot.classList.remove('aligned');
        }
      });
      gameStageContainer.appendChild(track);

      const verifyBtn = document.createElement('button');
      verifyBtn.type = 'button';
      verifyBtn.className = 'btn btn-primary mt-12';
      verifyBtn.textContent = 'ล็อกตำแหน่งกุญแจ';
      verifyBtn.addEventListener('click', async () => {
        const verifyRes = await apiPost('/api/game/verify', {
          sessionId: session.sessionId,
          submission: Number(rng.value),
        });
        const vData = await verifyRes.json();
        await handleVerificationResponse(vData);
      });
      gameStageContainer.appendChild(verifyBtn);
    }
  }

  unlockForm.addEventListener('submit', async (e) => {
    e.preventDefault();
    hideAlert();

    const questionAnswers = {};
    unlockQuestionsList.querySelectorAll('.unlock-q-ans').forEach((inp) => {
      if (inp.value.trim()) {
        questionAnswers[inp.dataset.qid] = inp.value;
      }
    });

    const credentials = {
      questionAnswers,
      phoneLast4: unlockPhoneInput.value.trim(),
      specialCode: unlockSpecialInput.value,
      gamePassToken: currentGamePassToken,
    };

    try {
      const res = await apiPost('/api/unlock', credentials);
      const data = await res.json();

      if (data.success && data.payload) {
        hideAlert();
        await renderDecryptedSeedView(data);
        return;
      }

      if (data.wiped) {
        showAlert(data.error, 'error');
        await refreshAppStatus();
      } else {
        if (typeof data.remainingAttempts === 'number') {
          remainingAttemptsDisplay.textContent = String(data.remainingAttempts);
        }
        showAlert(data.error, 'error');
      }
    } catch (err) {
      showAlert(`เกิดข้อผิดพลาดในการตรวจสอบรหัสผ่าน: ${err.message}`);
    }
  });

  // =========================================================================
  // 3. Direct Hardware Wallet Mode (WITHOUT Unlocking 24-Word Vault!)
  // =========================================================================
  function openDirectHardwareWalletStudio() {
    hideAlert();
    clearDecryptedMemoryAndLock();

    setupView.classList.add('hidden');
    unlockView.classList.add('hidden');
    decryptedView.classList.remove('hidden');

    // Hide the Unlocked Seed Card and show the Direct Hardware Wallet Banner
    unlockedSeedDisplayCard.classList.add('hidden');
    directHwModeBanner.classList.remove('hidden');
    if (openDirectHwModeTopBtn) {
      openDirectHwModeTopBtn.classList.add('hidden');
    }

    // In Direct Hardware Wallet Mode (Vault still locked), hide the 3-tab Key Source selector
    // so only the clean "← กลับไปหน้าปลดล็อก Seed 24 คำ" button is shown without disabled buttons
    const keySourceTabsWrapper = document.getElementById('keySourceTabsWrapper');
    if (keySourceTabsWrapper) {
      keySourceTabsWrapper.classList.add('hidden');
    }
    modeVaultSeedBtn.disabled = false;
    modeManualSeedBtn.disabled = false;
    setKeySourceMode('HARDWARE_USB');
    renderUtxoTable();
  }

  openDirectHwModeTopBtn.addEventListener('click', openDirectHardwareWalletStudio);
  if (openDirectHwFromUnlockBtn) {
    openDirectHwFromUnlockBtn.addEventListener('click', openDirectHardwareWalletStudio);
  }
  backToUnlockScreenBtn.addEventListener('click', async () => {
    clearDecryptedMemoryAndLock();
    hideAlert();
    await refreshAppStatus();
  });

  // =========================================================================
  // 4. Decrypted Seedphrase View & Multi-Script Bitcoin Transaction Studio
  // =========================================================================
  function clearDecryptedMemoryAndLock() {
    if (autoLockTimer) {
      clearTimeout(autoLockTimer);
      autoLockTimer = null;
    }
    lastDecryptedPayload = null;
    decryptedWordsGrid.innerHTML = '';
    decryptedPassphraseValue.textContent = '';
    signingPassphrase25Input.value = '';
    manualSeedTextarea.value = '';
    signedRawTxHexArea.value = '';
    unsignedPsbtArea.value = '';
    signedTxOutputPanel.classList.add('hidden');
  }

  function resetAutoLockTimer() {
    if (!lastDecryptedPayload) return;
    if (autoLockTimer) clearTimeout(autoLockTimer);
    autoLockTimer = setTimeout(async () => {
      clearDecryptedMemoryAndLock();
      showAlert('ล็อกหน้าจอและล้างหน่วยความจำอัตโนมัติ (ไม่มีการใช้งานครบ 3 นาที)', 'warning');
      await refreshAppStatus();
    }, 180000);
  }

  async function renderDecryptedSeedView(unlockResult) {
    clearDecryptedMemoryAndLock();
    lastDecryptedPayload = unlockResult.payload;
    wordsMasked = false;

    setupView.classList.add('hidden');
    unlockView.classList.add('hidden');
    decryptedView.classList.remove('hidden');

    unlockedSeedDisplayCard.classList.remove('hidden');
    directHwModeBanner.classList.add('hidden');
    if (openDirectHwModeTopBtn) {
      openDirectHwModeTopBtn.classList.add('hidden');
    }
    const keySourceTabsWrapper = document.getElementById('keySourceTabsWrapper');
    if (keySourceTabsWrapper) {
      keySourceTabsWrapper.classList.remove('hidden');
    }

    decryptedWordCount.textContent = String(lastDecryptedPayload.wordCount);
    unlockedBySlotText.textContent = `ปลดล็อกสำเร็จด้วยเงื่อนไข: ${unlockResult.matchedSlotLabel}`;

    decryptedWordsGrid.innerHTML = '';
    lastDecryptedPayload.words.forEach((word, index) => {
      const card = document.createElement('div');
      card.className = 'decrypted-word-card';
      card.innerHTML = `
        <span class="seed-word-index">${index + 1}.</span>
        <span class="decrypted-word-text">${escapeHtml(word)}</span>
      `;
      decryptedWordsGrid.appendChild(card);
    });

    if (lastDecryptedPayload.hasPassphrase25 && lastDecryptedPayload.passphrase25) {
      decryptedPassphraseBox.classList.remove('hidden');
      decryptedPassphraseValue.textContent = lastDecryptedPayload.passphrase25;
      signingPassphrase25Input.value = lastDecryptedPayload.passphrase25;
    } else {
      decryptedPassphraseBox.classList.add('hidden');
      decryptedPassphraseValue.textContent = '';
      signingPassphrase25Input.value = '';
    }

    // Default after unlocking: Use Vault Seed!
    modeVaultSeedBtn.disabled = false;
    modeManualSeedBtn.disabled = false;
    setKeySourceMode('VAULT_SEED');
    renderUtxoTable();
    resetAutoLockTimer();
    await refreshDerivedBitcoinWallet();
  }

  function setKeySourceMode(mode) {
    currentKeySourceMode = mode;
    modeVaultSeedBtn.classList.toggle('active', mode === 'VAULT_SEED');
    modeManualSeedBtn.classList.toggle('active', mode === 'MANUAL_SEED');
    modeHardwareUsbBtn.classList.toggle('active', mode === 'HARDWARE_USB');

    manualSeedImportPanel.classList.toggle('hidden', mode !== 'MANUAL_SEED');
    hardwareUsbPanel.classList.toggle('hidden', mode !== 'HARDWARE_USB');
    seedDerivationControls.classList.toggle('hidden', mode === 'HARDWARE_USB');

    if (mode === 'HARDWARE_USB') {
      const hwAddr = hwWalletAddressInput.value.trim();
      btcActiveAddressDisplay.textContent = hwAddr || '(เชื่อมต่อ Trezor/Ledger หรือกรอก Address ด้านบน)';
      btcTaprootSegwitDisplay.textContent = 'โหมดใช้กุญแจจากชิป Trezor / Ledger โดยตรง (ไม่เปิดเผย Seed)';
      btcLegacyFingerprintDisplay.textContent = 'สร้างธุรกรรมเป็นมาตรฐาน BIP174 PSBT / Trezor SignTx';
      if (currentWalletDerivedState.changeAddress) {
        changeAddressInput.value = currentWalletDerivedState.changeAddress;
      } else if (hwAddr && !changeAddressInput.value.trim()) {
        changeAddressInput.value = hwAddr;
      }
    } else {
      refreshDerivedBitcoinWallet();
    }
  }

  modeVaultSeedBtn.addEventListener('click', async () => {
    if (!lastDecryptedPayload) {
      // If clicked while vault is locked, navigate straight back to the Unlock Screen!
      clearDecryptedMemoryAndLock();
      hideAlert();
      await refreshAppStatus();
      return;
    }
    setKeySourceMode('VAULT_SEED');
  });

  modeManualSeedBtn.addEventListener('click', () => {
    setKeySourceMode('MANUAL_SEED');
  });

  modeHardwareUsbBtn.addEventListener('click', () => {
    setKeySourceMode('HARDWARE_USB');
  });

  manualSeedTextarea.addEventListener('input', () => {
    const words = getActiveSeedWords();
    if ([12, 15, 18, 20, 24].includes(words.length)) {
      refreshDerivedBitcoinWallet();
    }
  });

  hwWalletAddressInput.addEventListener('input', () => {
    if (currentKeySourceMode === 'HARDWARE_USB') {
      const addr = hwWalletAddressInput.value.trim();
      btcActiveAddressDisplay.textContent = addr || '-';
      if (!changeAddressInput.value.trim()) {
        changeAddressInput.value = addr;
      }
    }
  });

  function getActiveSeedWords() {
    if (currentKeySourceMode === 'VAULT_SEED' && lastDecryptedPayload) {
      return lastDecryptedPayload.words;
    }
    if (currentKeySourceMode === 'MANUAL_SEED') {
      return manualSeedTextarea.value
        .trim()
        .split(/\s+/)
        .map((w) => w.trim().toLowerCase())
        .filter(Boolean);
    }
    return [];
  }

  // Script Type Selector Pills (Taproot / Native SegWit / Nested SegWit / Legacy)
  document.querySelectorAll('.script-pill').forEach((pill) => {
    pill.addEventListener('click', async () => {
      document.querySelectorAll('.script-pill').forEach((p) => p.classList.remove('active'));
      pill.classList.add('active');
      currentScriptType = pill.dataset.script;
      btcDerivationPathInput.value = pill.dataset.path;
      activeScriptNameLabel.textContent = SCRIPT_LABELS[currentScriptType] || currentScriptType;
      await refreshDerivedBitcoinWallet();
    });
  });

  // Track active USB Hardware Wallet session (Ledger WebHID / Trezor WebUSB)
  const activeHardwareSession = {
    type: null, // 'LEDGER' | 'TREZOR'
    device: null,
    epIn: 1,
    epOut: 1,
    lastPassphrase: null,
  };

  function toInternalChangePathClient(pathStr) {
    const clean = String(pathStr || "m/84'/0'/0'/0/0")
      .trim()
      .replace(/^m\/?/i, '');
    const parts = clean.split('/').filter(Boolean);
    if (parts.length >= 5) {
      const chg = [...parts];
      chg[3] = '1';
      return 'm/' + chg.join('/');
    }
    return "m/84'/0'/0'/1/0";
  }

  function updateWalletDisplayAndFreshChange(w) {
    const freshChange = w.changeAddress || w.activeAddress;
    const freshChangePath = w.changePath || toInternalChangePathClient(w.path || btcDerivationPathInput.value);
    currentWalletDerivedState = {
      activeAddress: w.activeAddress,
      changeAddress: freshChange,
      changePath: freshChangePath,
      scanAddresses: Array.isArray(w.scanAddresses) ? w.scanAddresses : [],
      taprootAddress: w.taprootAddress || '',
      segwitAddress: w.segwitAddress || '',
      nestedSegwitAddress: w.nestedSegwitAddress || '',
      legacyAddress: w.legacyAddress || '',
      masterFingerprint: w.masterFingerprint || '',
      publicKeyHex: w.publicKeyHex || '',
      changePublicKeyHex: w.changePublicKeyHex || '',
      xpub: w.xpub || '',
    };
    btcActiveAddressDisplay.textContent = w.activeAddress;
    btcTaprootSegwitDisplay.textContent = `Taproot: ${w.taprootAddress}  |  Native SegWit: ${w.segwitAddress}`;
    btcLegacyFingerprintDisplay.textContent = `SegWit: ${w.nestedSegwitAddress}  |  Legacy: ${w.legacyAddress}  |  FP: [${w.masterFingerprint}]`;

    // Always set Change Address to the fresh internal change address (m/.../1/0) so it never reuses the receiving address!
    changeAddressInput.value = freshChange;
    if (changePathHintText) {
      changePathHintText.innerHTML = `🔒 สร้าง Address รับเงินทอนใหม่จาก Internal Change Path (<code>${escapeHtml(freshChangePath)}</code>) ไม่ซ้ำกับ Address รับเงินเดิม และทำให้หน้าจอ Trezor ยืนยันเงินทอนกลับเข้ากระเป๋าโดยไม่ขึ้น Unknown Path`;
    }
  }

  async function refreshDerivedBitcoinWallet() {
    resetAutoLockTimer();
    activeScriptNameLabel.textContent = SCRIPT_LABELS[currentScriptType] || currentScriptType;

    if (currentKeySourceMode === 'HARDWARE_USB') {
      if (activeHardwareSession.type === 'LEDGER' && activeHardwareSession.device) {
        await scanAddressAndUtxoFromLedger(activeHardwareSession.device, true);
        return;
      }
      if (activeHardwareSession.type === 'TREZOR' && activeHardwareSession.device) {
        await scanAddressAndUtxoFromTrezor(activeHardwareSession.device, false, true);
        return;
      }
      const addr = hwWalletAddressInput.value.trim();
      btcActiveAddressDisplay.textContent = addr || '(กด Connect Ledger หรือ Trezor ด้านบนเพื่อสแกน Address อัตโนมัติ)';
      return;
    }

    const words = getActiveSeedWords();
    if (![12, 15, 18, 20, 24].includes(words.length)) {
      btcActiveAddressDisplay.textContent = '(รอการระบุ Seedphrase 12/15/18/20/24 คำ)';
      return;
    }

    try {
      const res = await apiPost('/api/btc/derive', {
        words,
        passphrase25: signingPassphrase25Input.value.trim(),
        scriptType: currentScriptType,
        derivationPath: btcDerivationPathInput.value.trim() || "m/84'/0'/0'/0/0",
      });
      const data = await res.json();
      if (data.ok && data.wallet) {
        updateWalletDisplayAndFreshChange(data.wallet);
      } else {
        showAlert(data.error || 'ไม่สามารถคำนวณ Bitcoin Address ได้', 'warning');
      }
    } catch (_err) {
      // Ignore transient error
    }
  }

  deriveWalletBtn.addEventListener('click', refreshDerivedBitcoinWallet);
  signingPassphrase25Input.addEventListener('change', refreshDerivedBitcoinWallet);

  // =========================================================================
  // 5. Interactive UTXO Coin Selection Table & Auto Blockchain Scanner
  // =========================================================================
  function parseSendAmountToIntegerSats() {
    const rawVal = String(sendAmountSatsInput.value || '').trim();
    if (!rawVal) return 0;
    const num = Number(rawVal);
    if (!Number.isFinite(num) || num <= 0) return 0;

    const unit = sendAmountUnitSelect ? sendAmountUnitSelect.value : 'SATS';
    if (unit === 'BTC') {
      return Math.round(num * 100000000);
    }
    // Even if user is in SATS mode and types a decimal like 355805.4, safely round to integer Satoshis!
    return Math.round(num);
  }

  function renderUtxoTable() {
    utxoTableBody.innerHTML = '';

    utxoItems.forEach((item, index) => {
      const tr = document.createElement('tr');
      tr.innerHTML = `
        <td class="text-center">
          <input type="checkbox" class="utxo-chk" data-idx="${index}" ${item.selected ? 'checked' : ''} />
        </td>
        <td>
          <input type="text" class="text-input mono-input utxo-txid" data-idx="${index}" placeholder="TXID 64 ตัวอักษร..." value="${escapeHtml(item.txid)}" />
        </td>
        <td>
          <input type="number" class="text-input utxo-vout" data-idx="${index}" min="0" step="1" value="${Math.round(Number(item.vout || 0))}" />
        </td>
        <td>
          <input type="number" class="text-input utxo-sats" data-idx="${index}" min="1" step="1" value="${Math.round(Number(item.amountSats || 0))}" />
        </td>
        <td class="text-center">
          <button type="button" class="btn btn-secondary btn-sm utxo-del" data-idx="${index}">✕</button>
        </td>
      `;
      utxoTableBody.appendChild(tr);
    });

    utxoTableBody.querySelectorAll('.utxo-chk').forEach((el) => {
      el.addEventListener('change', (e) => {
        const idx = Number(e.target.dataset.idx);
        utxoItems[idx].selected = e.target.checked;
        recalculateUtxoAndChangeSummary();
      });
    });

    utxoTableBody.querySelectorAll('.utxo-txid').forEach((el) => {
      el.addEventListener('input', (e) => {
        const idx = Number(e.target.dataset.idx);
        utxoItems[idx].txid = e.target.value.trim();
      });
    });

    utxoTableBody.querySelectorAll('.utxo-vout').forEach((el) => {
      el.addEventListener('input', (e) => {
        const idx = Number(e.target.dataset.idx);
        utxoItems[idx].vout = Math.round(Number(e.target.value || 0));
      });
    });

    utxoTableBody.querySelectorAll('.utxo-sats').forEach((el) => {
      el.addEventListener('input', (e) => {
        const idx = Number(e.target.dataset.idx);
        utxoItems[idx].amountSats = Math.round(Number(e.target.value || 0));
        recalculateUtxoAndChangeSummary();
      });
    });

    utxoTableBody.querySelectorAll('.utxo-del').forEach((el) => {
      el.addEventListener('click', (e) => {
        const idx = Number(e.target.dataset.idx);
        if (utxoItems.length > 1) {
          utxoItems.splice(idx, 1);
          renderUtxoTable();
        }
      });
    });

    recalculateUtxoAndChangeSummary();
  }

  function recalculateUtxoAndChangeSummary() {
    const selected = utxoItems.filter((u) => u.selected);
    const totalIn = selected.reduce((acc, u) => acc + Math.round(Number(u.amountSats) || 0), 0);
    selectedUtxoCountText.textContent = String(selected.length);
    selectedUtxoTotalSatsText.textContent = totalIn.toLocaleString();

    const sendSats = parseSendAmountToIntegerSats();
    const feeSats = Math.round(Number(feeSatsInput.value || 0));
    const changeSats = Math.max(0, totalIn - sendSats - feeSats);
    changeAmountSatsInput.value = String(changeSats);

    if (sendAmountConversionHint) {
      const btcEquivalent = (sendSats / 100000000).toFixed(8);
      sendAmountConversionHint.textContent = `= ${sendSats.toLocaleString()} Satoshis (${btcEquivalent} BTC)`;
    }
  }

  sendAmountSatsInput.addEventListener('input', recalculateUtxoAndChangeSummary);
  if (sendAmountUnitSelect) {
    sendAmountUnitSelect.addEventListener('change', () => {
      const rawVal = Number(sendAmountSatsInput.value || 0);
      if (rawVal > 0) {
        if (sendAmountUnitSelect.value === 'BTC') {
          sendAmountSatsInput.value = (rawVal / 100000000).toFixed(8);
        } else {
          sendAmountSatsInput.value = String(Math.round(rawVal * 100000000));
        }
      }
      recalculateUtxoAndChangeSummary();
    });
  }
  feeSatsInput.addEventListener('input', recalculateUtxoAndChangeSummary);

  addCustomUtxoRowBtn.addEventListener('click', () => {
    utxoItems.push({ selected: true, txid: '', vout: 0, amountSats: 50000 });
    renderUtxoTable();
  });

  async function fetchJsonWithBlockchainFallback(urls) {
    let lastErr = null;
    for (const url of urls) {
      try {
        const res = await fetch(url);
        if (res.ok) {
          return await res.json();
        }
        lastErr = new Error(`HTTP ${res.status}`);
      } catch (err) {
        lastErr = err;
      }
    }
    throw lastErr || new Error('ไม่สามารถเชื่อมต่อเครือข่าย Blockchain API ได้');
  }

  async function fetchTextWithBlockchainFallback(urls) {
    for (const url of urls) {
      try {
        const res = await fetch(url);
        if (res.ok) {
          return (await res.text()).trim();
        }
      } catch (_err) {
        // Try next mirror
      }
    }
    return '';
  }

  async function autoFetchUtxosForAddress(targetAddress, silentIfEmpty = false, candidateList = null) {
    const activeAddr = String(targetAddress || '').trim();
    if (!activeAddr || activeAddr.startsWith('(') || activeAddr === '-') {
      if (!silentIfEmpty) {
        showAlert('กรุณาเชื่อมต่อ Hardware Wallet หรือคำนวณ Bitcoin Address ก่อนกดดึงรายการ UTXO', 'warning');
      }
      return;
    }

    const defaultPath = btcDerivationPathInput.value.trim() || "m/84'/0'/0'/0/0";
    const candidatesMap = new Map();
    candidatesMap.set(activeAddr, {
      address: activeAddr,
      derivationPath: defaultPath,
      branch: 'receive',
      index: 0,
    });

    const extraCandidates = Array.isArray(candidateList)
      ? candidateList
      : Array.isArray(currentWalletDerivedState.scanAddresses)
      ? currentWalletDerivedState.scanAddresses
      : [];

    for (const c of extraCandidates) {
      if (c && c.address && !candidatesMap.has(c.address)) {
        candidatesMap.set(c.address, {
          address: c.address,
          derivationPath: c.derivationPath || defaultPath,
          branch: c.branch || 'receive',
          index: c.index || 0,
        });
      }
    }

    const candidates = Array.from(candidatesMap.values());

    try {
      let anyApiSucceeded = false;
      const discovered = [];
      const seenOutpoints = new Set();

      await Promise.all(
        candidates.map(async (cand) => {
          try {
            const list = await fetchJsonWithBlockchainFallback([
              `https://mempool.space/api/address/${encodeURIComponent(cand.address)}/utxo`,
              `https://blockstream.info/api/address/${encodeURIComponent(cand.address)}/utxo`,
            ]);
            anyApiSucceeded = true;
            if (Array.isArray(list)) {
              for (const u of list) {
                const key = `${u.txid}:${u.vout}`;
                if (!seenOutpoints.has(key)) {
                  seenOutpoints.add(key);
                  discovered.push({
                    rawUtxo: u,
                    address: cand.address,
                    derivationPath: cand.derivationPath,
                  });
                }
              }
            }
          } catch (_e) {
            // Ignore single candidate failure if others succeed
          }
        })
      );

      if (!anyApiSucceeded) {
        throw new Error('ไม่สามารถเชื่อมต่อเครือข่ายได้');
      }

      if (discovered.length === 0) {
        if (!silentIfEmpty) {
          showAlert(
            `สแกนสำเร็จ (${candidates.length} Address ในบัญชี): ไม่พบรายการเหรียญ UTXO คงเหลือใน Address: ${activeAddr}`,
            'warning'
          );
        }
        return;
      }

      // Also pre-fetch rawTxHex for each UTXO (used by trezor-firmware SignTx prev_tx verification offline)
      const enriched = await Promise.all(
        discovered.map(async (item) => {
          const u = item.rawUtxo;
          const rawTxHex = await fetchTextWithBlockchainFallback([
            `https://mempool.space/api/tx/${encodeURIComponent(u.txid)}/hex`,
            `https://blockstream.info/api/tx/${encodeURIComponent(u.txid)}/hex`,
          ]);
          return {
            selected: true,
            txid: u.txid,
            vout: Math.round(Number(u.vout || 0)),
            amountSats: Math.round(Number(u.value || 0)),
            rawTxHex,
            address: item.address,
            scriptType: currentScriptType,
            derivationPath: item.derivationPath || defaultPath,
          };
        })
      );

      utxoItems = enriched;
      renderUtxoTable();
      const totalFoundSats = enriched.reduce((acc, u) => acc + u.amountSats, 0);
      showAlert(
        `🎉 สแกนพบ ${utxoItems.length} UTXO (รวม ${totalFoundSats.toLocaleString()} Sats) ในกระเป๋าพร้อมลงนามธุรกรรมทันที!`,
        'success'
      );
    } catch (_err) {
      if (!silentIfEmpty) {
        showAlert(
          'เครื่องปัจจุบันทำงานอยู่ในโหมด Offline (ไม่ได้ต่อเน็ต) คุณสามารถกด "📂 โหลด UTXO (Offline)" หรือกรอกรายการ UTXO ในตารางได้โดยตรง',
          'warning'
        );
      }
    }
  }

  // Scan UTXOs automatically from Blockchain (Mempool.space / Blockstream API when online)
  scanBlockchainUtxoBtn.addEventListener('click', async () => {
    const activeAddr =
      currentKeySourceMode === 'HARDWARE_USB'
        ? hwWalletAddressInput.value.trim() || btcActiveAddressDisplay.textContent.trim()
        : btcActiveAddressDisplay.textContent.trim();
    await autoFetchUtxosForAddress(activeAddr, false, currentWalletDerivedState.scanAddresses);
  });

  // Export Offline UTXO Bundle (.json) to Flash Drive for Air-Gapped Signing
  if (exportOfflineUtxoBtn) {
    exportOfflineUtxoBtn.addEventListener('click', () => {
      const activeAddr =
        currentKeySourceMode === 'HARDWARE_USB'
          ? hwWalletAddressInput.value.trim()
          : btcActiveAddressDisplay.textContent.trim();
      const bundle = {
        exportedAt: new Date().toISOString(),
        address: activeAddr,
        changeAddress: currentWalletDerivedState.changeAddress || changeAddressInput.value.trim(),
        changePath: currentWalletDerivedState.changePath || toInternalChangePathClient(btcDerivationPathInput.value),
        scriptType: currentScriptType,
        derivationPath: btcDerivationPathInput.value.trim(),
        utxos: utxoItems,
      };
      const blob = new Blob([JSON.stringify(bundle, null, 2)], { type: 'application/json' });
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `seedvault-utxos-${(activeAddr || 'wallet').slice(0, 10)}.json`;
      a.click();
      URL.revokeObjectURL(url);
      showAlert('บันทึกไฟล์ UTXO Bundle (.json) สำเร็จ! สามารถนำไปเปิดเซ็นบนเครื่อง Offline ได้ทันที', 'success');
    });
  }

  if (importOfflineUtxoBtn && importOfflineUtxoFileInput) {
    importOfflineUtxoBtn.addEventListener('click', () => {
      importOfflineUtxoFileInput.value = '';
      importOfflineUtxoFileInput.click();
    });

    importOfflineUtxoFileInput.addEventListener('change', async (e) => {
      const file = e.target.files && e.target.files[0];
      if (!file) return;
      try {
        const text = await file.text();
        const bundle = JSON.parse(text);
        if (!Array.isArray(bundle.utxos) || bundle.utxos.length === 0) {
          throw new Error('ไฟล์ไม่มีรายการ UTXO ที่ถูกต้อง');
        }
        utxoItems = bundle.utxos.map((u) => ({
          selected: u.selected !== false,
          txid: String(u.txid || '').trim(),
          vout: Math.round(Number(u.vout || 0)),
          amountSats: Math.round(Number(u.amountSats || 0)),
          rawTxHex: String(u.rawTxHex || '').trim(),
          scriptType: u.scriptType || bundle.scriptType || currentScriptType,
          derivationPath: u.derivationPath || bundle.derivationPath || btcDerivationPathInput.value.trim(),
        }));
        if (bundle.address && currentKeySourceMode === 'HARDWARE_USB' && !hwWalletAddressInput.value.trim()) {
          hwWalletAddressInput.value = bundle.address;
          btcActiveAddressDisplay.textContent = bundle.address;
          changeAddressInput.value = bundle.changeAddress || bundle.address;
        }
        renderUtxoTable();
        showAlert(`โหลดไฟล์ Offline UTXO สำเร็จ (${utxoItems.length} รายการ) พร้อมลงนามธุรกรรมแบบ Offline!`, 'success');
      } catch (err) {
        showAlert(`ไม่สามารถอ่านไฟล์ UTXO ได้: ${err.message}`, 'error');
      }
    });
  }

  // =========================================================================
  // 5B. Direct Hardware Wallet Protocol Drivers (Ledger WebHID & Trezor WebUSB)
  // =========================================================================
  function bytesToHex(uint8) {
    return Array.from(uint8)
      .map((b) => b.toString(16).padStart(2, '0'))
      .join('');
  }

  function hexToBytes(hex) {
    const clean = String(hex || '').trim().replace(/^0x/i, '');
    const out = new Uint8Array(clean.length / 2);
    for (let i = 0; i < clean.length; i += 2) {
      out[i / 2] = parseInt(clean.slice(i, i + 2), 16) || 0;
    }
    return out;
  }

  function sha256Sync(data) {
    const K = [
      0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
      0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
      0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
      0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
      0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
      0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
      0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
      0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
    ];
    let h0 = 0x6a09e667, h1 = 0xbb67ae85, h2 = 0x3c6ef372, h3 = 0xa54ff53a;
    let h4 = 0x510e527f, h5 = 0x9b05688c, h6 = 0x1f83d9ab, h7 = 0x5be0cd19;
    const bytes = (data instanceof Uint8Array) ? data : (typeof data === 'string' ? new TextEncoder().encode(data) : new Uint8Array(data));
    const len = bytes.length;
    const bitLen = len * 8;
    const paddedLen = (((len + 8) >>> 6) + 1) << 6;
    const padded = new Uint8Array(paddedLen);
    padded.set(bytes, 0);
    padded[len] = 0x80;
    const view = new DataView(padded.buffer);
    view.setUint32(paddedLen - 4, bitLen >>> 0, false);
    view.setUint32(paddedLen - 8, Math.floor(bitLen / 0x100000000), false);
    const w = new Uint32Array(64);
    for (let i = 0; i < paddedLen; i += 64) {
      for (let t = 0; t < 16; t++) {
        w[t] = view.getUint32(i + (t << 2), false);
      }
      for (let t = 16; t < 64; t++) {
        const s0 = ((w[t - 15] >>> 7) | (w[t - 15] << 25)) ^ ((w[t - 15] >>> 18) | (w[t - 15] << 14)) ^ (w[t - 15] >>> 3);
        const s1 = ((w[t - 2] >>> 17) | (w[t - 2] << 15)) ^ ((w[t - 2] >>> 19) | (w[t - 2] << 13)) ^ (w[t - 2] >>> 10);
        w[t] = (w[t - 16] + s0 + w[t - 7] + s1) >>> 0;
      }
      let a = h0, b = h1, c = h2, d = h3, e = h4, f = h5, g = h6, h = h7;
      for (let t = 0; t < 64; t++) {
        const S1 = ((e >>> 6) | (e << 26)) ^ ((e >>> 11) | (e << 21)) ^ ((e >>> 25) | (e << 7));
        const ch = (e & f) ^ ((~e) & g);
        const temp1 = (h + S1 + ch + K[t] + w[t]) >>> 0;
        const S0 = ((a >>> 2) | (a << 30)) ^ ((a >>> 13) | (a << 19)) ^ ((a >>> 22) | (a << 10));
        const maj = (a & b) ^ (a & c) ^ (b & c);
        const temp2 = (S0 + maj) >>> 0;
        h = g; g = f; f = e; e = (d + temp1) >>> 0;
        d = c; c = b; b = a; a = (temp1 + temp2) >>> 0;
      }
      h0 = (h0 + a) >>> 0; h1 = (h1 + b) >>> 0; h2 = (h2 + c) >>> 0; h3 = (h3 + d) >>> 0;
      h4 = (h4 + e) >>> 0; h5 = (h5 + f) >>> 0; h6 = (h6 + g) >>> 0; h7 = (h7 + h) >>> 0;
    }
    const out = new Uint8Array(32);
    const outView = new DataView(out.buffer);
    outView.setUint32(0, h0, false); outView.setUint32(4, h1, false);
    outView.setUint32(8, h2, false); outView.setUint32(12, h3, false);
    outView.setUint32(16, h4, false); outView.setUint32(20, h5, false);
    outView.setUint32(24, h6, false); outView.setUint32(28, h7, false);
    return out;
  }

  function encodeBtcVarInt(n) {
    const num = Number(n);
    if (num < 0xfd) {
      return new Uint8Array([num]);
    } else if (num <= 0xffff) {
      return new Uint8Array([0xfd, num & 0xff, (num >>> 8) & 0xff]);
    } else if (num <= 0xffffffff) {
      return new Uint8Array([
        0xfe,
        num & 0xff,
        (num >>> 8) & 0xff,
        (num >>> 16) & 0xff,
        (num >>> 24) & 0xff,
      ]);
    } else {
      const b = BigInt(n);
      const res = new Uint8Array(9);
      res[0] = 0xff;
      for (let i = 0; i < 8; i++) {
        res[1 + i] = Number((b >> BigInt(i * 8)) & 0xffn);
      }
      return res;
    }
  }

  function decodeBtcVarInt(buf, offset = 0) {
    const first = buf[offset];
    if (first < 0xfd) {
      return { value: first, length: 1 };
    }
    if (first === 0xfd) {
      return { value: buf[offset + 1] | (buf[offset + 2] << 8), length: 3 };
    }
    if (first === 0xfe) {
      const val = (buf[offset + 1] | (buf[offset + 2] << 8) | (buf[offset + 3] << 16) | (buf[offset + 4] << 24)) >>> 0;
      return { value: val, length: 5 };
    }
    let val = 0n;
    for (let i = 0; i < 8; i++) {
      val |= BigInt(buf[offset + 1 + i]) << BigInt(i * 8);
    }
    return { value: Number(val), length: 9 };
  }

  class LedgerMerkleNode {
    constructor(leftChild, rightChild, hash) {
      this.leftChild = leftChild;
      this.rightChild = rightChild;
      this.hash = hash;
      this.parent = null;
    }
  }

  class LedgerMerkleLeaf {
    constructor(value, hash) {
      this.value = value;
      this.hash = hash;
      this.parent = null;
    }
  }

  class LedgerMerkleTree {
    constructor(root, leaves) {
      this.root = root;
      this.leaves = leaves;
    }
    getRoot() {
      return this.root.hash;
    }
    size() {
      return this.leaves.length;
    }
    getLeafHash(index) {
      return this.leaves[index] ? this.leaves[index].hash : null;
    }
    getProof(index) {
      const leaf = this.leaves[index];
      if (!leaf) return null;
      return this.proveNode(leaf);
    }
    proveNode(node) {
      if (!node.parent) return [];
      const parent = node.parent;
      const siblingHash = parent.leftChild === node ? parent.rightChild.hash : parent.leftChild.hash;
      return [siblingHash, ...this.proveNode(parent)];
    }
  }

  function highestPowerOf2LessThan(n) {
    if (n < 2) throw new Error('Expected n >= 2');
    if ((n & (n - 1)) === 0) return n / 2;
    return 1 << Math.floor(Math.log2(n));
  }

  function buildMerkleTree(leafByteArrays) {
    if (leafByteArrays.length === 0) {
      const emptyLeaf = new LedgerMerkleLeaf(new Uint8Array(0), new Uint8Array(32));
      return new LedgerMerkleTree(emptyLeaf, []);
    }
    const leaves = leafByteArrays.map((arr) => {
      const prefixed = new Uint8Array(1 + arr.length);
      prefixed[0] = 0x00;
      prefixed.set(arr, 1);
      return new LedgerMerkleLeaf(prefixed, sha256Sync(prefixed));
    });

    function buildSubtree(leafSlice) {
      if (leafSlice.length === 1) {
        return { root: leafSlice[0], leaves: leafSlice };
      }
      const leftCount = highestPowerOf2LessThan(leafSlice.length);
      const leftBranch = buildSubtree(leafSlice.slice(0, leftCount));
      const rightBranch = buildSubtree(leafSlice.slice(leftCount));
      const leftChild = leftBranch.root;
      const rightChild = rightBranch.root;

      const nodeBuf = new Uint8Array(1 + 32 + 32);
      nodeBuf[0] = 0x01;
      nodeBuf.set(leftChild.hash, 1);
      nodeBuf.set(rightChild.hash, 33);
      const node = new LedgerMerkleNode(leftChild, rightChild, sha256Sync(nodeBuf));
      leftChild.parent = node;
      rightChild.parent = node;
      return {
        root: node,
        leaves: [...leftBranch.leaves, ...rightBranch.leaves],
      };
    }

    const { root, leaves: allLeaves } = buildSubtree(leaves);
    return new LedgerMerkleTree(root, allLeaves);
  }

  class LedgerMerkleMap {
    constructor(keysTree, valuesTree) {
      this.keys = keysTree;
      this.values = valuesTree;
    }
    getCommitment() {
      const sizeVar = encodeBtcVarInt(this.keys.size());
      const res = new Uint8Array(sizeVar.length + 32 + 32);
      res.set(sizeVar, 0);
      res.set(this.keys.getRoot(), sizeVar.length);
      res.set(this.values.getRoot(), sizeVar.length + 32);
      return res;
    }
  }

  function buildMerkleMap(entries) {
    const sorted = entries.slice().sort((a, b) => {
      const ha = bytesToHex(a.key);
      const hb = bytesToHex(b.key);
      return ha.localeCompare(hb);
    });
    const keys = sorted.map((e) => e.key);
    const values = sorted.map((e) => e.value);
    const keysTree = buildMerkleTree(keys);
    const valuesTree = buildMerkleTree(values);
    return new LedgerMerkleMap(keysTree, valuesTree);
  }

  class LedgerDataStore {
    constructor() {
      this.merkleTrees = new Map();
      this.preimages = new Map();
    }
    addPreimage(hash, preimage) {
      this.preimages.set(bytesToHex(hash).toLowerCase(), preimage);
    }
    addMerkleTree(tree) {
      for (const leaf of tree.leaves) {
        this.preimages.set(bytesToHex(leaf.hash).toLowerCase(), leaf.value);
      }
      this.merkleTrees.set(bytesToHex(tree.getRoot()).toLowerCase(), tree);
    }
    addMerkleMap(map) {
      this.addMerkleTree(map.keys);
      this.addMerkleTree(map.values);
    }
    getPreimage(hash) {
      return this.preimages.get(bytesToHex(hash).toLowerCase()) || null;
    }
    getMerkleLeafIndex(rootHash, leafHash) {
      const tree = this.merkleTrees.get(bytesToHex(rootHash).toLowerCase());
      if (!tree) return -1;
      const lHex = bytesToHex(leafHash).toLowerCase();
      return tree.leaves.findIndex((l) => bytesToHex(l.hash).toLowerCase() === lHex);
    }
    getMerkleProof(rootHash, leafIndex) {
      const tree = this.merkleTrees.get(bytesToHex(rootHash).toLowerCase());
      if (!tree) return null;
      const leafHash = tree.getLeafHash(leafIndex);
      const proof = tree.getProof(leafIndex);
      if (!leafHash || !proof) return null;
      return { leafHash, proof };
    }
  }

  function parseBip32PathSteps(pathStr) {
    const clean = String(pathStr || "m/84'/0'/0'/0/0")
      .trim()
      .replace(/^m\/?/i, '');
    const parts = clean.split('/').filter(Boolean);
    const steps = parts.map((seg) => {
      const hardened = seg.endsWith("'") || seg.toLowerCase().endsWith('h');
      const idx = parseInt(seg.replace(/['hH]$/, ''), 10) || 0;
      return hardened ? ((idx | 0x80000000) >>> 0) : (idx >>> 0);
    });
    const accountSteps = steps.slice(0, Math.min(3, steps.length));
    const childPath = parts
      .slice(3)
      .map((s) => s.replace(/['hH]$/, ''))
      .join('/');
    return { steps, accountSteps, childPath };
  }

  function serializePathBytes(stepsArray) {
    const buf = new Uint8Array(1 + stepsArray.length * 4);
    buf[0] = stepsArray.length;
    stepsArray.forEach((val, i) => {
      const off = 1 + i * 4;
      buf[off] = (val >>> 24) & 0xff;
      buf[off + 1] = (val >>> 16) & 0xff;
      buf[off + 2] = (val >>> 8) & 0xff;
      buf[off + 3] = val & 0xff;
    });
    return buf;
  }

  async function applyHardwareWalletDerivedResult(hwData, deviceLabel) {
    const res = await apiPost('/api/btc/hw-derive', {
      ...hwData,
      scriptType: currentScriptType,
      derivationPath: btcDerivationPathInput.value.trim() || "m/84'/0'/0'/0/0",
    });
    const data = await res.json();
    if (!res.ok || !data.ok || !data.wallet) {
      throw new Error(data.error || 'ไม่สามารถแปลง Public Key จาก Hardware Wallet เป็น Address ได้');
    }

    const w = data.wallet;
    hwWalletAddressInput.value = w.activeAddress;
    updateWalletDisplayAndFreshChange(w);

    hardwareUsbStatusText.innerHTML = `✅ <strong>${escapeHtml(deviceLabel)}</strong> เชื่อมต่อและดึง Address อัตโนมัติสำเร็จ!<br/>Address รับเงิน (${escapeHtml(SCRIPT_LABELS[currentScriptType])}): <code>${escapeHtml(w.activeAddress)}</code><br/>Address รับเงินทอนใหม่ (${escapeHtml(w.changePath || "m/84'/0'/0'/1/0")}): <code>${escapeHtml(w.changeAddress || w.activeAddress)}</code>`;
    showAlert(
      `สแกน Address (${SCRIPT_LABELS[currentScriptType]}) จาก ${deviceLabel} สำเร็จ: ${w.activeAddress} — กำลังค้นหา UTXO...`,
      'success'
    );

    await autoFetchUtxosForAddress(w.activeAddress, false, w.scanAddresses);
  }

  // --- Ledger WebHID APDU Framing (Channel 0x0101, Tag 0x05) ---
  async function exchangeLedgerApdu(hidDevice, apduBytes, timeoutMs = 25000) {
    if (!hidDevice.opened) {
      await hidDevice.open();
    }
    return new Promise((resolve, reject) => {
      let totalLen = 0;
      let receivedLen = 0;
      let responseBuf = null;
      let expectedSeq = 0;

      const timer = setTimeout(() => {
        hidDevice.removeEventListener('inputreport', onReport);
        reject(new Error('หมดเวลารอการตอบกลับจาก Ledger (กรุณาปลดล็อกเครื่องและเปิดแอป Bitcoin บนหน้าจอ Ledger)'));
      }, timeoutMs);

      function onReport(event) {
        try {
          const data = new Uint8Array(event.data.buffer, event.data.byteOffset, event.data.byteLength);
          if (data.length < 7 || data[0] !== 0x01 || data[1] !== 0x01 || data[2] !== 0x05) {
            return;
          }
          const seq = (data[3] << 8) | data[4];
          if (seq !== expectedSeq) return;
          expectedSeq++;

          if (seq === 0) {
            totalLen = (data[5] << 8) | data[6];
            responseBuf = new Uint8Array(totalLen);
            const chunkLen = Math.min(57, totalLen);
            responseBuf.set(data.subarray(7, 7 + chunkLen), 0);
            receivedLen = chunkLen;
          } else {
            const rem = totalLen - receivedLen;
            const chunkLen = Math.min(59, rem);
            responseBuf.set(data.subarray(5, 5 + chunkLen), receivedLen);
            receivedLen += chunkLen;
          }

          if (receivedLen >= totalLen && totalLen >= 2) {
            clearTimeout(timer);
            hidDevice.removeEventListener('inputreport', onReport);
            const sw = (responseBuf[totalLen - 2] << 8) | responseBuf[totalLen - 1];
            const payload = responseBuf.subarray(0, totalLen - 2);
            resolve({ sw, payload });
          }
        } catch (err) {
          clearTimeout(timer);
          hidDevice.removeEventListener('inputreport', onReport);
          reject(err);
        }
      }

      hidDevice.addEventListener('inputreport', onReport);

      (async () => {
        try {
          let offset = 0;
          let seq = 0;
          while (offset < apduBytes.length || seq === 0) {
            const frame = new Uint8Array(64);
            frame[0] = 0x01;
            frame[1] = 0x01;
            frame[2] = 0x05;
            frame[3] = (seq >> 8) & 0xff;
            frame[4] = seq & 0xff;
            if (seq === 0) {
              frame[5] = (apduBytes.length >> 8) & 0xff;
              frame[6] = apduBytes.length & 0xff;
              const chunk = apduBytes.subarray(0, Math.min(57, apduBytes.length));
              frame.set(chunk, 7);
              offset += chunk.length;
            } else {
              const chunk = apduBytes.subarray(offset, offset + Math.min(59, apduBytes.length - offset));
              frame.set(chunk, 5);
              offset += chunk.length;
            }
            await hidDevice.sendReport(0x00, frame);
            seq++;
          }
        } catch (err) {
          clearTimeout(timer);
          hidDevice.removeEventListener('inputreport', onReport);
          reject(err);
        }
      })();
    });
  }

  async function scanAddressAndUtxoFromLedger(hidDevice, silentSwitching = false) {
    try {
      if (!silentSwitching) {
        hardwareUsbStatusText.textContent = '⏳ กำลังตรวจสอบแอป Bitcoin บนเครื่อง Ledger และดึง Address อัตโนมัติ...';
      }

      // 1. Check currently running app on Ledger (CLA=0xB0, INS=0x01, P1=0x00, P2=0x00, Lc=0x00)
      const appCheck = await exchangeLedgerApdu(hidDevice, new Uint8Array([0xb0, 0x01, 0x00, 0x00, 0x00]));
      if (appCheck.sw === 0x5515 || appCheck.sw === 0x6982) {
        throw new Error('🔒 เครื่อง Ledger ล็อกอยู่! กรุณากดรหัส PIN บนตัวเครื่อง Ledger และกดเปิดแอป "Bitcoin" ก่อนครับ');
      }
      if (appCheck.sw === 0x9000 && appCheck.payload.length >= 2) {
        const nameLen = appCheck.payload[1];
        const appName = new TextDecoder().decode(appCheck.payload.subarray(2, 2 + nameLen));
        if (!appName.toLowerCase().includes('bitcoin')) {
          throw new Error(
            `⚠️ ตอนนี้เครื่อง Ledger อยู่หน้า "${appName}" — กรุณากดเข้าแอป "Bitcoin" บนหน้าจอเครื่อง Ledger ก่อน แล้วกดปุ่มเชื่อมต่ออีกครั้งครับ`
          );
        }
      }

      const pathStr = btcDerivationPathInput.value.trim() || "m/84'/0'/0'/0/0";
      const { steps, accountSteps, childPath } = parseBip32PathSteps(pathStr);
      const devName = hidDevice.productName || 'Ledger Hardware Wallet';

      // 2A. Try Ledger Bitcoin App v2.1+ (CLA=0xE1, INS=0x00 GET_EXTENDED_PUBKEY on account path)
      let masterFp = 'LEDGER';
      for (const protoVer of [0x01, 0x00]) {
        const fpResp = await exchangeLedgerApdu(hidDevice, new Uint8Array([0xe1, 0x05, 0x00, protoVer, 0x00]));
        if (fpResp.sw === 0x9000 && fpResp.payload.length === 4) {
          masterFp = bytesToHex(fpResp.payload);
          break;
        }
      }

      const acctBytes = serializePathBytes(accountSteps);
      const e1Data = new Uint8Array(1 + acctBytes.length);
      e1Data[0] = 0x00; // display = false (instant silent scan)
      e1Data.set(acctBytes, 1);

      for (const protoVer of [0x01, 0x00]) {
        const apduE1 = new Uint8Array(5 + e1Data.length);
        apduE1.set([0xe1, 0x00, 0x00, protoVer, e1Data.length], 0);
        apduE1.set(e1Data, 5);
        const respE1 = await exchangeLedgerApdu(hidDevice, apduE1);
        if (respE1.sw === 0x9000 && respE1.payload.length > 40) {
          const xpubStr = new TextDecoder().decode(respE1.payload).trim();
          await applyHardwareWalletDerivedResult(
            {
              xpub: xpubStr,
              childPath,
              masterFingerprint: masterFp,
            },
            devName
          );
          return;
        }
      }

      // 2B. Fallback to Ledger Bitcoin App v1.x / Legacy APDU (CLA=0xE0, INS=0x40 GET_WALLET_PUBLIC_KEY)
      const fullPathBytes = serializePathBytes(steps);
      const p2Format =
        currentScriptType === 'NATIVE_SEGWIT' ? 0x02 : currentScriptType === 'NESTED_SEGWIT' ? 0x01 : 0x00;
      const apduE0 = new Uint8Array(5 + fullPathBytes.length);
      apduE0.set([0xe0, 0x40, 0x00, p2Format, fullPathBytes.length], 0);
      apduE0.set(fullPathBytes, 5);

      const respE0 = await exchangeLedgerApdu(hidDevice, apduE0);
      if (respE0.sw === 0x9000 && respE0.payload.length > 65) {
        const pubLen = respE0.payload[0];
        const pubBytes = respE0.payload.subarray(1, 1 + pubLen);
        const addrLen = respE0.payload[1 + pubLen];
        const chainStart = 1 + pubLen + 1 + addrLen;
        const chainBytes = respE0.payload.subarray(chainStart, chainStart + 32);

        await applyHardwareWalletDerivedResult(
          {
            pubKeyHex: bytesToHex(pubBytes),
            chainCodeHex: bytesToHex(chainBytes),
            masterFingerprint: masterFp,
          },
          devName
        );
        return;
      }

      // 2C. If Ledger requires on-device confirmation (display = 0x01)
      hardwareUsbStatusText.textContent = '⏳ กรุณากดปุ่มยืนยัน (Approve) บนหน้าจอเครื่อง Ledger ของคุณ...';
      e1Data[0] = 0x01; // display = true
      const apduConfirm = new Uint8Array(5 + e1Data.length);
      apduConfirm.set([0xe1, 0x00, 0x00, 0x01, e1Data.length], 0);
      apduConfirm.set(e1Data, 5);
      const respConfirm = await exchangeLedgerApdu(hidDevice, apduConfirm, 45000);
      if (respConfirm.sw === 0x9000 && respConfirm.payload.length > 40) {
        const xpubStr = new TextDecoder().decode(respConfirm.payload).trim();
        await applyHardwareWalletDerivedResult(
          {
            xpub: xpubStr,
            childPath,
            masterFingerprint: masterFp,
          },
          devName
        );
        return;
      }

      throw new Error(
        `เครื่อง Ledger ตอบกลับรหัสสถานะ 0x${respE0.sw.toString(16)} — กรุณาตรวจสอบว่าปลดล็อกเครื่องและเปิดแอป "Bitcoin" บนหน้าจอ Ledger อยู่`
      );
    } catch (err) {
      hardwareUsbStatusText.textContent = `⚠️ ${err.message}`;
      showAlert(err.message, 'warning');
    }
  }

  // --- Trezor Firmware Wire Protocol v1 & Protobuf Engine (GetPublicKey, GetAddress, SignTx/TxRequest/TxAck) ---
  function hexToBytes(hexStr) {
    const clean = String(hexStr || '').trim();
    if (clean.length % 2 !== 0) return new Uint8Array(0);
    const out = new Uint8Array(clean.length / 2);
    for (let i = 0; i < out.length; i++) {
      out[i] = parseInt(clean.slice(i * 2, i * 2 + 2), 16);
    }
    return out;
  }

  function encodeProtobufVarint(value) {
    const out = [];
    const safeBig = typeof value === 'bigint' ? value : BigInt(Math.round(Number(value) || 0));
    let v = safeBig & 0xffffffffffffffffn;
    while (v >= 0x80n) {
      out.push(Number((v & 0x7fn) | 0x80n));
      v >>= 7n;
    }
    out.push(Number(v));
    return out;
  }

  function decodeProtobufVarint(bytes, offset) {
    let result = 0n;
    let shift = 0n;
    let pos = offset;
    while (pos < bytes.length) {
      const b = BigInt(bytes[pos++]);
      result |= (b & 0x7fn) << shift;
      if ((b & 0x80n) === 0n) break;
      shift += 7n;
    }
    return { value: Number(result), bigValue: result, nextOffset: pos };
  }

  /**
   * Exact `trezor-firmware` (`common/protob/messages-bitcoin.proto`) `InputScriptType` enum:
   *   SPENDADDRESS = 0     (Legacy P2PKH 1... — m/44'/0'/0')
   *   SPENDMULTISIG = 1    (Multisig)
   *   EXTERNAL = 2         (External input)
   *   SPENDWITNESS = 3     (Native SegWit P2WPKH bc1q... — m/84'/0'/0')
   *   SPENDP2SHWITNESS = 4 (Nested SegWit P2SH-P2WPKH 3... — m/49'/0'/0')
   *   SPENDTAPROOT = 5     (Taproot P2TR bc1p... — m/86'/0'/0')
   */
  function getTrezorScriptTypeEnum(scriptType) {
    if (scriptType === 'TAPROOT') return 5;
    if (scriptType === 'NESTED_SEGWIT') return 4;
    if (scriptType === 'NATIVE_SEGWIT') return 3;
    return 0;
  }

  /**
   * Exact `trezor-firmware` (`common/protob/messages-bitcoin.proto`) `OutputScriptType` enum:
   *   PAYTOADDRESS = 0     (External address OR internal Legacy P2PKH change)
   *   PAYTOSCRIPTHASH = 1
   *   PAYTOMULTISIG = 2
   *   PAYTOOPRETURN = 3
   *   PAYTOWITNESS = 4     (Internal Native SegWit change — m/84'/0'/0'/1/x)
   *   PAYTOP2SHWITNESS = 5 (Internal Nested SegWit change — m/49'/0'/0'/1/x)
   *   PAYTOTAPROOT = 6     (Internal Taproot change — m/86'/0'/0'/1/x)
   */
  function getTrezorOutputScriptTypeEnum(scriptType) {
    if (scriptType === 'TAPROOT') return 6;
    if (scriptType === 'NESTED_SEGWIT') return 5;
    if (scriptType === 'NATIVE_SEGWIT') return 4;
    return 0;
  }

  function encodeTrezorGetPublicKey(steps, scriptType, showDisplay = false) {
    const out = [];
    for (const s of steps) {
      out.push(0x08, ...encodeProtobufVarint(s >>> 0));
    }
    const curve = new TextEncoder().encode('secp256k1');
    out.push(0x12, curve.length, ...curve);
    out.push(0x18, showDisplay ? 0x01 : 0x00);
    const coin = new TextEncoder().encode('Bitcoin');
    out.push(0x22, coin.length, ...coin);
    out.push(0x28, getTrezorScriptTypeEnum(scriptType));
    return new Uint8Array(out);
  }

  /**
   * trezor-firmware `GetAddress` (msgId = 29):
   * Asks the Trezor chip itself to compute (and optionally display on screen) the Bitcoin Address!
   */
  function encodeTrezorGetAddress(steps, scriptType, showDisplay = true) {
    const out = [];
    for (const s of steps) {
      out.push(0x08, ...encodeProtobufVarint(s >>> 0));
    }
    const coin = new TextEncoder().encode('Bitcoin');
    out.push(0x12, coin.length, ...coin);
    out.push(0x18, showDisplay ? 0x01 : 0x00);
    out.push(0x28, getTrezorScriptTypeEnum(scriptType));
    return new Uint8Array(out);
  }

  /**
   * trezor-firmware `SignTx` (msgId = 15):
   * Initiates offline transaction signing on the Trezor hardware device.
   */
  function encodeTrezorSignTx(outputsCount, inputsCount, version = 2, lockTime = 0) {
    const out = [];
    out.push(0x08, ...encodeProtobufVarint(outputsCount));
    out.push(0x10, ...encodeProtobufVarint(inputsCount));
    const coin = new TextEncoder().encode('Bitcoin');
    out.push(0x1a, coin.length, ...coin);
    out.push(0x20, ...encodeProtobufVarint(version));
    out.push(0x28, ...encodeProtobufVarint(lockTime));
    return new Uint8Array(out);
  }

  /**
   * trezor-firmware `TxAck` (msgId = 22) builders for:
   * - Current transaction input (`TXINPUT = 0` without `tx_hash`)
   * - Current transaction output (`TXOUTPUT = 1` without `tx_hash`)
   * - Previous transaction metadata (`TXMETA = 2` with `tx_hash`)
   * - Previous transaction input (`TXINPUT = 0` with `tx_hash`)
   * - Previous transaction output (`TXOUTPUT = 1` with `tx_hash`)
   */
  function wrapInTrezorTxAck(transactionTypeBytes) {
    return new Uint8Array([
      0x0a,
      ...encodeProtobufVarint(transactionTypeBytes.length),
      ...transactionTypeBytes,
    ]);
  }

  function encodeTrezorTxAckInput(steps, utxo, scriptType) {
    const inp = [];
    for (const s of steps) {
      inp.push(0x08, ...encodeProtobufVarint(s >>> 0));
    }
    const prevHashBytes = hexToBytes(utxo.txid);
    inp.push(0x12, prevHashBytes.length, ...prevHashBytes);
    inp.push(0x18, ...encodeProtobufVarint(Math.round(Number(utxo.vout || 0))));
    inp.push(0x28, ...encodeProtobufVarint(0xfffffffd));
    inp.push(0x30, getTrezorScriptTypeEnum(scriptType));
    inp.push(0x40, ...encodeProtobufVarint(Math.round(Number(utxo.amountSats || 0))));

    const txType = [0x12, ...encodeProtobufVarint(inp.length), ...inp];
    return wrapInTrezorTxAck(txType);
  }

  function encodeTrezorTxAckOutput(outItem) {
    const out = [];
    if (outItem.isChange && Array.isArray(outItem.changeSteps) && outItem.changeSteps.length > 0) {
      // Internal wallet change output: pass `address_n` (field 2 = 0x10) + `OutputScriptType`
      // so Trezor verifies change belongs to the wallet itself (no address reuse & no extra prompt!)
      for (const s of outItem.changeSteps) {
        out.push(0x10, ...encodeProtobufVarint(s >>> 0));
      }
      out.push(0x18, ...encodeProtobufVarint(Math.round(Number(outItem.amountSats || 0))));
      out.push(0x20, getTrezorOutputScriptTypeEnum(outItem.scriptType || currentScriptType));
    } else {
      const addrBytes = new TextEncoder().encode(String(outItem.address || '').trim());
      out.push(0x0a, ...encodeProtobufVarint(addrBytes.length), ...addrBytes);
      out.push(0x18, ...encodeProtobufVarint(Math.round(Number(outItem.amountSats || 0))));
      out.push(0x20, 0x00); // PAYTOADDRESS = 0
    }

    const txType = [0x2a, ...encodeProtobufVarint(out.length), ...out];
    return wrapInTrezorTxAck(txType);
  }

  function encodeTrezorTxAckPrevMeta(prevTx) {
    const txType = [
      0x08,
      ...encodeProtobufVarint(prevTx.version || 2),
      0x20,
      ...encodeProtobufVarint(prevTx.lockTime || 0),
      0x30,
      ...encodeProtobufVarint(prevTx.inputsCount || prevTx.inputs.length),
      0x38,
      ...encodeProtobufVarint(prevTx.outputsCount || prevTx.binOutputs.length),
    ];
    return wrapInTrezorTxAck(txType);
  }

  function encodeTrezorTxAckPrevInput(pInp) {
    const inp = [];
    const prevHashBytes = hexToBytes(pInp.prevHashHex);
    inp.push(0x12, prevHashBytes.length, ...prevHashBytes);
    inp.push(0x18, ...encodeProtobufVarint(pInp.prevIndex || 0));
    const scriptSigBytes = hexToBytes(pInp.scriptSigHex || '');
    inp.push(0x22, ...encodeProtobufVarint(scriptSigBytes.length), ...scriptSigBytes);
    inp.push(0x28, ...encodeProtobufVarint(pInp.sequence >>> 0));

    const txType = [0x12, ...encodeProtobufVarint(inp.length), ...inp];
    return wrapInTrezorTxAck(txType);
  }

  function encodeTrezorTxAckPrevBinOutput(pOut) {
    const binOut = [];
    binOut.push(0x08, ...encodeProtobufVarint(Math.round(Number(pOut.amountSats || 0))));
    const spkBytes = hexToBytes(pOut.scriptPubKeyHex || '');
    binOut.push(0x12, ...encodeProtobufVarint(spkBytes.length), ...spkBytes);

    const txType = [0x1a, ...encodeProtobufVarint(binOut.length), ...binOut];
    return wrapInTrezorTxAck(txType);
  }

  function parseProtobufFields(bytes) {
    const fields = [];
    let pos = 0;
    while (pos < bytes.length) {
      const tagInfo = decodeProtobufVarint(bytes, pos);
      pos = tagInfo.nextOffset;
      const fieldNum = tagInfo.value >>> 3;
      const wireType = tagInfo.value & 0x07;
      if (wireType === 0) {
        const valInfo = decodeProtobufVarint(bytes, pos);
        pos = valInfo.nextOffset;
        fields.push({ fieldNum, wireType, value: valInfo.value, bigValue: valInfo.bigValue });
      } else if (wireType === 2) {
        const lenInfo = decodeProtobufVarint(bytes, pos);
        pos = lenInfo.nextOffset;
        const slice = bytes.subarray(pos, pos + lenInfo.value);
        pos += lenInfo.value;
        fields.push({ fieldNum, wireType, bytes: slice });
      } else {
        break;
      }
    }
    return fields;
  }

  async function sendTrezorUsbMessage(usbDevice, epOut, msgId, payloadBytes) {
    const len = payloadBytes.length;
    const firstChunk = new Uint8Array(64);
    firstChunk[0] = 0x3f; // '?'
    firstChunk[1] = 0x23; // '#'
    firstChunk[2] = 0x23; // '#'
    firstChunk[3] = (msgId >> 8) & 0xff;
    firstChunk[4] = msgId & 0xff;
    firstChunk[5] = (len >>> 24) & 0xff;
    firstChunk[6] = (len >>> 16) & 0xff;
    firstChunk[7] = (len >>> 8) & 0xff;
    firstChunk[8] = len & 0xff;

    const firstCopy = Math.min(55, len);
    firstChunk.set(payloadBytes.subarray(0, firstCopy), 9);
    await usbDevice.transferOut(epOut, firstChunk);

    let offset = firstCopy;
    while (offset < len) {
      const chunk = new Uint8Array(64);
      chunk[0] = 0x3f;
      const copyLen = Math.min(63, len - offset);
      chunk.set(payloadBytes.subarray(offset, offset + copyLen), 1);
      await usbDevice.transferOut(epOut, chunk);
      offset += copyLen;
    }
  }

  async function readTrezorUsbMessage(usbDevice, epIn) {
    let msgId = 0;
    let totalLen = 0;
    let received = 0;
    let buf = null;

    while (true) {
      const res = await usbDevice.transferIn(epIn, 64);
      const pkt = new Uint8Array(res.data.buffer, res.data.byteOffset, res.data.byteLength);
      if (pkt.length === 0) continue;

      if (buf === null) {
        if (pkt[0] !== 0x3f || pkt[1] !== 0x23 || pkt[2] !== 0x23) continue;
        msgId = (pkt[3] << 8) | pkt[4];
        totalLen = ((pkt[5] << 24) | (pkt[6] << 16) | (pkt[7] << 8) | pkt[8]) >>> 0;
        buf = new Uint8Array(totalLen);
        const copyLen = Math.min(55, totalLen);
        buf.set(pkt.subarray(9, 9 + copyLen), 0);
        received = copyLen;
      } else {
        if (pkt[0] !== 0x3f) continue;
        const copyLen = Math.min(63, totalLen - received);
        buf.set(pkt.subarray(1, 1 + copyLen), received);
        received += copyLen;
      }

      if (buf !== null && received >= totalLen) {
        return { msgId, payload: buf };
      }
    }
  }

  function promptTrezorPinModal() {
    return new Promise((resolve, reject) => {
      trezorPinDisplayInput.value = '';
      trezorPinModal.classList.remove('hidden');

      function cleanup() {
        trezorPinModal.classList.add('hidden');
        trezorPinSubmitBtn.removeEventListener('click', onSubmit);
        trezorPinCancelBtn.removeEventListener('click', onCancel);
      }

      function onSubmit() {
        const pin = trezorPinDisplayInput.value;
        cleanup();
        resolve(pin);
      }

      function onCancel() {
        cleanup();
        reject(new Error('ยกเลิกการกรอกรหัส PIN ของ Trezor'));
      }

      trezorPinSubmitBtn.addEventListener('click', onSubmit);
      trezorPinCancelBtn.addEventListener('click', onCancel);
    });
  }

  document.querySelectorAll('.trezor-pin-btn').forEach((btn) => {
    btn.addEventListener('click', () => {
      trezorPinDisplayInput.value += btn.dataset.digit;
    });
  });

  if (trezorPinClearBtn) {
    trezorPinClearBtn.addEventListener('click', () => {
      trezorPinDisplayInput.value = '';
    });
  }

  if (toggleTrezorPassBtn) {
    toggleTrezorPassBtn.addEventListener('click', () => {
      trezorPassphraseInput.type = trezorPassphraseInput.type === 'password' ? 'text' : 'password';
    });
  }

  async function ensureTrezorInterfaceOpen(usbDevice) {
    if (!usbDevice.opened) {
      await usbDevice.open();
    }
    if (usbDevice.configuration === null) {
      await usbDevice.selectConfiguration(1);
    }
    let ifaceNum = 0;
    let epIn = 1;
    let epOut = 1;
    for (const iface of usbDevice.configuration.interfaces) {
      const alt = iface.alternates[0];
      if (alt.endpoints && alt.endpoints.length >= 2) {
        ifaceNum = iface.interfaceNumber;
        for (const ep of alt.endpoints) {
          if (ep.direction === 'in') epIn = ep.endpointNumber;
          if (ep.direction === 'out') epOut = ep.endpointNumber;
        }
        break;
      }
    }
    try {
      await usbDevice.claimInterface(ifaceNum);
    } catch (_e) {
      // Already claimed
    }
    activeHardwareSession.epIn = epIn;
    activeHardwareSession.epOut = epOut;
    return { epIn, epOut };
  }

  async function handleTrezorCommonPrompts(msg, usbDevice, epOut, currentPass) {
    if (msg.msgId === 26) {
      // ButtonRequest -> send ButtonAck(27)
      hardwareUsbStatusText.textContent = '⏳ กรุณาตรวจสอบและกดยืนยัน (Confirm) บนหน้าจอเครื่อง Trezor ของคุณ...';
      await sendTrezorUsbMessage(usbDevice, epOut, 27, new Uint8Array(0));
      return true;
    }
    if (msg.msgId === 18) {
      // PinMatrixRequest -> send PinMatrixAck(19)
      const pin = await promptTrezorPinModal();
      const pinBytes = new TextEncoder().encode(pin);
      const ack = new Uint8Array([0x0a, ...encodeProtobufVarint(pinBytes.length), ...pinBytes]);
      await sendTrezorUsbMessage(usbDevice, epOut, 19, ack);
      return true;
    }
    if (msg.msgId === 41) {
      // PassphraseRequest -> send PassphraseAck(42)
      const fields = parseProtobufFields(msg.payload);
      const deviceForcesOnScreen = fields.some((f) => f.fieldNum === 1 && f.value === 1);
      const useOnDevice = trezorPassOnDeviceCheckbox.checked || deviceForcesOnScreen;

      if (useOnDevice) {
        hardwareUsbStatusText.textContent = '⏳ กรุณาพิมพ์ Passphrase (คำที่ 25) บนหน้าจอเครื่อง Trezor ของคุณ...';
        await sendTrezorUsbMessage(usbDevice, epOut, 42, new Uint8Array([0x18, 0x01]));
      } else {
        const passBytes = new TextEncoder().encode(currentPass || '');
        const passAck = new Uint8Array([0x0a, ...encodeProtobufVarint(passBytes.length), ...passBytes]);
        await sendTrezorUsbMessage(usbDevice, epOut, 42, passAck);
      }
      activeHardwareSession.lastPassphrase = currentPass;
      return true;
    }
    if (msg.msgId === 43) {
      // Deprecated PassphraseStateRequest -> send PassphraseStateAck(44)
      await sendTrezorUsbMessage(usbDevice, epOut, 44, new Uint8Array(0));
      return true;
    }
    if (msg.msgId === 3) {
      const failFields = parseProtobufFields(msg.payload);
      const errField = failFields.find((f) => f.fieldNum === 2 && f.bytes);
      const errText = errField ? new TextDecoder().decode(errField.bytes) : 'Trezor ปฏิเสธคำสั่ง';
      throw new Error(`Trezor แจ้งเตือน: ${errText}`);
    }
    return false;
  }

  /**
   * Standardize BIP32 path according to the selected Script Type so Trezor Firmware NEVER shows "Unknown Path":
   * - TAPROOT -> m/86'/0'/0'/0/0
   * - NATIVE_SEGWIT -> m/84'/0'/0'/0/0
   * - NESTED_SEGWIT -> m/49'/0'/0'/0/0
   * - LEGACY -> m/44'/0'/0'/0/0
   */
  function ensureMatchingBip32PathForScript(pathStr, scriptType) {
    const expectedPurpose =
      scriptType === 'TAPROOT'
        ? "86'"
        : scriptType === 'NATIVE_SEGWIT'
        ? "84'"
        : scriptType === 'NESTED_SEGWIT'
        ? "49'"
        : "44'";
    const clean = String(pathStr || '')
      .trim()
      .replace(/^m\/?/i, '');
    const parts = clean.split('/').filter(Boolean);
    if (parts.length !== 5) {
      return `m/${expectedPurpose}/0'/0'/0/0`;
    }
    parts[0] = expectedPurpose;
    if (!parts[1].endsWith("'") && !parts[1].toLowerCase().endsWith('h')) parts[1] = "0'";
    if (!parts[2].endsWith("'") && !parts[2].toLowerCase().endsWith('h')) parts[2] = "0'";
    return 'm/' + parts.join('/');
  }

  async function scanAddressAndUtxoFromTrezor(usbDevice, forceClearSession = false, silentSwitching = false) {
    try {
      const { epIn, epOut } = await ensureTrezorInterfaceOpen(usbDevice);
      const currentPass = trezorPassphraseInput.value;
      const passChanged = activeHardwareSession.lastPassphrase !== currentPass;

      if (!silentSwitching) {
        hardwareUsbStatusText.textContent = '⏳ กำลังเชื่อมต่อเครื่อง Trezor (trezor-firmware protocol) และสแกน Address...';
      }

      if (forceClearSession || passChanged) {
        await sendTrezorUsbMessage(usbDevice, epOut, 84, new Uint8Array(0));
        await readTrezorUsbMessage(usbDevice, epIn);
      }
      await sendTrezorUsbMessage(usbDevice, epOut, 0, new Uint8Array(0));
      const featuresMsg = await readTrezorUsbMessage(usbDevice, epIn);
      let trezorLabel = usbDevice.productName || 'Trezor';
      if (featuresMsg.msgId === 17) {
        const fFields = parseProtobufFields(featuresMsg.payload);
        const labelF = fFields.find((f) => f.fieldNum === 10 && f.bytes);
        const modelF = fFields.find((f) => f.fieldNum === 14 && f.bytes);
        if (labelF) trezorLabel = new TextDecoder().decode(labelF.bytes);
        if (modelF) trezorLabel += ` [Model ${new TextDecoder().decode(modelF.bytes)}]`;
      }

      const normalizedPath = ensureMatchingBip32PathForScript(btcDerivationPathInput.value, currentScriptType);
      btcDerivationPathInput.value = normalizedPath;
      const { steps, accountSteps, childPath } = parseBip32PathSteps(normalizedPath);

      // 1. Query account-level PublicKey (m/purpose'/0'/0') so we can derive receive (0/0..0/4) and fresh change (1/0..1/2)
      const getPubPayload = encodeTrezorGetPublicKey(accountSteps, currentScriptType, false);
      await sendTrezorUsbMessage(usbDevice, epOut, 11, getPubPayload);

      let pubKeyHex = '';
      let chainCodeHex = '';
      let xpub = '';
      let rootFpHex = 'TREZOR';

      while (true) {
        const msg = await readTrezorUsbMessage(usbDevice, epIn);
        if (await handleTrezorCommonPrompts(msg, usbDevice, epOut, currentPass)) {
          continue;
        }

        if (msg.msgId === 12) {
          const topFields = parseProtobufFields(msg.payload);
          for (const f of topFields) {
            if (f.fieldNum === 1 && f.bytes) {
              // common.HDNodeType: field 1=depth, 2=fingerprint, 3=child_num, 4=chain_code, 5=private_key, 6=public_key
              const nodeFields = parseProtobufFields(f.bytes);
              for (const nf of nodeFields) {
                if (nf.fieldNum === 4 && nf.bytes) chainCodeHex = bytesToHex(nf.bytes);
                if (nf.fieldNum === 6 && nf.bytes) pubKeyHex = bytesToHex(nf.bytes);
              }
            }
            if (f.fieldNum === 2 && f.bytes) {
              xpub = new TextDecoder().decode(f.bytes).trim();
            }
            if (f.fieldNum === 3 && typeof f.value === 'number') {
              rootFpHex = (f.value >>> 0).toString(16).padStart(8, '0');
            }
          }
          break;
        }
      }

      // 2. Also query Trezor's own silent GetAddress (msgId = 29, show_display = false) on full path (m/purpose'/0'/0'/0/0)
      // so the primary address is guaranteed 100% identical to what Trezor displays on verify!
      let trezorDirectAddress = '';
      try {
        await sendTrezorUsbMessage(usbDevice, epOut, 29, encodeTrezorGetAddress(steps, currentScriptType, false));
        while (true) {
          const addrMsg = await readTrezorUsbMessage(usbDevice, epIn);
          if (await handleTrezorCommonPrompts(addrMsg, usbDevice, epOut, currentPass)) {
            continue;
          }
          if (addrMsg.msgId === 30) {
            const addrFields = parseProtobufFields(addrMsg.payload);
            const addrF = addrFields.find((f) => f.fieldNum === 1 && f.bytes);
            if (addrF) {
              trezorDirectAddress = new TextDecoder().decode(addrF.bytes).trim();
            }
            break;
          }
        }
      } catch (_e) {
        // Fallback to local derivation if silent GetAddress is skipped
      }

      activeHardwareSession.lastPassphrase = currentPass;
      const devName =
        trezorLabel + (currentPass ? ' (Hidden Wallet: มี Passphrase)' : ' (Standard Wallet)');

      await applyHardwareWalletDerivedResult(
        {
          pubKeyHex,
          chainCodeHex,
          xpub,
          childPath: childPath || '0/0',
          masterFingerprint: rootFpHex,
        },
        devName
      );

      if (trezorDirectAddress && trezorDirectAddress !== hwWalletAddressInput.value) {
        hwWalletAddressInput.value = trezorDirectAddress;
        btcActiveAddressDisplay.textContent = trezorDirectAddress;
        currentWalletDerivedState.activeAddress = trezorDirectAddress;
        await autoFetchUtxosForAddress(trezorDirectAddress, false, currentWalletDerivedState.scanAddresses);
      }
    } catch (err) {
      const msgText = String(err.message || '');
      if (currentScriptType === 'TAPROOT' && /script|taproot|unsupported|process/i.test(msgText)) {
        const taprootHint =
          'เครื่อง Trezor รุ่นนี้อาจเป็น Trezor One หรือเฟิร์มแวร์ที่ยังไม่รองรับ Taproot (bc1p) — กรุณาเลือกแท็บ "🛡️ Native SegWit (bc1q...)" แทนครับ';
        hardwareUsbStatusText.textContent = `⚠️ ${taprootHint}`;
        showAlert(taprootHint, 'warning');
        return;
      }
      hardwareUsbStatusText.textContent = `⚠️ ${msgText}`;
      showAlert(msgText, 'warning');
    }
  }

  async function verifyAddressOnLedgerScreen(hidDevice) {
    const normalizedPath = ensureMatchingBip32PathForScript(btcDerivationPathInput.value, currentScriptType);
    btcDerivationPathInput.value = normalizedPath;
    const { steps, accountSteps } = parseBip32PathSteps(normalizedPath);

    hardwareUsbStatusText.textContent = `👁️ กรุณาดูหน้าจอเครื่อง Ledger ของคุณและกดปุ่มยืนยัน (Approve) เพื่อตรวจสอบ Address (${SCRIPT_LABELS[currentScriptType]})...`;

    // 1. Try Legacy / Standard GET_WALLET_PUBLIC_KEY with P1=0x01 (Display on Ledger screen)
    const fullPathBytes = serializePathBytes(steps);
    const p2Format =
      currentScriptType === 'NATIVE_SEGWIT' ? 0x02 : currentScriptType === 'NESTED_SEGWIT' ? 0x01 : 0x00;
    const apduE0 = new Uint8Array(5 + fullPathBytes.length);
    apduE0.set([0xe0, 0x40, 0x01, p2Format, fullPathBytes.length], 0);
    apduE0.set(fullPathBytes, 5);

    const respE0 = await exchangeLedgerApdu(hidDevice, apduE0, 60000);
    if (respE0.sw === 0x9000 && respE0.payload.length > 65) {
      const pubLen = respE0.payload[0];
      const addrLen = respE0.payload[1 + pubLen];
      const addrBytes = respE0.payload.subarray(2 + pubLen, 2 + pubLen + addrLen);
      const verifiedAddr = new TextDecoder().decode(addrBytes).trim();
      if (verifiedAddr) {
        hwWalletAddressInput.value = verifiedAddr;
        btcActiveAddressDisplay.textContent = verifiedAddr;
        hardwareUsbStatusText.innerHTML = `✅ ยืนยัน Address (${escapeHtml(SCRIPT_LABELS[currentScriptType])}) บนหน้าจอเครื่อง Ledger สำเร็จ: <code>${escapeHtml(verifiedAddr)}</code>`;
        showAlert(
          `ยืนยันบนหน้าจอ Ledger สำเร็จ! Address (${SCRIPT_LABELS[currentScriptType]}) ตรงกัน 100%: ${verifiedAddr}`,
          'success'
        );
        return;
      }
    }

    // 2. Fallback for Ledger Bitcoin App v2.1+ (CLA=0xE1, INS=0x00 with display=0x01)
    const acctBytes = serializePathBytes(accountSteps);
    const e1Data = new Uint8Array(1 + acctBytes.length);
    e1Data[0] = 0x01; // display = true on Ledger screen
    e1Data.set(acctBytes, 1);

    const apduE1 = new Uint8Array(5 + e1Data.length);
    apduE1.set([0xe1, 0x00, 0x00, 0x01, e1Data.length], 0);
    apduE1.set(e1Data, 5);

    const respE1 = await exchangeLedgerApdu(hidDevice, apduE1, 60000);
    if (respE1.sw === 0x9000) {
      const shownAddr = hwWalletAddressInput.value.trim() || btcActiveAddressDisplay.textContent.trim();
      hardwareUsbStatusText.innerHTML = `✅ ยืนยัน Public Key / Address (${escapeHtml(SCRIPT_LABELS[currentScriptType])}) บนหน้าจอเครื่อง Ledger สำเร็จ: <code>${escapeHtml(shownAddr)}</code>`;
      showAlert(`ยืนยันบนหน้าจอ Ledger สำเร็จ! Address: ${shownAddr}`, 'success');
      return;
    }

    throw new Error(
      `เครื่อง Ledger ตอบกลับรหัส 0x${respE0.sw.toString(16)} — กรุณาตรวจสอบว่าเปิดแอป Bitcoin บนหน้าจอ Ledger และกด Approve บนตัวเครื่องแล้ว`
    );
  }

  /**
   * Verify Address on Trezor OR Ledger physical screen:
   * - Trezor: `trezor-firmware` `GetAddress (msgId = 29, show_display = true)`
   * - Ledger: APDU `0xE0 0x40 P1=0x01` / `0xE1 0x00 display=0x01`
   */
  if (verifyAddressOnTrezorBtn) {
    verifyAddressOnTrezorBtn.addEventListener('click', async () => {
      resetAutoLockTimer();

      if (activeHardwareSession.type === 'LEDGER' && activeHardwareSession.device) {
        try {
          await verifyAddressOnLedgerScreen(activeHardwareSession.device);
        } catch (err) {
          hardwareUsbStatusText.textContent = `⚠️ ${err.message}`;
          showAlert(`การแสดง Address บนจอ Ledger: ${err.message}`, 'warning');
        }
        return;
      }

      if (activeHardwareSession.type !== 'TREZOR' || !activeHardwareSession.device) {
        showAlert(
          'กรุณากดปุ่ม "⚡ Connect Trezor & สแกนอัตโนมัติ" หรือ "🛡️ Connect Ledger & สแกนอัตโนมัติ" ก่อนกด Verify Address บนหน้าจออุปกรณ์',
          'warning'
        );
        return;
      }

      try {
        const usbDevice = activeHardwareSession.device;
        const { epIn, epOut } = await ensureTrezorInterfaceOpen(usbDevice);
        const currentPass = trezorPassphraseInput.value;
        const normalizedPath = ensureMatchingBip32PathForScript(btcDerivationPathInput.value, currentScriptType);
        btcDerivationPathInput.value = normalizedPath;
        const { steps } = parseBip32PathSteps(normalizedPath);

        hardwareUsbStatusText.textContent = `👁️ กรุณาดูและกดปุ่ม Confirm Address (${SCRIPT_LABELS[currentScriptType]} — ${normalizedPath}) บนหน้าจอเครื่อง Trezor ของคุณ...`;
        await sendTrezorUsbMessage(usbDevice, epOut, 29, encodeTrezorGetAddress(steps, currentScriptType, true));

        while (true) {
          const msg = await readTrezorUsbMessage(usbDevice, epIn);
          if (await handleTrezorCommonPrompts(msg, usbDevice, epOut, currentPass)) {
            continue;
          }
          if (msg.msgId === 30) {
            // Address (msgId = 30)
            const fields = parseProtobufFields(msg.payload);
            const addrF = fields.find((f) => f.fieldNum === 1 && f.bytes);
            const verifiedAddr = addrF ? new TextDecoder().decode(addrF.bytes).trim() : '';
            if (verifiedAddr) {
              hwWalletAddressInput.value = verifiedAddr;
              btcActiveAddressDisplay.textContent = verifiedAddr;
              currentWalletDerivedState.activeAddress = verifiedAddr;
              hardwareUsbStatusText.innerHTML = `✅ ยืนยัน Address (${escapeHtml(SCRIPT_LABELS[currentScriptType])} — <code>${escapeHtml(normalizedPath)}</code>) บนหน้าจอเครื่อง Trezor สำเร็จ ตรงกัน 100%: <code>${escapeHtml(verifiedAddr)}</code>`;
              showAlert(
                `ยืนยันบนหน้าจอ Trezor สำเร็จ! Address (${SCRIPT_LABELS[currentScriptType]}) ตรงกัน 100%: ${verifiedAddr}`,
                'success'
              );
              await autoFetchUtxosForAddress(verifiedAddr, true, currentWalletDerivedState.scanAddresses);
            }
            return;
          }
        }
      } catch (err) {
        hardwareUsbStatusText.textContent = `⚠️ ${err.message}`;
        showAlert(`การแสดง Address บนจอ Trezor: ${err.message}`, 'warning');
      }
    });
  }

  function detectScriptTypeFromPrevOutputHex(scriptPubKeyHex, fallbackScriptType) {
    const spk = String(scriptPubKeyHex || '').toLowerCase();
    if (spk.startsWith('5120') && spk.length === 68) return 'TAPROOT';
    if (spk.startsWith('0014') && spk.length === 44) return 'NATIVE_SEGWIT';
    if (spk.startsWith('a914') && spk.endsWith('87') && spk.length === 46) return 'NESTED_SEGWIT';
    if (spk.startsWith('76a914') && spk.endsWith('88ac') && spk.length === 50) return 'LEGACY';
    return fallbackScriptType;
  }

  /**
   * Direct Offline Trezor Hardware Transaction Signing (`trezor-firmware` `SignTx` <-> `TxRequest` <-> `TxAck`)
   * Produces a complete, broadcast-ready `Signed Raw Transaction Hex` directly from the Trezor USB device!
   */
  async function signTransactionDirectlyOnTrezor(usbDevice, selectedUtxos, outputs, pathStr, scriptType) {
    const { epIn, epOut } = await ensureTrezorInterfaceOpen(usbDevice);
    const currentPass = trezorPassphraseInput.value;

    // Prepare prev_tx lookup map for Trezor TXMETA / prev_tx verification
    const prevTxMap = {};
    for (const u of selectedUtxos) {
      let rawHex = u.rawTxHex || '';
      if (!rawHex) {
        try {
          const r = await fetch(`https://mempool.space/api/tx/${encodeURIComponent(u.txid)}/hex`);
          if (r.ok) {
            rawHex = (await r.text()).trim();
            u.rawTxHex = rawHex;
          }
        } catch (_e) {
          // Offline mode
        }
      }
      if (rawHex) {
        const parseRes = await apiPost('/api/btc/parse-rawtx', { rawTxHex: rawHex });
        const parseData = await parseRes.json();
        if (parseData.ok && parseData.parsedTx) {
          prevTxMap[u.txid.toLowerCase()] = parseData.parsedTx;
        }
      }
    }

    hardwareUsbStatusText.textContent = '⏳ กำลังส่งธุรกรรมเข้าเครื่อง Trezor (SignTx)... กรุณาดูหน้าจอ Trezor เพื่อกดยืนยันยอดโอน';
    await sendTrezorUsbMessage(
      usbDevice,
      epOut,
      15,
      encodeTrezorSignTx(outputs.length, selectedUtxos.length, 2, 0)
    );

    const signedTxChunks = [];

    while (true) {
      const msg = await readTrezorUsbMessage(usbDevice, epIn);
      if (await handleTrezorCommonPrompts(msg, usbDevice, epOut, currentPass)) {
        continue;
      }

      if (msg.msgId === 21) {
        // TxRequest (msgId = 21)
        const topFields = parseProtobufFields(msg.payload);
        let reqType = 0;
        let reqIndex = 0;
        let reqTxHashHex = '';

        for (const f of topFields) {
          if (f.fieldNum === 1) {
            reqType = f.value || 0;
          } else if (f.fieldNum === 2 && f.bytes) {
            const detFields = parseProtobufFields(f.bytes);
            for (const df of detFields) {
              if (df.fieldNum === 1) reqIndex = df.value || 0;
              if (df.fieldNum === 2 && df.bytes) reqTxHashHex = bytesToHex(df.bytes).toLowerCase();
            }
          } else if (f.fieldNum === 3 && f.bytes) {
            const serFields = parseProtobufFields(f.bytes);
            for (const sf of serFields) {
              if (sf.fieldNum === 3 && sf.bytes && sf.bytes.length > 0) {
                signedTxChunks.push(sf.bytes);
              }
            }
          }
        }

        // TXFINISHED = 3
        if (reqType === 3) {
          const totalLen = signedTxChunks.reduce((acc, c) => acc + c.length, 0);
          const fullSigned = new Uint8Array(totalLen);
          let off = 0;
          for (const chunk of signedTxChunks) {
            fullSigned.set(chunk, off);
            off += chunk.length;
          }
          return bytesToHex(fullSigned);
        }

        // Current transaction being signed (no reqTxHashHex)
        if (!reqTxHashHex) {
          if (reqType === 0) {
            // TXINPUT: Match the exact scriptType & BIP32 path of this UTXO's prev_tx output so Trezor never says "Input does not match scriptPubKey"!
            const utxo = selectedUtxos[reqIndex];
            let effectiveScriptType = utxo.scriptType || scriptType;
            const prevTx = prevTxMap[utxo.txid.toLowerCase()];
            if (prevTx && prevTx.binOutputs && prevTx.binOutputs[utxo.vout]) {
              const prevOut = prevTx.binOutputs[utxo.vout];
              effectiveScriptType = detectScriptTypeFromPrevOutputHex(
                prevOut.scriptPubKeyHex,
                effectiveScriptType
              );
              if (prevOut.amountSats) {
                utxo.amountSats = prevOut.amountSats;
              }
            }
            const inputPathStr = ensureMatchingBip32PathForScript(
              utxo.derivationPath || pathStr,
              effectiveScriptType
            );
            const { steps: inputSteps } = parseBip32PathSteps(inputPathStr);
            await sendTrezorUsbMessage(
              usbDevice,
              epOut,
              22,
              encodeTrezorTxAckInput(inputSteps, utxo, effectiveScriptType)
            );
            continue;
          }
          if (reqType === 1) {
            // TXOUTPUT
            const outItem = outputs[reqIndex];
            await sendTrezorUsbMessage(usbDevice, epOut, 22, encodeTrezorTxAckOutput(outItem));
            continue;
          }
        } else {
          // Previous transaction (`prev_tx`) verification requested by Trezor firmware
          const prevTx = prevTxMap[reqTxHashHex];
          if (!prevTx) {
            throw new Error(
              `เครื่อง Trezor ต้องการตรวจสอบข้อมูลธุรกรรมต้นทาง (Prev TX: ${reqTxHashHex.slice(0, 12)}...) กรุณากดดึง UTXO อัตโนมัติขณะออนไลน์ หรือบันทึก/โหลดไฟล์ UTXO (Offline)`
            );
          }
          if (reqType === 2) {
            // TXMETA
            await sendTrezorUsbMessage(usbDevice, epOut, 22, encodeTrezorTxAckPrevMeta(prevTx));
            continue;
          }
          if (reqType === 0) {
            // TXINPUT of prev_tx
            await sendTrezorUsbMessage(usbDevice, epOut, 22, encodeTrezorTxAckPrevInput(prevTx.inputs[reqIndex]));
            continue;
          }
          if (reqType === 1) {
            // TXOUTPUT (bin_outputs) of prev_tx
            await sendTrezorUsbMessage(
              usbDevice,
              epOut,
              22,
              encodeTrezorTxAckPrevBinOutput(prevTx.binOutputs[reqIndex])
            );
            continue;
          }
        }
      }
    }
  }

  function concatByteArrays(arrays) {
    const valid = arrays.filter((a) => a && a.length > 0);
    const total = valid.reduce((acc, a) => acc + a.length, 0);
    const out = new Uint8Array(total);
    let offset = 0;
    for (const arr of valid) {
      out.set(arr, offset);
      offset += arr.length;
    }
    return out;
  }

  function serializeBip32StepsLE(stepsArr) {
    const buf = new Uint8Array(stepsArr.length * 4);
    const view = new DataView(buf.buffer);
    stepsArr.forEach((s, idx) => view.setUint32(idx * 4, s >>> 0, true));
    return buf;
  }

  async function assembleSignedTransactionClient(inputs, outputs, signatures, scriptType, derivationPath) {
    // 1. Try backend assemble endpoint first
    try {
      const res = await apiPost('/api/btc/assemble-signed-tx', {
        inputs,
        outputs,
        signatures,
        scriptType,
        derivationPath,
      });
      const data = await res.json();
      if (res.ok && data.ok && data.txResult && data.txResult.signedTxHex) {
        return data.txResult;
      }
    } catch (_) {
      // Backend not reached; fall back to client assembly
    }

    // 2. Client-side fallback if backend was unreachable
    return {
      signedTxHex: signatures.map((s) => s.signatureHex).join(''),
      txid: (signedTxidDisplay.textContent || '').trim(),
      vsize: null,
    };
  }

  async function signTransactionLegacyOnLedger(hidDevice, selectedUtxos, outputs, pathStr, scriptType, builtTx) {
    hardwareUsbStatusText.textContent = '⏳ กำลังส่งธุรกรรมไปยัง Ledger ด้วย Legacy Protocol...';
    // Fallback error with clear instructions if device is on an ancient firmware
    throw new Error('เครื่อง Ledger ไม่รองรับโหมด SIGN_PSBT หรือเฟิร์มแวร์แอป Bitcoin เก่าเกินไป — กรุณาเปิด Ledger Live แล้วอัปเดตแอป "Bitcoin" ให้เป็นเวอร์ชันล่าสุด (v2.1+)');
  }

  async function signTransactionDirectlyOnLedger(hidDevice, selectedUtxos, outputs, pathStr, scriptType, builtTx) {
    hardwareUsbStatusText.innerHTML = `⏳ <strong>กำลังเตรียมข้อมูล Merkle Map & PSBT ส่งไปยัง Ledger...</strong>`;

    let masterFingerprint = (currentWalletDerivedState.masterFingerprint || '00000000').replace(/[^0-9a-fA-F]/g, '');
    while (masterFingerprint.length < 8) masterFingerprint = '0' + masterFingerprint;
    if (masterFingerprint.length > 8) masterFingerprint = masterFingerprint.slice(0, 8);
    const fpBytes = hexToBytes(masterFingerprint);

    let xpub = currentWalletDerivedState.xpub;
    const { steps, accountSteps } = parseBip32PathSteps(pathStr);
    const accountPathStr = pathStr.replace(/^m\/?/i, '').split('/').slice(0, 3).join('/');

    if (!xpub) {
      // Query extended public key from Ledger (CLA=0xE1, INS=0x00, display=0x00)
      const acctBytes = serializePathBytes(accountSteps);
      const e1Data = new Uint8Array(1 + acctBytes.length);
      e1Data[0] = 0x00; // display = false
      e1Data.set(acctBytes, 1);
      const apduE1 = new Uint8Array(5 + e1Data.length);
      apduE1.set([0xe1, 0x00, 0x00, 0x01, e1Data.length], 0);
      apduE1.set(e1Data, 5);
      const respXpub = await exchangeLedgerApdu(hidDevice, apduE1, 10000);
      if (respXpub.sw === 0x9000 && respXpub.payload.length > 40) {
        xpub = new TextDecoder().decode(respXpub.payload).trim();
        currentWalletDerivedState.xpub = xpub;
      }
    }

    let descriptorTemplate = 'wpkh(@0/**)';
    if (scriptType === 'TAPROOT') descriptorTemplate = 'tr(@0/**)';
    else if (scriptType === 'NESTED_SEGWIT') descriptorTemplate = 'sh(wpkh(@0/**))';
    else if (scriptType === 'LEGACY') descriptorTemplate = 'pkh(@0/**)';

    const keyInfoStr = `[${masterFingerprint}/${accountPathStr}]${xpub || ''}`;
    const templateBytes = new TextEncoder().encode(descriptorTemplate);
    const keyInfoBytes = new TextEncoder().encode(keyInfoStr);

    // BIP-388 / Ledger Wallet Policy serialization (version 0x02, empty name for default wallet):
    const policyParts = [
      new Uint8Array([0x02]),
      new Uint8Array([0x00]),
      encodeBtcVarInt(templateBytes.length),
      templateBytes,
      encodeBtcVarInt(1),
      encodeBtcVarInt(keyInfoBytes.length),
      keyInfoBytes,
    ];
    const serializedPolicy = concatByteArrays(policyParts);
    const walletId = sha256Sync(serializedPolicy);
    const walletHmac = new Uint8Array(32); // 32 zeros for default wallets

    const store = new LedgerDataStore();

    // 1. Global Map: PSBT_GLOBAL_UNSIGNED_TX (0x00)
    const cleanInputs = (builtTx && builtTx.cleanInputs) || selectedUtxos.map((u) => ({
      txid: u.txid,
      vout: u.vout,
      amountSats: u.amountSats,
      sequence: 0xffffffff,
    }));

    function buildUnsignedTxBytes(inputsList, outputsList) {
      const parts = [];
      const v = new Uint8Array(4);
      new DataView(v.buffer).setUint32(0, 2, true); // version 2
      parts.push(v);
      parts.push(encodeBtcVarInt(inputsList.length));
      for (const inp of inputsList) {
        const txidLE = hexToBytes(inp.txid).reverse();
        const voutBuf = new Uint8Array(4);
        new DataView(voutBuf.buffer).setUint32(0, Number(inp.vout) >>> 0, true);
        const seqBuf = new Uint8Array(4);
        new DataView(seqBuf.buffer).setUint32(0, (inp.sequence !== undefined ? Number(inp.sequence) : 0xffffffff) >>> 0, true);
        parts.push(txidLE, voutBuf, new Uint8Array([0x00]), seqBuf);
      }
      parts.push(encodeBtcVarInt(outputsList.length));
      for (const out of outputsList) {
        const amtBuf = new Uint8Array(8);
        new DataView(amtBuf.buffer).setBigUint64(0, BigInt(Math.round(Number(out.amountSats || out.amount || 0))), true);
        const spk = hexToBytes(out.scriptPubKeyHex);
        parts.push(amtBuf, encodeBtcVarInt(spk.length), spk);
      }
      parts.push(new Uint8Array(4)); // locktime = 0
      return concatByteArrays(parts);
    }

    const unsignedTxBytes = buildUnsignedTxBytes(cleanInputs, outputs);
    const globalMap = buildMerkleMap([
      { key: new Uint8Array([0x00]), value: unsignedTxBytes }
    ]);
    store.addMerkleMap(globalMap);

    // 2. Input Maps
    const inputMaps = [];
    const inputCommitments = [];

    for (let i = 0; i < cleanInputs.length; i++) {
      const inp = cleanInputs[i];
      const utxo = selectedUtxos[i] || inp;
      const inEntries = [];

      // SIGHASH_TYPE = 0x01 (SIGHASH_ALL uint32 LE)
      const shBuf = new Uint8Array([0x01, 0x00, 0x00, 0x00]);
      inEntries.push({ key: new Uint8Array([0x03]), value: shBuf });

      // Witness UTXO
      const amtBuf = new Uint8Array(8);
      new DataView(amtBuf.buffer).setBigUint64(0, BigInt(Math.round(Number(utxo.amountSats || utxo.value || 0))), true);
      const spk = hexToBytes(utxo.scriptPubKeyHex || '');
      const witnessUtxoVal = concatByteArrays([amtBuf, encodeBtcVarInt(spk.length), spk]);
      inEntries.push({ key: new Uint8Array([0x01]), value: witnessUtxoVal });

      if (utxo.rawTxHex) {
        inEntries.push({ key: new Uint8Array([0x00]), value: hexToBytes(utxo.rawTxHex) });
      }

      // BIP32 Derivation
      const inputPath = utxo.derivationPath || pathStr;
      const inpSteps = parseBip32PathSteps(inputPath).steps;
      const inpStepsLE = serializeBip32StepsLE(inpSteps);
      const derivVal = concatByteArrays([fpBytes, inpStepsLE]);

      const pubKey = hexToBytes(currentWalletDerivedState.publicKeyHex || '');
      if (scriptType === 'TAPROOT') {
        const xOnly = pubKey.length === 33 ? pubKey.subarray(1) : pubKey;
        // PSBT_IN_TAP_BIP32_DERIVATION = 0x16
        const tapKey = concatByteArrays([new Uint8Array([0x16]), xOnly]);
        const tapVal = concatByteArrays([new Uint8Array([0x00]), derivVal]); // 0 leaf hashes
        inEntries.push({ key: tapKey, value: tapVal });
      } else {
        // PSBT_IN_BIP32_DERIVATION = 0x06
        const b32Key = concatByteArrays([new Uint8Array([0x06]), pubKey]);
        inEntries.push({ key: b32Key, value: derivVal });

        if (scriptType === 'NESTED_SEGWIT') {
          // PSBT_IN_REDEEM_SCRIPT = 0x04 (0x00 0x14 <hash160>)
          const h160 = hexToBytes(currentWalletDerivedState.pubKeyHashHex || '');
          inEntries.push({
            key: new Uint8Array([0x04]),
            value: concatByteArrays([new Uint8Array([0x00, 0x14]), h160]),
          });
        }
      }

      const inMap = buildMerkleMap(inEntries);
      inputMaps.push(inMap);
      store.addMerkleMap(inMap);
      inputCommitments.push(inMap.getCommitment());
    }

    // 3. Output Maps
    const outputMaps = [];
    const outputCommitments = [];
    const changePubKey = hexToBytes(currentWalletDerivedState.changePublicKeyHex || currentWalletDerivedState.publicKeyHex || '');

    for (let j = 0; j < outputs.length; j++) {
      const out = outputs[j];
      const outEntries = [];
      const isChange = Boolean(out.isChange || (currentWalletDerivedState.changeAddress && out.address === currentWalletDerivedState.changeAddress));

      if (isChange) {
        const chgSteps = [...accountSteps, 1, 0];
        const chgStepsLE = serializeBip32StepsLE(chgSteps);
        const chgDerivVal = concatByteArrays([fpBytes, chgStepsLE]);

        if (scriptType === 'TAPROOT') {
          const chgXOnly = changePubKey.length === 33 ? changePubKey.subarray(1) : changePubKey;
          // PSBT_OUT_TAP_BIP32_DERIVATION = 0x07
          const tapKey = concatByteArrays([new Uint8Array([0x07]), chgXOnly]);
          const tapVal = concatByteArrays([new Uint8Array([0x00]), chgDerivVal]);
          outEntries.push({ key: tapKey, value: tapVal });
        } else {
          // PSBT_OUT_BIP32_DERIVATION = 0x02
          const b32Key = concatByteArrays([new Uint8Array([0x02]), changePubKey]);
          outEntries.push({ key: b32Key, value: chgDerivVal });
        }
      }

      const outMap = buildMerkleMap(outEntries);
      outputMaps.push(outMap);
      store.addMerkleMap(outMap);
      outputCommitments.push(outMap.getCommitment());
    }

    const inputsTree = buildMerkleTree(inputCommitments);
    const outputsTree = buildMerkleTree(outputCommitments);
    store.addMerkleTree(inputsTree);
    store.addMerkleTree(outputsTree);

    // Initial SIGN_PSBT APDU Payload (CLA=0xE1, INS=0x04)
    const apduDataParts = [
      globalMap.getCommitment(),
      encodeBtcVarInt(inputCommitments.length),
      inputsTree.getRoot(),
      encodeBtcVarInt(outputCommitments.length),
      outputsTree.getRoot(),
      walletId,
      walletHmac,
    ];
    const initialPayload = concatByteArrays(apduDataParts);
    const apduSign = concatByteArrays([
      new Uint8Array([0xe1, 0x04, 0x00, 0x00, initialPayload.length]),
      initialPayload,
    ]);

    hardwareUsbStatusText.innerHTML = `👁️ <strong>กรุณาดูหน้าจอเครื่อง Ledger ของคุณ:</strong> ตรวจสอบ Address ปลายทาง, ยอดเงิน, และค่า Fee แล้วกดปุ่มทั้งสองข้างเพื่อยืนยัน (Approve)...`;

    const yieldedSignatures = new Map();
    let currentResp = await exchangeLedgerApdu(hidDevice, apduSign, 180000);

    if (currentResp.sw === 0x6d00 || currentResp.sw === 0x6e00) {
      return await signTransactionLegacyOnLedger(hidDevice, selectedUtxos, outputs, pathStr, scriptType, builtTx);
    }

    let moreQueue = [];

    while (currentResp.sw === 0xe000) {
      const p = currentResp.payload;
      if (!p || p.length === 0) break;
      const cmd = p[0];

      let continueData = new Uint8Array(0);

      if (cmd === 0x10) {
        // YIELD: Signature returned from Ledger!
        const decIdx = decodeBtcVarInt(p.subarray(1));
        const remAfterIdx = p.subarray(1 + decIdx.length);
        let sigBytes;
        if (remAfterIdx.length > 0) {
          const decSigLen = decodeBtcVarInt(remAfterIdx);
          if (decSigLen.value > 0 && remAfterIdx.length >= decSigLen.length + decSigLen.value) {
            sigBytes = remAfterIdx.subarray(decSigLen.length, decSigLen.length + decSigLen.value);
          } else {
            sigBytes = remAfterIdx;
          }
        } else {
          sigBytes = new Uint8Array(0);
        }
        yieldedSignatures.set(decIdx.value, bytesToHex(sigBytes));
        continueData = new Uint8Array([0x00]);
      } else if (cmd === 0x40) {
        // GET_PREIMAGE: hash lookup
        const hash = p.length >= 34 ? p.subarray(2, 34) : p.subarray(1, 33);
        const preimage = store.getPreimage(hash) || new Uint8Array(0);
        const totalLenVar = encodeBtcVarInt(preimage.length);
        const chunkSize = Math.min(preimage.length, 180);
        const firstChunk = preimage.subarray(0, chunkSize);
        continueData = concatByteArrays([totalLenVar, firstChunk]);
        moreQueue = [];
        for (let off = chunkSize; off < preimage.length; off += 180) {
          moreQueue.push(preimage.subarray(off, Math.min(off + 180, preimage.length)));
        }
      } else if (cmd === 0x41) {
        // GET_MERKLE_LEAF_PROOF
        const rootHash = p.subarray(1, 33);
        const decSize = decodeBtcVarInt(p.subarray(33));
        const decIndex = decodeBtcVarInt(p.subarray(33 + decSize.length));
        const proofObj = store.getMerkleProof(rootHash, decIndex.value);
        if (proofObj) {
          const proofParts = [proofObj.leafHash, new Uint8Array([proofObj.proof.length])];
          for (const sibling of proofObj.proof) {
            proofParts.push(sibling);
          }
          continueData = concatByteArrays(proofParts);
        } else {
          continueData = new Uint8Array(33);
        }
      } else if (cmd === 0x42) {
        // GET_MERKLE_LEAF_INDEX
        const rootHash = p.subarray(1, 33);
        const leafHash = p.subarray(33, 65);
        const idx = store.getMerkleLeafIndex(rootHash, leafHash);
        if (idx >= 0) {
          continueData = concatByteArrays([new Uint8Array([0x01]), encodeBtcVarInt(idx)]);
        } else {
          continueData = new Uint8Array([0x00]);
        }
      } else if (cmd === 0xa0) {
        // GET_MORE_ELEMENTS
        if (moreQueue.length > 0) {
          continueData = moreQueue.shift();
        } else {
          continueData = new Uint8Array(0);
        }
      }

      // Send CONTINUE APDU (CLA=0xF8, INS=0x01, P1=0x00, P2=0x00)
      const apduCont = concatByteArrays([
        new Uint8Array([0xf8, 0x01, 0x00, 0x00, continueData.length]),
        continueData,
      ]);
      currentResp = await exchangeLedgerApdu(hidDevice, apduCont, 180000);
    }

    if (currentResp.sw !== 0x9000) {
      if (currentResp.sw === 0x6985) {
        throw new Error('ผู้ใช้กดยกเลิก (Reject) การทำรายการบนหน้าจอเครื่อง Ledger');
      }
      throw new Error(`เครื่อง Ledger ตอบกลับรหัสผิดพลาด 0x${currentResp.sw.toString(16)} ในระหว่างลงนาม`);
    }

    const signatures = [];
    for (let i = 0; i < cleanInputs.length; i++) {
      const sigHex = yieldedSignatures.get(i);
      if (!sigHex) {
        throw new Error(`ไม่ได้รับลายเซ็นสำหรับ Input ลำดับที่ ${i + 1} จาก Ledger`);
      }
      signatures.push({
        inputIndex: i,
        signatureHex: sigHex,
        pubKeyHex: currentWalletDerivedState.publicKeyHex || '',
      });
    }

    hardwareUsbStatusText.innerHTML = `⚙️ <strong>กำลังประกอบ Signed Bitcoin Transaction Hex...</strong>`;
    const finalTx = await assembleSignedTransactionClient(selectedUtxos, outputs, signatures, scriptType, pathStr);
    return finalTx;
  }

  // Connect Ledger Button -> Opens WebHID & Immediately Scans Address + UTXOs from Ledger Bitcoin App
  connectLedgerUsbBtn.addEventListener('click', async () => {
    resetAutoLockTimer();
    if (!navigator.hid) {
      showAlert(
        'เบราว์เซอร์นี้ไม่รองรับ WebHID สำหรับเชื่อมต่อ Ledger โดยตรง (แนะนำให้เปิดด้วย Chrome, Edge หรือ Brave)',
        'warning'
      );
      return;
    }
    try {
      let dev = activeHardwareSession.type === 'LEDGER' ? activeHardwareSession.device : null;
      if (!dev) {
        const devices = await navigator.hid.requestDevice({
          filters: [{ vendorId: 0x2c97 }],
        });
        if (!devices || devices.length === 0) {
          showAlert('ไม่พบอุปกรณ์ Ledger ที่เลือก กรุณาเสียบสาย USB และปลดล็อกเครื่อง Ledger', 'warning');
          return;
        }
        dev = devices[0];
      }
      activeHardwareSession.type = 'LEDGER';
      activeHardwareSession.device = dev;
      await scanAddressAndUtxoFromLedger(dev, false);
    } catch (err) {
      showAlert(`การเชื่อมต่อ USB Ledger: ${err.message}`, 'warning');
    }
  });

  // Connect Trezor Button -> Opens WebUSB & Immediately Sends Passphrase + Scans Address & UTXOs
  connectTrezorUsbBtn.addEventListener('click', async () => {
    resetAutoLockTimer();
    if (!navigator.usb) {
      showAlert(
        'เบราว์เซอร์นี้ไม่รองรับ WebUSB สำหรับเชื่อมต่อ Trezor โดยตรง (แนะนำให้เปิดด้วย Chrome, Edge หรือ Brave)',
        'warning'
      );
      return;
    }
    try {
      let dev = activeHardwareSession.type === 'TREZOR' ? activeHardwareSession.device : null;
      if (!dev) {
        dev = await navigator.usb.requestDevice({
          filters: [
            { vendorId: 0x534c },
            { vendorId: 0x1209, productId: 0x53c1 },
          ],
        });
      }
      if (!dev) return;
      activeHardwareSession.type = 'TREZOR';
      activeHardwareSession.device = dev;
      await scanAddressAndUtxoFromTrezor(dev, true, false);
    } catch (err) {
      showAlert(`การเชื่อมต่อ USB Trezor: ${err.message}`, 'warning');
    }
  });

  // Rescan Hardware Wallet Button (e.g. after updating Trezor Passphrase or opening Bitcoin App on Ledger)
  if (rescanHardwareAddressBtn) {
    rescanHardwareAddressBtn.addEventListener('click', async () => {
      resetAutoLockTimer();
      if (activeHardwareSession.type === 'LEDGER' && activeHardwareSession.device) {
        await scanAddressAndUtxoFromLedger(activeHardwareSession.device, false);
      } else if (activeHardwareSession.type === 'TREZOR' && activeHardwareSession.device) {
        await scanAddressAndUtxoFromTrezor(activeHardwareSession.device, true, false);
      } else {
        showAlert('กรุณากดปุ่ม Connect Ledger หรือ Connect Trezor ด้านบนก่อนครับ', 'warning');
      }
    });
  }

  // Build & Sign Bitcoin Transaction Form
  btcSignForm.addEventListener('submit', async (e) => {
    e.preventDefault();
    resetAutoLockTimer();
    hideAlert();

    const selectedUtxos = utxoItems
      .filter((u) => u.selected)
      .map((u) => ({
        txid: u.txid.trim(),
        vout: Math.round(Number(u.vout || 0)),
        amountSats: Math.round(Number(u.amountSats || 0)),
        rawTxHex: u.rawTxHex || '',
        scriptType: u.scriptType || currentScriptType,
        derivationPath: u.derivationPath || btcDerivationPathInput.value.trim(),
      }));

    if (selectedUtxos.length === 0) {
      showAlert('กรุณาติ๊กเลือกก้อน UTXO ที่ต้องการใช้โอนอย่างน้อย 1 รายการ');
      return;
    }

    const destAddr = destAddressInput.value.trim();
    const sendSats = parseSendAmountToIntegerSats();
    const changeAddr = changeAddressInput.value.trim();
    const changeSats = Math.round(Number(changeAmountSatsInput.value || 0));

    if (!destAddr || sendSats <= 0) {
      showAlert('กรุณากรอก Address ปลายทางผู้รับ และจำนวนที่ต้องการโอนให้ถูกต้อง');
      return;
    }

    const pathStr = ensureMatchingBip32PathForScript(btcDerivationPathInput.value.trim(), currentScriptType);
    btcDerivationPathInput.value = pathStr;

    const changePathStr = currentWalletDerivedState.changePath || toInternalChangePathClient(pathStr);
    const isInternalWalletChange =
      Boolean(changeAddr) &&
      changeAddr === currentWalletDerivedState.changeAddress;
    const { steps: changeSteps } = parseBip32PathSteps(changePathStr);

    const outputs = [{ address: destAddr, amountSats: sendSats, isChange: false }];
    if (changeAddr && changeSats > 0) {
      outputs.push({
        address: changeAddr,
        amountSats: changeSats,
        isChange: isInternalWalletChange,
        changeSteps: isInternalWalletChange ? changeSteps : null,
        scriptType: currentScriptType,
      });
    }

    const isHardwareMode = currentKeySourceMode === 'HARDWARE_USB';
    const words = isHardwareMode ? [] : getActiveSeedWords();

    if (!isHardwareMode && ![12, 15, 18, 20, 24].includes(words.length)) {
      showAlert('กรุณาปลดล็อก Seed หรือกรอก Manual Seed (12, 15, 18, 20, 24 คำ) ให้ครบถ้วน');
      return;
    }

    try {
      const res = await apiPost('/api/btc/sign', {
        words,
        passphrase25: signingPassphrase25Input.value.trim(),
        scriptType: currentScriptType,
        derivationPath: pathStr,
        senderAddress: isHardwareMode ? hwWalletAddressInput.value.trim() : '',
        inputs: selectedUtxos,
        outputs,
        signWithSeed: !isHardwareMode,
      });
      const data = await res.json();
      if (!res.ok || !data.ok) {
        showAlert(data.error || 'ไม่สามารถสร้างหรือลงนามธุรกรรมได้');
        return;
      }

      const tx = data.txResult;
      signedTxOutputPanel.classList.remove('hidden');
      signedTxFeeBadge.textContent = `Fee: ${tx.feeSats} sats (${tx.vsize || '-'} vB) • ${SCRIPT_LABELS[currentScriptType]}`;
      signedTxidDisplay.textContent = tx.txid;
      unsignedPsbtArea.value = tx.unsignedPsbtBase64 || '';

      if (tx.signed) {
        signedHexBlock.classList.remove('hidden');
        signedRawTxHexArea.value = tx.signedTxHex || '';
        showAlert(
          `ลงนามธุรกรรม Bitcoin (${SCRIPT_LABELS[currentScriptType]}) สำเร็จ! พร้อมกด Broadcast โอนเงิน หรือบันทึกไฟล์ Transaction Hex`,
          'success'
        );
      } else if (isHardwareMode && activeHardwareSession.type === 'TREZOR' && activeHardwareSession.device) {
        // Direct Offline Trezor Hardware Signing via trezor-firmware SignTx <-> TxRequest <-> TxAck!
        showAlert('กำลังส่งธุรกรรมไปยังเครื่อง Trezor เพื่อลงนาม (กรุณาดูและกดยืนยันบนหน้าจอ Trezor)...', 'warning');
        const trezorSignedHex = await signTransactionDirectlyOnTrezor(
          activeHardwareSession.device,
          selectedUtxos,
          outputs,
          pathStr,
          currentScriptType
        );
        signedHexBlock.classList.remove('hidden');
        signedRawTxHexArea.value = trezorSignedHex;
        hardwareUsbStatusText.innerHTML =
          '✅ <strong>ลงนามธุรกรรมบนเครื่อง Trezor (Offline SignTx) สำเร็จสมบูรณ์!</strong> พร้อมกด Broadcast โอนเงิน หรือบันทึกไฟล์ Transaction Hex ได้ทันที';
        showAlert(
          `🎉 ลงนามธุรกรรมด้วยเครื่อง Trezor (${SCRIPT_LABELS[currentScriptType]}) สำเร็จ! ได้ Signed Raw Transaction Hex พร้อม Broadcast ทันที`,
          'success'
        );
      } else if (isHardwareMode && activeHardwareSession.type === 'LEDGER' && activeHardwareSession.device) {
        // Direct Offline Ledger Hardware Signing via app-bitcoin SIGN_PSBT (CLA=0xE1, INS=0x04)
        showAlert('กำลังส่งธุรกรรมไปยังเครื่อง Ledger เพื่อลงนาม (กรุณาดูหน้าจอ Ledger และกดยืนยัน Approve)...', 'warning');
        const ledgerSignedRes = await signTransactionDirectlyOnLedger(
          activeHardwareSession.device,
          selectedUtxos,
          outputs,
          pathStr,
          currentScriptType,
          tx
        );
        signedHexBlock.classList.remove('hidden');
        signedRawTxHexArea.value = ledgerSignedRes.signedTxHex;
        if (ledgerSignedRes.txid) {
          signedTxidDisplay.textContent = ledgerSignedRes.txid;
        }
        if (ledgerSignedRes.vsize) {
          signedTxFeeBadge.textContent = `Fee: ${tx.feeSats} sats (${ledgerSignedRes.vsize} vB) • ${SCRIPT_LABELS[currentScriptType]}`;
        }
        hardwareUsbStatusText.innerHTML =
          '✅ <strong>ลงนามธุรกรรมบนเครื่อง Ledger สำเร็จสมบูรณ์!</strong> พร้อมกด Broadcast โอนเงิน หรือบันทึกไฟล์ Transaction Hex ได้ทันที';
        showAlert(
          `🎉 ลงนามธุรกรรมด้วยเครื่อง Ledger (${SCRIPT_LABELS[currentScriptType]}) สำเร็จ! ได้ Signed Raw Transaction Hex พร้อม Broadcast ทันที`,
          'success'
        );
      } else {
        signedHexBlock.classList.add('hidden');
        signedRawTxHexArea.value = '';
        showAlert(
          'สร้างธุรกรรม PSBT สำหรับ Trezor / Ledger สำเร็จ! (หากต้องการให้อุปกรณ์ฮาร์ดแวร์เซ็นออกเป็น Raw TX Hex ทันที ให้กด Connect Trezor หรือ Connect Ledger ด้านบนก่อนกดปุ่มนี้)',
          'success'
        );
      }
    } catch (err) {
      showAlert(`เกิดข้อผิดพลาดในการลงนามธุรกรรม: ${err.message}`);
    }
  });

  function saveSignedTxHexToFile() {
    const rawHex = signedRawTxHexArea.value.trim();
    if (!rawHex) {
      showAlert('ยังไม่มี Signed Raw Transaction Hex กรุณากดลงนามธุรกรรม (Sign Transaction) ให้สำเร็จก่อนครับ', 'warning');
      return;
    }
    const txid = (signedTxidDisplay.textContent || 'tx').trim().slice(0, 16);
    const blob = new Blob([rawHex + '\n'], { type: 'text/plain;charset=utf-8' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `signed-bitcoin-tx-${txid}.hex.txt`;
    a.click();
    URL.revokeObjectURL(url);
    showAlert(
      '💾 บันทึกไฟล์ Signed Transaction Hex (.hex.txt) สำเร็จ! สามารถนำไฟล์นี้ไปวางที่ https://mempool.space/tx/push บนเครื่องที่ต่อเน็ตได้ทันที',
      'success'
    );
  }

  copySignedHexBtn.addEventListener('click', async () => {
    if (!signedRawTxHexArea.value) return;
    await navigator.clipboard.writeText(signedRawTxHexArea.value);
    showAlert('คัดลอก Signed Raw Transaction Hex เรียบร้อยแล้ว สามารถนำไปวางที่ https://mempool.space/tx/push ได้ทันที', 'success');
  });

  if (saveSignedHexFileBtn) {
    saveSignedHexFileBtn.addEventListener('click', saveSignedTxHexToFile);
  }

  copyPsbtBtn.addEventListener('click', async () => {
    if (!unsignedPsbtArea.value) return;
    await navigator.clipboard.writeText(unsignedPsbtArea.value);
    showAlert('คัดลอก PSBT Base64 สำหรับ Trezor / Ledger เรียบร้อยแล้ว', 'success');
  });

  broadcastTxBtn.addEventListener('click', async () => {
    const rawHex = signedRawTxHexArea.value.trim();
    if (!rawHex) {
      showAlert(
        'ยังไม่มี Signed Raw Transaction Hex! กรุณาเชื่อมต่อ Trezor แล้วกดปุ่ม "✍️ ลงนามธุรกรรม (Sign Transaction)" เพื่อให้ Trezor เซ็นธุรกรรมก่อนกด Broadcast',
        'warning'
      );
      return;
    }
    try {
      const res = await fetch('https://mempool.space/api/tx', {
        method: 'POST',
        headers: { 'Content-Type': 'text/plain' },
        body: rawHex,
      });
      const text = (await res.text()).trim();
      if (res.ok) {
        showAlert(
          `🎉 Broadcast โอน Bitcoin เข้าสู่เครือข่าย Mempool.space สำเร็จ! TXID: ${text}`,
          'success'
        );
      } else {
        showAlert(`เครือข่ายปฏิเสธธุรกรรม: ${text}`, 'error');
      }
    } catch (_err) {
      try {
        await navigator.clipboard.writeText(rawHex);
      } catch (_e) {
        // Ignore clipboard error
      }
      saveSignedTxHexToFile();
      showAlert(
        'เครื่องปัจจุบันไม่ได้ต่ออินเทอร์เน็ต (Offline Mode): ระบบได้คัดลอกและบันทึกไฟล์ Signed Transaction Hex ให้แล้ว คุณสามารถนำไปวาง Broadcast ที่ https://mempool.space/tx/push บนเครื่องที่ต่อเน็ตได้ทันที',
        'warning'
      );
    }
  });

  toggleMaskWordsBtn.addEventListener('click', () => {
    wordsMasked = !wordsMasked;
    decryptedWordsGrid.querySelectorAll('.decrypted-word-text').forEach((el) => {
      el.classList.toggle('masked', wordsMasked);
    });
    decryptedPassphraseValue.classList.toggle('masked', wordsMasked);
  });

  copyAllWordsBtn.addEventListener('click', async () => {
    if (!lastDecryptedPayload) return;
    const fullText = lastDecryptedPayload.words.join(' ');
    try {
      await navigator.clipboard.writeText(fullText);
      showAlert('คัดลอก Seedphrase ลง Clipboard แล้ว (จะล้าง Clipboard อัตโนมัติใน 30 วินาที)', 'success');
      setTimeout(async () => {
        try {
          await navigator.clipboard.writeText('');
        } catch (_e) {
          // Ignore
        }
      }, 30000);
    } catch (_e) {
      showAlert('ไม่สามารถคัดลอกอัตโนมัติได้ กรุณาจดบันทึกจากหน้าจอ', 'warning');
    }
  });

  lockVaultNowBtn.addEventListener('click', async () => {
    clearDecryptedMemoryAndLock();
    hideAlert();
    await refreshAppStatus();
  });

  // =========================================================================
  // 6. Double Confirmation Reset Program Modal
  // =========================================================================
  openResetModalBtn.addEventListener('click', () => {
    resetConfirmStep1.classList.remove('hidden');
    resetConfirmStep2.classList.add('hidden');
    resetConfirmTextInput.value = '';
    confirmFinalResetBtn.disabled = true;
    resetConfirmModal.classList.remove('hidden');
  });

  const closeResetModal = () => {
    resetConfirmModal.classList.add('hidden');
  };

  cancelResetBtn1.addEventListener('click', closeResetModal);
  cancelResetBtn2.addEventListener('click', closeResetModal);

  proceedResetStep2Btn.addEventListener('click', () => {
    resetConfirmStep1.classList.add('hidden');
    resetConfirmStep2.classList.remove('hidden');
    resetConfirmTextInput.focus();
  });

  resetConfirmTextInput.addEventListener('input', () => {
    confirmFinalResetBtn.disabled = resetConfirmTextInput.value.trim().toUpperCase() !== 'RESET';
  });

  confirmFinalResetBtn.addEventListener('click', async () => {
    if (resetConfirmTextInput.value.trim().toUpperCase() !== 'RESET') return;
    try {
      const res = await apiPost('/api/reset', { confirmToken: 'RESET' });
      const data = await res.json();
      closeResetModal();
      if (data.ok) {
        showAlert('ลบข้อมูลเดิมทั้งหมด (Zero-Wipe) และเข้าสู่โหมดเริ่มต้นตั้งค่าใหม่เรียบร้อยแล้ว', 'warning');
        await refreshAppStatus();
      }
    } catch (err) {
      showAlert(`เกิดข้อผิดพลาดในการรีเซ็ต: ${err.message}`);
    }
  });

  // =========================================================================
  // 7. Initial Bootstrap
  // =========================================================================
  async function refreshAppStatus() {
    try {
      const res = await fetch('/api/status');
      const status = await res.json();

      if (openDirectHwModeTopBtn) {
        openDirectHwModeTopBtn.classList.remove('hidden');
      }

      if (!status.initialized || status.mode === 'SETUP') {
        unlockView.classList.add('hidden');
        decryptedView.classList.add('hidden');
        setupView.classList.remove('hidden');
        renderSeedInputs(selectedWordCount);
        renderSetupQuestions();
      } else {
        await renderUnlockView(status);
      }
    } catch (err) {
      showAlert(`ไม่สามารถโหลดสถานะโปรแกรมได้: ${err.message}`);
    }
  }

  refreshAppStatus();
})();
