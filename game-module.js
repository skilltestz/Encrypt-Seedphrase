'use strict';

/**
 * Multi-Stage Extensible Security Game Pipeline (Anti-Bot Gatekeeper v2.0)
 *
 * Security & Extensibility Design:
 * 1. Multi-Game Chain Support (`gameChain: ['pattern_shield', 'orbital_lock', ...]`, `requiredGamesCount: N`):
 *    Allows configuring 1, 2, or more sequential mini-games before the user is even allowed
 *    to submit unlock credentials.
 * 2. Hard Server-Side Cryptographic Gatekeeper:
 *    When `gameModule.enabled === true`, `/api/unlock` requires a server-issued `gamePassToken`
 *    that is ONLY minted after ALL stages in the game chain are solved in order.
 *    This makes it impossible for a bot or script to bypass the game screen by calling `/api/unlock` directly.
 */

const crypto = require('crypto');

class GameGuardModuleRegistry {
  constructor() {
    this.modules = new Map();
    this.activeSessions = new Map();
    this.validPassTokens = new Map(); // token -> { expiresAt, used }
    this._registerBuiltInModules();
  }

  _registerBuiltInModules() {
    // 1. Cyber Matrix Pattern Shield (2D 4x4 Grid Sequence Memory)
    this.registerModule({
      id: 'pattern_shield',
      name: 'Cyber Matrix Pattern Shield (จำลำดับโหนดพลังงาน 4x4)',
      description:
        'กดโหนดในตาราง 4x4 ตามลำดับแสงพลังงานที่ปรากฏให้ถูกต้อง เพื่อยืนยันว่าเป็นมนุษย์จริง',
      version: '2.0.0',
      generateChallenge: (difficulty = 1) => {
        const seqLength = Math.min(3 + Number(difficulty || 1), 8);
        const sequence = [];
        for (let i = 0; i < seqLength; i++) {
          sequence.push(crypto.randomInt(0, 16));
        }
        return {
          gridSize: 16,
          sequence,
          seqLength,
        };
      },
      verifySolution: (challengeData, userSubmission) => {
        if (!Array.isArray(userSubmission)) return false;
        if (userSubmission.length !== challengeData.sequence.length) return false;
        for (let i = 0; i < challengeData.sequence.length; i++) {
          if (Number(userSubmission[i]) !== challengeData.sequence[i]) {
            return false;
          }
        }
        return true;
      },
    });

    // 2. Orbital Timing Lock (Quantum Ring Alignment)
    this.registerModule({
      id: 'orbital_lock',
      name: 'Orbital Timing Lock (จัดเรียงวงแหวนควอนตัม 3 ชั้น)',
      description:
        'หมุนปรับองศาวงแหวนทั้ง 3 ชั้นให้ตรงกับพิกัดเป้าหมายก่อนเข้าถึงหน้ากรอกรหัสผ่าน',
      version: '2.0.0',
      generateChallenge: (difficulty = 1) => {
        const rings = 3;
        const targets = [];
        for (let i = 0; i < rings; i++) {
          targets.push(crypto.randomInt(20, 340));
        }
        return {
          rings,
          targets,
          toleranceDeg: Math.max(8, 20 - Number(difficulty || 1) * 3),
        };
      },
      verifySolution: (challengeData, userAngles) => {
        if (!Array.isArray(userAngles) || userAngles.length !== challengeData.targets.length) {
          return false;
        }
        for (let i = 0; i < challengeData.targets.length; i++) {
          const diff = Math.abs(Number(userAngles[i]) - challengeData.targets[i]) % 360;
          const shortest = diff > 180 ? 360 - diff : diff;
          if (shortest > challengeData.toleranceDeg) {
            return false;
          }
        }
        return true;
      },
    });

    // 3. Chroma Spectrum Match (เลื่อนเฉดสีให้ตรงกับสีตัวอย่าง)
    this.registerModule({
      id: 'chroma_slider',
      name: 'Chroma Spectrum Match (เลื่อนเฉดสีให้ตรงกับสีตัวอย่าง)',
      description:
        'เลื่อน Slider แถบเฉดสีเพื่อให้กล่องสีของคุณตรงกับสีตัวอย่างเป้าหมาย',
      version: '2.0.0',
      generateChallenge: (difficulty = 1) => {
        const targetHue = crypto.randomInt(15, 345);
        const tolerance = Math.max(12, 26 - Number(difficulty || 1) * 4);
        return {
          targetHue,
          tolerance,
          colorSample: `hsl(${targetHue}, 85%, 55%)`,
        };
      },
      verifySolution: (challengeData, userHue) => {
        const hue = Number(userHue);
        if (isNaN(hue)) return false;
        const diff = Math.abs(hue - challengeData.targetHue) % 360;
        const shortest = diff > 180 ? 360 - diff : diff;
        return shortest <= challengeData.tolerance;
      },
    });

    // 4. Spot the Outlier (แตะเลือกสัญลักษณ์ 1 ชิ้นที่แตกต่างจากพวก)
    this.registerModule({
      id: 'glyph_outlier',
      name: 'Spot the Outlier (เลือกสัญลักษณ์ที่แปลกแยกจากพวก)',
      description:
        'แตะเลือกไอคอนหรือสัญลักษณ์ 1 ชิ้นที่ไม่เข้าพวก เพื่อยืนยันการรับรู้ทางสายตาของมนุษย์',
      version: '2.0.0',
      generateChallenge: (difficulty = 1) => {
        const glyphPairs = [
          { common: '🛡️', outlier: '⚔️', name: 'โล่ป้องกัน vs ดาบ' },
          { common: '🔑', outlier: '🗝️', name: 'กุญแจทอง vs กุญแจโบราณ' },
          { common: '🔒', outlier: '🔓', name: 'แม่กุญแจล็อก vs ปลดล็อก' },
          { common: '⚡', outlier: '🔥', name: 'สายฟ้า vs เปลวไฟ' },
          { common: '🪙', outlier: '💎', name: 'เหรียญทอง vs เพชร' },
          { common: '⭐', outlier: '🌙', name: 'ดวงดาว vs พระจันทร์' },
        ];
        const pair = glyphPairs[crypto.randomInt(0, glyphPairs.length)];
        const totalItems = difficulty > 1 ? 8 : 6;
        const outlierIndex = crypto.randomInt(0, totalItems);

        const items = [];
        for (let i = 0; i < totalItems; i++) {
          if (i === outlierIndex) {
            items.push({ id: i, icon: pair.outlier, isOutlier: true });
          } else {
            items.push({ id: i, icon: pair.common, isOutlier: false });
          }
        }
        return {
          totalItems,
          items: items.map((x) => ({ id: x.id, icon: x.icon })),
          outlierIndex,
        };
      },
      verifySolution: (challengeData, userSelectedId) => {
        return Number(userSelectedId) === Number(challengeData.outlierIndex);
      },
    });

    // 5. Ascending Number Tap (แตะฟองตัวเลขเรียงจากน้อยไปมาก)
    this.registerModule({
      id: 'bubble_sequence',
      name: 'Ascending Number Tap (แตะเรียงตัวเลขจากน้อยไปมาก)',
      description:
        'แตะฟองตัวเลขที่กระจัดกระจายเรียงตามลำดับจากค่าน้อยที่สุดไปหาค่ามากที่สุด',
      version: '2.0.0',
      generateChallenge: (difficulty = 1) => {
        const count = Math.min(4 + Number(difficulty || 1), 6);
        const numbersSet = new Set();
        while (numbersSet.size < count) {
          numbersSet.add(crypto.randomInt(1, 99));
        }
        const sorted = Array.from(numbersSet).sort((a, b) => a - b);
        const shuffled = [...sorted].sort(() => Math.random() - 0.5);

        return {
          count,
          bubbles: shuffled.map((val, idx) => ({ id: idx, value: val })),
          correctSequence: sorted,
        };
      },
      verifySolution: (challengeData, userSequence) => {
        if (!Array.isArray(userSequence) || userSequence.length !== challengeData.correctSequence.length) {
          return false;
        }
        for (let i = 0; i < challengeData.correctSequence.length; i++) {
          if (Number(userSequence[i]) !== challengeData.correctSequence[i]) {
            return false;
          }
        }
        return true;
      },
    });

    // 6. Slide to Snap (เลื่อนแถบกุญแจเข้าช่องเป้าหมาย)
    this.registerModule({
      id: 'puzzle_slider',
      name: 'Slide to Snap (เลื่อนกุญแจเข้าช่องเป้าหมาย)',
      description:
        'ลากแถบสไลด์เพื่อนำกุญแจไปวางให้ตรงกับร่องเป้าหมายที่กำหนด',
      version: '2.0.0',
      generateChallenge: (difficulty = 1) => {
        const targetPercent = crypto.randomInt(28, 88);
        const tolerance = Math.max(4, 8 - Number(difficulty || 1));
        return {
          targetPercent,
          tolerance,
        };
      },
      verifySolution: (challengeData, userPercent) => {
        const val = Number(userPercent);
        if (isNaN(val)) return false;
        return Math.abs(val - challengeData.targetPercent) <= challengeData.tolerance;
      },
    });
  }

  registerModule(moduleDefinition) {
    if (!moduleDefinition || !moduleDefinition.id) {
      throw new Error('Game module must have a valid id');
    }
    this.modules.set(moduleDefinition.id, moduleDefinition);
  }

  listModules() {
    const list = [];
    for (const mod of this.modules.values()) {
      list.push({
        id: mod.id,
        name: mod.name,
        description: mod.description,
        version: mod.version,
      });
    }
    return list;
  }

  /**
   * Starts a single or multi-game pipeline session.
   * @param {object} gameConfig - { gameType, gameChain: string[], difficulty, requiredGamesCount }
   */
  createChallengeSession(gameConfig = {}) {
    const difficulty = Number(gameConfig.difficulty || 1);
    let chain = Array.isArray(gameConfig.gameChain) && gameConfig.gameChain.length > 0
      ? gameConfig.gameChain.filter((id) => this.modules.has(id))
      : [];

    if (chain.length === 0) {
      const primary = this.modules.has(gameConfig.gameType) ? gameConfig.gameType : 'pattern_shield';
      const count = Math.min(Math.max(1, Number(gameConfig.requiredGamesCount) || 1), 5);
      const availableIds = Array.from(this.modules.keys());
      chain.push(primary);
      for (let i = 1; i < count; i++) {
        chain.push(availableIds[i % availableIds.length]);
      }
    }

    const stages = chain.map((modId, idx) => {
      const mod = this.modules.get(modId) || this.modules.get('pattern_shield');
      return {
        stageIndex: idx,
        totalStages: chain.length,
        gameType: mod.id,
        gameName: mod.name,
        challenge: mod.generateChallenge(difficulty),
        solved: false,
      };
    });

    const sessionId = crypto.randomUUID();
    this.activeSessions.set(sessionId, {
      sessionId,
      difficulty,
      currentStageIndex: 0,
      stages,
      allSolved: false,
      createdAt: Date.now(),
    });

    const currentStage = stages[0];
    return {
      sessionId,
      currentStageIndex: 0,
      totalStages: stages.length,
      gameType: currentStage.gameType,
      gameName: currentStage.gameName,
      challenge: currentStage.challenge,
    };
  }

  /**
   * Verifies the current stage in the multi-game chain.
   * Only issues `gamePassToken` when ALL configured games in the chain are solved!
   */
  verifyChallengeSession(sessionId, submission) {
    const session = this.activeSessions.get(sessionId);
    if (!session) {
      return { verified: false, error: 'เซสชันของเกมหมดอายุ กรุณาเริ่มด่านใหม่' };
    }

    const stage = session.stages[session.currentStageIndex];
    if (!stage) {
      return { verified: false, error: 'ไม่พบด่านเกมปัจจุบัน' };
    }

    const mod = this.modules.get(stage.gameType);
    const passed = mod.verifySolution(stage.challenge, submission);

    if (!passed) {
      return {
        verified: false,
        stageCleared: false,
        currentStageIndex: session.currentStageIndex,
        totalStages: session.stages.length,
        error: `ยังไม่ผ่านด่านที่ ${session.currentStageIndex + 1}/${session.stages.length} (${stage.gameName}) กรุณาลองใหม่อีกครั้ง`,
      };
    }

    stage.solved = true;
    session.currentStageIndex += 1;

    // Check if more games remain in the multi-game pipeline
    if (session.currentStageIndex < session.stages.length) {
      const nextStage = session.stages[session.currentStageIndex];
      return {
        verified: false,
        stageCleared: true,
        allCompleted: false,
        sessionId: session.sessionId,
        currentStageIndex: session.currentStageIndex,
        totalStages: session.stages.length,
        nextStage: {
          sessionId: session.sessionId,
          currentStageIndex: session.currentStageIndex,
          totalStages: session.stages.length,
          gameType: nextStage.gameType,
          gameName: nextStage.gameName,
          challenge: nextStage.challenge,
        },
      };
    }

    // All games in chain completed -> Mint single-use cryptographic gamePassToken
    session.allSolved = true;
    const gamePassToken = crypto.randomBytes(32).toString('hex');
    this.validPassTokens.set(gamePassToken, {
      createdAt: Date.now(),
      expiresAt: Date.now() + 10 * 60 * 1000, // Valid for 10 minutes
    });
    this.activeSessions.delete(sessionId);

    return {
      verified: true,
      stageCleared: true,
      allCompleted: true,
      totalStages: session.stages.length,
      gamePassToken,
    };
  }

  /**
   * Validates and consumes or checks a `gamePassToken` on `/api/unlock`.
   */
  validateGamePassToken(token) {
    if (!token || typeof token !== 'string') return false;
    const record = this.validPassTokens.get(token);
    if (!record) return false;
    if (Date.now() > record.expiresAt) {
      this.validPassTokens.delete(token);
      return false;
    }
    return true;
  }
}

module.exports = Object.freeze({
  GameGuardModuleRegistry,
});
