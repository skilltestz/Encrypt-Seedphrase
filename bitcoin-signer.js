'use strict';

/**
 * Pure Zero-Dependency Bitcoin HD Wallet, Multi-Script Derivation & Transaction Signer (v4.0)
 *
 * Supports:
 * 1. All 4 Bitcoin Script Types:
 *    - Taproot (P2TR, BIP86: m/86'/0'/0'/0/0, bc1p..., Bech32m BIP350 + BIP340/BIP341 TapTweak)
 *    - Native SegWit (P2WPKH, BIP84: m/84'/0'/0'/0/0, bc1q..., Bech32 BIP173)
 *    - Nested SegWit (P2SH-P2WPKH, BIP49: m/49'/0'/0'/0/0, 3..., Base58Check)
 *    - Legacy (P2PKH, BIP44: m/44'/0'/0'/0/0, 1..., Base58Check)
 * 2. Three Signing / Key Source Modes:
 *    - Mode A: Direct Hardware Wallet (Trezor / Ledger) WITHOUT unlocking the 24-word vault!
 *      Builds standard BIP174 PSBT from Hardware Wallet Address/PubKey & selected UTXOs.
 *    - Mode B: Unlocked Vault Seed (Default after unlocking) + optional dynamic 25th Passphrase.
 *    - Mode C: Manual Imported Seed (12/15/18/20/24 words + optional 25th Passphrase) after unlocking.
 */

const crypto = require('crypto');

const SCRIPT_TYPES = Object.freeze({
  TAPROOT: { id: 'TAPROOT', label: 'Taproot (bc1p...)', defaultPath: "m/86'/0'/0'/0/0" },
  NATIVE_SEGWIT: { id: 'NATIVE_SEGWIT', label: 'Native SegWit (bc1q...)', defaultPath: "m/84'/0'/0'/0/0" },
  NESTED_SEGWIT: { id: 'NESTED_SEGWIT', label: 'Nested SegWit (3...)', defaultPath: "m/49'/0'/0'/0/0" },
  LEGACY: { id: 'LEGACY', label: 'Legacy (1...)', defaultPath: "m/44'/0'/0'/0/0" },
});

// ============================================================================
// 1. Secp256k1 Elliptic Curve Arithmetic (ECDSA + BIP340 Schnorr / TapTweak)
// ============================================================================
const SECP256K1 = (() => {
  const P = 0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2fn;
  const N = 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141n;
  const HALF_N = N >> 1n;
  const Gx = 0x79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798n;
  const Gy = 0x483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8n;

  function mod(a, m = P) {
    const res = a % m;
    return res >= 0n ? res : res + m;
  }

  function modPow(base, exp, m = P) {
    let result = 1n;
    let b = mod(base, m);
    let e = exp;
    while (e > 0n) {
      if (e & 1n) result = (result * b) % m;
      b = (b * b) % m;
      e >>= 1n;
    }
    return result;
  }

  function modInverse(a, m = P) {
    let t = 0n;
    let newT = 1n;
    let r = m;
    let newR = mod(a, m);
    while (newR !== 0n) {
      const q = r / newR;
      [t, newT] = [newT, t - q * newT];
      [r, newR] = [newR, r - q * newR];
    }
    if (r > 1n) throw new Error('Value is not invertible');
    return t < 0n ? t + m : t;
  }

  function pointAdd(p1, p2) {
    if (!p1) return p2;
    if (!p2) return p1;
    const [x1, y1] = p1;
    const [x2, y2] = p2;
    if (x1 === x2 && y1 !== y2) return null;

    let lam;
    if (x1 === x2 && y1 === y2) {
      if (y1 === 0n) return null;
      lam = mod(3n * x1 * x1 * modInverse(2n * y1));
    } else {
      lam = mod((y2 - y1) * modInverse(x2 - x1));
    }

    const x3 = mod(lam * lam - x1 - x2);
    const y3 = mod(lam * (x1 - x3) - y1);
    return [x3, y3];
  }

  function pointMultiply(k, point = [Gx, Gy]) {
    let scalar = mod(k, N);
    if (scalar === 0n) return null;
    let result = null;
    let addend = point;
    while (scalar > 0n) {
      if (scalar & 1n) {
        result = pointAdd(result, addend);
      }
      addend = pointAdd(addend, addend);
      scalar >>= 1n;
    }
    return result;
  }

  function bigintTo32Bytes(num) {
    const hex = num.toString(16).padStart(64, '0');
    return Buffer.from(hex, 'hex');
  }

  function bytesToBigint(buf) {
    return BigInt('0x' + buf.toString('hex'));
  }

  function getPublicKey(privateKeyBytes, compressed = true) {
    const d = bytesToBigint(privateKeyBytes);
    if (d <= 0n || d >= N) throw new Error('Invalid private key scalar');
    const pt = pointMultiply(d);
    const xBuf = bigintTo32Bytes(pt[0]);
    if (!compressed) {
      const yBuf = bigintTo32Bytes(pt[1]);
      return Buffer.concat([Buffer.from([0x04]), xBuf, yBuf]);
    }
    const prefix = (pt[1] & 1n) === 0n ? 0x02 : 0x03;
    return Buffer.concat([Buffer.from([prefix]), xBuf]);
  }

  function compressPoint(pt) {
    const prefix = (pt[1] & 1n) === 0n ? 0x02 : 0x03;
    return Buffer.concat([Buffer.from([prefix]), bigintTo32Bytes(pt[0])]);
  }

  function decompressPoint(pubKeyBuf) {
    const buf = Buffer.isBuffer(pubKeyBuf) ? pubKeyBuf : Buffer.from(pubKeyBuf, 'hex');
    if (buf.length === 65 && buf[0] === 0x04) {
      return [bytesToBigint(buf.subarray(1, 33)), bytesToBigint(buf.subarray(33, 65))];
    }
    if (buf.length === 33 && (buf[0] === 0x02 || buf[0] === 0x03)) {
      const x = bytesToBigint(buf.subarray(1, 33));
      const rhs = mod(modPow(x, 3n, P) + 7n, P);
      let y = modPow(rhs, (P + 1n) / 4n, P);
      const isOdd = (y & 1n) === 1n;
      const wantOdd = buf[0] === 0x03;
      if (isOdd !== wantOdd) y = P - y;
      return [x, y];
    }
    throw new Error('Invalid secp256k1 public key length or prefix');
  }

  function deriveTaprootOutputKeyFromPoint(pt) {
    const evenPt = (pt[1] & 1n) === 0n ? pt : [pt[0], P - pt[1]];
    const internalPubKeyX = bigintTo32Bytes(evenPt[0]);
    const tweakHash = taggedHash('TapTweak', internalPubKeyX);
    const t = bytesToBigint(tweakHash);
    if (t >= N) throw new Error('Invalid TapTweak scalar');
    const Q_pt = pointAdd(evenPt, pointMultiply(t));
    return {
      internalPubKeyX,
      outputPubKeyX: bigintTo32Bytes(Q_pt[0]),
      parity: Number(Q_pt[1] & 1n),
    };
  }

  function taggedHash(tag, msgBuf) {
    const tagHash = crypto.createHash('sha256').update(tag, 'utf8').digest();
    return crypto
      .createHash('sha256')
      .update(Buffer.concat([tagHash, tagHash, msgBuf]))
      .digest();
  }

  /**
   * BIP341 Taproot Key-Path Output Key Tweaking (Q = P + int(HashTapTweak(P_x)) * G)
   */
  function deriveTaprootOutputKey(privateKeyBytes) {
    let d = bytesToBigint(privateKeyBytes);
    let P_pt = pointMultiply(d);
    if ((P_pt[1] & 1n) !== 0n) {
      d = N - d;
      P_pt = [P_pt[0], P - P_pt[1]];
    }
    const internalPubKeyX = bigintTo32Bytes(P_pt[0]);
    const tweakHash = taggedHash('TapTweak', internalPubKeyX);
    const t = bytesToBigint(tweakHash);
    if (t >= N) throw new Error('Invalid TapTweak scalar');
    const Q_pt = pointAdd(P_pt, pointMultiply(t));
    const tweakedPriv = mod(d + t, N);
    const outputPubKeyX = bigintTo32Bytes(Q_pt[0]);
    return {
      internalPubKeyX,
      outputPubKeyX,
      tweakedPrivateKey: bigintTo32Bytes(tweakedPriv),
      parity: Number(Q_pt[1] & 1n),
    };
  }

  function generateDeterministicK(msgHash32, privKey32) {
    let v = Buffer.alloc(32, 0x01);
    let k = Buffer.alloc(32, 0x00);
    k = crypto
      .createHmac('sha256', k)
      .update(Buffer.concat([v, Buffer.from([0x00]), privKey32, msgHash32]))
      .digest();
    v = crypto.createHmac('sha256', k).update(v).digest();
    k = crypto
      .createHmac('sha256', k)
      .update(Buffer.concat([v, Buffer.from([0x01]), privKey32, msgHash32]))
      .digest();
    v = crypto.createHmac('sha256', k).update(v).digest();

    while (true) {
      v = crypto.createHmac('sha256', k).update(v).digest();
      const candidate = bytesToBigint(v);
      if (candidate >= 1n && candidate < N) {
        return candidate;
      }
      k = crypto
        .createHmac('sha256', k)
        .update(Buffer.concat([v, Buffer.from([0x00])]))
        .digest();
      v = crypto.createHmac('sha256', k).update(v).digest();
    }
  }

  function signECDSA(msgHash32, privKey32) {
    const d = bytesToBigint(privKey32);
    const z = bytesToBigint(msgHash32);
    const k = generateDeterministicK(msgHash32, privKey32);
    const R = pointMultiply(k);
    const r = mod(R[0], N);
    if (r === 0n) throw new Error('Invalid ECDSA r=0');
    let s = mod(modInverse(k, N) * mod(z + r * d, N), N);
    if (s === 0n) throw new Error('Invalid ECDSA s=0');
    if (s > HALF_N) {
      s = N - s;
    }
    return encodeDERSignature(r, s);
  }

  /**
   * BIP340 Schnorr Signature for Taproot (64 bytes)
   */
  function signSchnorrBIP340(msgHash32, privKey32) {
    let d = bytesToBigint(privKey32);
    let P_pt = pointMultiply(d);
    if ((P_pt[1] & 1n) !== 0n) {
      d = N - d;
    }
    const dBytes = bigintTo32Bytes(d);
    const pubXBytes = bigintTo32Bytes(P_pt[0]);
    const aux = Buffer.alloc(32, 0);
    const tHash = taggedHash('BIP0340/aux', aux);
    const maskedD = Buffer.alloc(32);
    for (let i = 0; i < 32; i++) maskedD[i] = dBytes[i] ^ tHash[i];
    const randHash = taggedHash('BIP0340/nonce', Buffer.concat([maskedD, pubXBytes, msgHash32]));
    let k = mod(bytesToBigint(randHash), N);
    if (k === 0n) throw new Error('Invalid Schnorr nonce');
    let R_pt = pointMultiply(k);
    if ((R_pt[1] & 1n) !== 0n) {
      k = N - k;
    }
    const rBytes = bigintTo32Bytes(R_pt[0]);
    const eHash = taggedHash('BIP0340/challenge', Buffer.concat([rBytes, pubXBytes, msgHash32]));
    const e = mod(bytesToBigint(eHash), N);
    const s = mod(k + e * d, N);
    return Buffer.concat([rBytes, bigintTo32Bytes(s)]);
  }

  function encodeDERInteger(bigVal) {
    let hex = bigVal.toString(16);
    if (hex.length % 2 !== 0) hex = '0' + hex;
    let buf = Buffer.from(hex, 'hex');
    if (buf[0] & 0x80) {
      buf = Buffer.concat([Buffer.from([0x00]), buf]);
    }
    return Buffer.concat([Buffer.from([0x02, buf.length]), buf]);
  }

  function encodeDERSignature(r, s) {
    const rDer = encodeDERInteger(r);
    const sDer = encodeDERInteger(s);
    const totalLen = rDer.length + sDer.length;
    return Buffer.concat([Buffer.from([0x30, totalLen]), rDer, sDer]);
  }

  return Object.freeze({
    P,
    N,
    mod,
    modPow,
    pointAdd,
    pointMultiply,
    bigintTo32Bytes,
    bytesToBigint,
    getPublicKey,
    compressPoint,
    decompressPoint,
    deriveTaprootOutputKey,
    deriveTaprootOutputKeyFromPoint,
    signECDSA,
    signSchnorrBIP340,
  });
})();

// ============================================================================
// 2. Encoding Helpers: Base58Check, Bech32 (SegWit v0) & Bech32m (Taproot v1)
// ============================================================================
function sha256(buf) {
  return crypto.createHash('sha256').update(buf).digest();
}

function hash256(buf) {
  return sha256(sha256(buf));
}

function hash160(buf) {
  const s = sha256(buf);
  return crypto.createHash('ripemd160').update(s).digest();
}

const BASE58_ALPHABET = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';

function base58CheckEncode(versionByte, payloadBuf) {
  const data = Buffer.concat([Buffer.from([versionByte]), payloadBuf]);
  const checksum = hash256(data).subarray(0, 4);
  const full = Buffer.concat([data, checksum]);

  let num = BigInt('0x' + full.toString('hex'));
  let out = '';
  while (num > 0n) {
    const rem = Number(num % 58n);
    out = BASE58_ALPHABET[rem] + out;
    num /= 58n;
  }
  for (let i = 0; i < full.length && full[i] === 0; i++) {
    out = '1' + out;
  }
  return out;
}

const BECH32_CHARSET = 'qpzry9x8gf2tvdw0s3jn54khce6mua7l';
const BECH32_CONST = 1;
const BECH32M_CONST = 0x2bc830a3; // BIP350 Bech32m constant for Taproot (witness v1+)

function bech32Polymod(values) {
  const GEN = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3];
  let chk = 1;
  for (const v of values) {
    const top = chk >> 25;
    chk = ((chk & 0x1ffffff) << 5) ^ v;
    for (let i = 0; i < 5; i++) {
      if ((top >> i) & 1) chk ^= GEN[i];
    }
  }
  return chk;
}

function bech32HrpExpand(hrp) {
  const ret = [];
  for (let i = 0; i < hrp.length; i++) ret.push(hrp.charCodeAt(i) >> 5);
  ret.push(0);
  for (let i = 0; i < hrp.length; i++) ret.push(hrp.charCodeAt(i) & 31);
  return ret;
}

function convertBits(data, fromBits, toBits, pad = true) {
  let acc = 0;
  let bits = 0;
  const ret = [];
  const maxv = (1 << toBits) - 1;
  for (const value of data) {
    acc = (acc << fromBits) | value;
    bits += fromBits;
    while (bits >= toBits) {
      bits -= toBits;
      ret.push((acc >> bits) & maxv);
    }
  }
  if (pad) {
    if (bits > 0) ret.push((acc << (toBits - bits)) & maxv);
  } else if (bits >= fromBits || ((acc << (toBits - bits)) & maxv)) {
    throw new Error('Invalid Bech32 bit conversion');
  }
  return ret;
}

function encodeBech32Address(hrp, witnessVersion, witnessProgram) {
  const words = [witnessVersion, ...convertBits(witnessProgram, 8, 5, true)];
  const values = [...bech32HrpExpand(hrp), ...words, 0, 0, 0, 0, 0, 0];
  const specConst = witnessVersion === 0 ? BECH32_CONST : BECH32M_CONST;
  const mod = bech32Polymod(values) ^ specConst;
  const checksum = [];
  for (let p = 0; p < 6; p++) {
    checksum.push((mod >> (5 * (5 - p))) & 31);
  }
  const combined = [...words, ...checksum];
  return hrp + '1' + combined.map((c) => BECH32_CHARSET[c]).join('');
}

function decodeBech32Address(addr) {
  const lower = addr.toLowerCase();
  const pos = lower.lastIndexOf('1');
  if (pos < 1 || pos + 7 > lower.length) throw new Error('Invalid Bech32/Bech32m address');
  const hrp = lower.slice(0, pos);
  const data = [];
  for (let i = pos + 1; i < lower.length; i++) {
    const idx = BECH32_CHARSET.indexOf(lower[i]);
    if (idx === -1) throw new Error('Invalid Bech32 character');
    data.push(idx);
  }
  const words = data.slice(0, -6);
  const witnessVersion = words[0];
  const program = Buffer.from(convertBits(words.slice(1), 5, 8, false));
  return { hrp, witnessVersion, program };
}

function decodeBase58Address(addr) {
  let num = 0n;
  for (const ch of addr) {
    const idx = BASE58_ALPHABET.indexOf(ch);
    if (idx === -1) throw new Error('Invalid Base58 character');
    num = num * 58n + BigInt(idx);
  }
  let hex = num.toString(16);
  if (hex.length % 2 !== 0) hex = '0' + hex;
  let leadingZeros = 0;
  for (const ch of addr) {
    if (ch === '1') leadingZeros++;
    else break;
  }
  const full = Buffer.concat([Buffer.alloc(leadingZeros, 0), Buffer.from(hex, 'hex')]);
  const payload = full.subarray(0, full.length - 4);
  const checksum = full.subarray(full.length - 4);
  if (!hash256(payload).subarray(0, 4).equals(checksum)) {
    throw new Error('Base58Check checksum mismatch');
  }
  return { version: payload[0], hash: payload.subarray(1) };
}

function addressToScriptPubKey(address) {
  const clean = address.trim();
  if (clean.toLowerCase().startsWith('bc1') || clean.toLowerCase().startsWith('tb1')) {
    const { witnessVersion, program } = decodeBech32Address(clean);
    const opVer = witnessVersion === 0 ? 0x00 : 0x50 + witnessVersion;
    return Buffer.concat([Buffer.from([opVer, program.length]), program]);
  }
  const { version, hash } = decodeBase58Address(clean);
  if (version === 0x00 || version === 0x6f) {
    return Buffer.concat([Buffer.from([0x76, 0xa9, 0x14]), hash, Buffer.from([0x88, 0xac])]);
  }
  if (version === 0x05 || version === 0xc4) {
    return Buffer.concat([Buffer.from([0xa9, 0x14]), hash, Buffer.from([0x87])]);
  }
  throw new Error('รูปแบบ Bitcoin Address ไม่ถูกต้องหรือไม่รองรับ');
}

// ============================================================================
// 3. BIP39 Seed & BIP32 / BIP44 / BIP49 / BIP84 / BIP86 HD Key Derivation
// ============================================================================
function mnemonicToSeed(wordsArray, passphrase25 = '') {
  const mnemonicSentence = wordsArray
    .map((w) => w.trim().toLowerCase())
    .join(' ')
    .normalize('NFKD');
  const salt = ('mnemonic' + (passphrase25 || '')).normalize('NFKD');
  return crypto.pbkdf2Sync(
    Buffer.from(mnemonicSentence, 'utf8'),
    Buffer.from(salt, 'utf8'),
    2048,
    64,
    'sha512'
  );
}

function deriveMasterNode(seed64) {
  const I = crypto.createHmac('sha512', Buffer.from('Bitcoin seed', 'utf8')).update(seed64).digest();
  return {
    privateKey: I.subarray(0, 32),
    chainCode: I.subarray(32, 64),
    depth: 0,
    index: 0,
    parentFingerprint: 0,
  };
}

function deriveChildNode(node, index, hardened = false) {
  const idx = hardened ? (index | 0x80000000) >>> 0 : index >>> 0;
  const idxBuf = Buffer.alloc(4);
  idxBuf.writeUInt32BE(idx, 0);

  let data;
  if (hardened) {
    data = Buffer.concat([Buffer.from([0x00]), node.privateKey, idxBuf]);
  } else {
    const pubKey = SECP256K1.getPublicKey(node.privateKey, true);
    data = Buffer.concat([pubKey, idxBuf]);
  }

  const I = crypto.createHmac('sha512', node.chainCode).update(data).digest();
  const IL = SECP256K1.bytesToBigint(I.subarray(0, 32));
  const kPar = SECP256K1.bytesToBigint(node.privateKey);
  const childPrivInt = SECP256K1.mod(IL + kPar, SECP256K1.N);
  if (IL >= SECP256K1.N || childPrivInt === 0n) {
    throw new Error('Invalid BIP32 child key derivation');
  }

  const parentPub = SECP256K1.getPublicKey(node.privateKey, true);
  const fp = hash160(parentPub).readUInt32BE(0);

  return {
    privateKey: SECP256K1.bigintTo32Bytes(childPrivInt),
    chainCode: I.subarray(32, 64),
    depth: node.depth + 1,
    index: idx,
    parentFingerprint: fp,
  };
}

/**
 * Converts a BIP32 receive path (e.g. m/84'/0'/0'/0/0) into the corresponding BIP44/84/86
 * internal change path (e.g. m/84'/0'/0'/1/0) so change is never sent back to the same receiving address.
 */
function toInternalChangePath(pathString = "m/84'/0'/0'/0/0") {
  const clean = String(pathString || "m/84'/0'/0'/0/0")
    .trim()
    .replace(/^m\/?/i, '');
  const parts = clean.split('/').filter(Boolean);
  if (parts.length >= 5) {
    const chgParts = [...parts];
    chgParts[3] = '1'; // internal change chain = 1
    return 'm/' + chgParts.join('/');
  }
  if (parts.length === 3) {
    return 'm/' + parts.join('/') + '/1/0';
  }
  return "m/84'/0'/0'/1/0";
}

function addressForPointAndScript(pt, scriptType) {
  const pubCompressed = SECP256K1.compressPoint(pt);
  const pubKeyHash = hash160(pubCompressed);
  const taprootInfo = SECP256K1.deriveTaprootOutputKeyFromPoint(pt);
  const taprootAddress = encodeBech32Address('bc', 1, taprootInfo.outputPubKeyX);
  const segwitAddress = encodeBech32Address('bc', 0, pubKeyHash);
  const redeemScript = Buffer.concat([Buffer.from([0x00, 0x14]), pubKeyHash]);
  const nestedSegwitAddress = base58CheckEncode(0x05, hash160(redeemScript));
  const legacyAddress = base58CheckEncode(0x00, pubKeyHash);

  let activeAddress = segwitAddress;
  if (scriptType === 'TAPROOT') activeAddress = taprootAddress;
  else if (scriptType === 'NESTED_SEGWIT') activeAddress = nestedSegwitAddress;
  else if (scriptType === 'LEGACY') activeAddress = legacyAddress;

  return {
    activeAddress,
    taprootAddress,
    segwitAddress,
    nestedSegwitAddress,
    legacyAddress,
    publicKeyHex: pubCompressed.toString('hex'),
    pubKeyHashHex: pubKeyHash.toString('hex'),
    taprootOutputPubKeyX: taprootInfo.outputPubKeyX,
  };
}

/**
 * Derives all 4 script type addresses (Taproot bc1p, Native SegWit bc1q, Nested SegWit 3..., Legacy 1...)
 * AND also derives a fresh internal Change Address (`m/.../1/0`) so change never reuses the receiving address!
 */
function derivePath(seed64, pathString = "m/84'/0'/0'/0/0", scriptType = 'NATIVE_SEGWIT') {
  const segments = pathString
    .trim()
    .replace(/^m\/?/i, '')
    .split('/')
    .filter(Boolean);

  const master = deriveMasterNode(seed64);
  const masterPub = SECP256K1.getPublicKey(master.privateKey, true);
  const masterFingerprint = hash160(masterPub).subarray(0, 4).toString('hex');

  let curr = master;
  for (const seg of segments) {
    const hardened = seg.endsWith("'") || seg.toLowerCase().endsWith('h');
    const num = parseInt(seg.replace(/['hH]$/, ''), 10);
    if (Number.isNaN(num) || num < 0) throw new Error(`Invalid BIP32 path segment: ${seg}`);
    curr = deriveChildNode(curr, num, hardened);
  }

  const publicKey = SECP256K1.getPublicKey(curr.privateKey, true);
  const pubKeyHash = hash160(publicKey);

  // 1. Taproot P2TR (bc1p..., Witness v1 Bech32m)
  const taprootInfo = SECP256K1.deriveTaprootOutputKey(curr.privateKey);
  const taprootAddress = encodeBech32Address('bc', 1, taprootInfo.outputPubKeyX);

  // 2. Native SegWit P2WPKH (bc1q..., Witness v0 Bech32)
  const segwitAddress = encodeBech32Address('bc', 0, pubKeyHash);

  // 3. Nested SegWit P2SH-P2WPKH (3..., Base58Check)
  const redeemScript = Buffer.concat([Buffer.from([0x00, 0x14]), pubKeyHash]);
  const nestedSegwitAddress = base58CheckEncode(0x05, hash160(redeemScript));

  // 4. Legacy P2PKH (1..., Base58Check)
  const legacyAddress = base58CheckEncode(0x00, pubKeyHash);

  let activeAddress = segwitAddress;
  if (scriptType === 'TAPROOT') activeAddress = taprootAddress;
  else if (scriptType === 'NESTED_SEGWIT') activeAddress = nestedSegwitAddress;
  else if (scriptType === 'LEGACY') activeAddress = legacyAddress;

  // Derive fresh internal change address (m/.../1/0)
  const changePath = toInternalChangePath(pathString);
  const changeSegs = changePath
    .replace(/^m\/?/i, '')
    .split('/')
    .filter(Boolean);
  let chgNode = master;
  for (const seg of changeSegs) {
    const hardened = seg.endsWith("'") || seg.toLowerCase().endsWith('h');
    const num = parseInt(seg.replace(/['hH]$/, ''), 10);
    chgNode = deriveChildNode(chgNode, num, hardened);
  }
  const chgPt = SECP256K1.decompressPoint(SECP256K1.getPublicKey(chgNode.privateKey, true));
  const changeAddrInfo = addressForPointAndScript(chgPt, scriptType);

  // Build multi-index candidate addresses (Receive 0/0..0/4 & Change 1/0..1/2) for UTXO Gap-Limit Discovery
  const scanAddresses = [{ address: activeAddress, derivationPath: pathString, branch: 'receive', index: 0 }];
  if (segments.length >= 5) {
    const acctPrefixSegs = segments.slice(0, 3);
    let acctNode = master;
    for (const seg of acctPrefixSegs) {
      const hardened = seg.endsWith("'") || seg.toLowerCase().endsWith('h');
      const num = parseInt(seg.replace(/['hH]$/, ''), 10);
      acctNode = deriveChildNode(acctNode, num, hardened);
    }
    const acctPt = SECP256K1.decompressPoint(SECP256K1.getPublicKey(acctNode.privateKey, true));
    const acctPrefixStr = 'm/' + acctPrefixSegs.join('/');
    scanAddresses.length = 0;
    for (let idx = 0; idx < 5; idx++) {
      const childPt = deriveNonHardenedPublicPoint(acctPt, acctNode.chainCode, ['0', String(idx)]).pt;
      const info = addressForPointAndScript(childPt, scriptType);
      scanAddresses.push({
        address: info.activeAddress,
        derivationPath: `${acctPrefixStr}/0/${idx}`,
        branch: 'receive',
        index: idx,
      });
    }
    for (let idx = 0; idx < 3; idx++) {
      const childPt = deriveNonHardenedPublicPoint(acctPt, acctNode.chainCode, ['1', String(idx)]).pt;
      const info = addressForPointAndScript(childPt, scriptType);
      scanAddresses.push({
        address: info.activeAddress,
        derivationPath: `${acctPrefixStr}/1/${idx}`,
        branch: 'change',
        index: idx,
      });
    }
  }

  return {
    path: pathString,
    changePath,
    changeAddress: changeAddrInfo.activeAddress,
    scanAddresses,
    scriptType,
    activeAddress,
    masterFingerprint,
    privateKey: curr.privateKey,
    tweakedPrivateKey: taprootInfo.tweakedPrivateKey,
    taprootOutputPubKeyX: taprootInfo.outputPubKeyX,
    publicKeyHex: publicKey.toString('hex'),
    pubKeyHashHex: pubKeyHash.toString('hex'),
    taprootAddress,
    segwitAddress,
    nestedSegwitAddress,
    legacyAddress,
  };
}

/**
 * Decodes a Base58Check xpub/ypub/zpub/tpub string into { pubKeyBuf (33 bytes), chainCode (32 bytes), parentFingerprint }.
 */
function decodeExtendedPublicKey(xpubStr) {
  const clean = String(xpubStr || '').trim();
  let num = 0n;
  for (const ch of clean) {
    const idx = BASE58_ALPHABET.indexOf(ch);
    if (idx === -1) throw new Error('Invalid Base58 character in xpub');
    num = num * 58n + BigInt(idx);
  }
  let hex = num.toString(16);
  if (hex.length % 2 !== 0) hex = '0' + hex;
  let leadingZeros = 0;
  for (const ch of clean) {
    if (ch === '1') leadingZeros++;
    else break;
  }
  const full = Buffer.concat([Buffer.alloc(leadingZeros, 0), Buffer.from(hex, 'hex')]);
  const payload = full.subarray(0, full.length - 4);
  const checksum = full.subarray(full.length - 4);
  if (!hash256(payload).subarray(0, 4).equals(checksum) || payload.length !== 78) {
    throw new Error('Invalid Extended Public Key (xpub) checksum or length');
  }
  return {
    depth: payload[4],
    parentFingerprint: payload.subarray(5, 9).toString('hex'),
    chainCode: payload.subarray(13, 45),
    pubKeyBuf: payload.subarray(45, 78),
  };
}

function deriveNonHardenedPublicPoint(rootPt, rootChainCode, childSegments) {
  let pt = rootPt;
  let pubCompressed = SECP256K1.compressPoint(pt);
  let chainCode = rootChainCode;
  for (const seg of childSegments) {
    if (seg.endsWith("'") || seg.toLowerCase().endsWith('h')) {
      throw new Error('Public key child derivation only supports non-hardened steps (e.g. 0/0)');
    }
    const idx = parseInt(seg, 10);
    if (Number.isNaN(idx) || idx < 0) throw new Error(`Invalid child segment: ${seg}`);
    const idxBuf = Buffer.alloc(4);
    idxBuf.writeUInt32BE(idx >>> 0, 0);
    const I = crypto.createHmac('sha512', chainCode).update(Buffer.concat([pubCompressed, idxBuf])).digest();
    const IL = SECP256K1.bytesToBigint(I.subarray(0, 32));
    pt = SECP256K1.pointAdd(SECP256K1.pointMultiply(IL), pt);
    pubCompressed = SECP256K1.compressPoint(pt);
    chainCode = I.subarray(32, 64);
  }
  return { pt, pubCompressed, chainCode };
}

/**
 * Derives all 4 Bitcoin Script Addresses (Taproot bc1p, Native SegWit bc1q, Nested SegWit 3..., Legacy 1...)
 * AND a fresh internal Change Address (`m/.../1/0`) + Multi-Index Scan Candidates (`0/0..0/4`, `1/0..1/2`)
 * directly from a Hardware Wallet (Ledger / Trezor) Public Key or Account Xpub WITHOUT needing any Seedphrase!
 */
function deriveFromHardwarePublicKey(params = {}) {
  const {
    pubKeyHex = '',
    chainCodeHex = '',
    xpub = '',
    childPath = '', // e.g., "0/0" when deriving from account xpub
    changePubKeyHex = '', // Optional explicit internal change public key
    scriptType = 'NATIVE_SEGWIT',
    derivationPath = "m/84'/0'/0'/0/0",
    masterFingerprint = 'HARDWARE',
  } = params;

  let rootPt;
  let rootChainCode = chainCodeHex ? Buffer.from(chainCodeHex, 'hex') : null;
  let fp = masterFingerprint;

  if (xpub && String(xpub).trim()) {
    const decoded = decodeExtendedPublicKey(xpub);
    rootPt = SECP256K1.decompressPoint(decoded.pubKeyBuf);
    rootChainCode = decoded.chainCode;
    if (fp === 'HARDWARE') fp = decoded.parentFingerprint;
  } else if (pubKeyHex && String(pubKeyHex).trim()) {
    rootPt = SECP256K1.decompressPoint(Buffer.from(String(pubKeyHex).trim(), 'hex'));
  } else {
    throw new Error('ไม่ได้รับ Public Key หรือ Xpub จากอุปกรณ์ Hardware Wallet');
  }

  const childSegments = String(childPath || '')
    .trim()
    .replace(/^m\/?/i, '')
    .split('/')
    .filter(Boolean);

  let pt = rootPt;
  if (childSegments.length > 0 && rootChainCode && rootChainCode.length === 32) {
    pt = deriveNonHardenedPublicPoint(rootPt, rootChainCode, childSegments).pt;
  }

  const mainInfo = addressForPointAndScript(pt, scriptType);
  const changePath = toInternalChangePath(derivationPath);
  let changeAddress = mainInfo.activeAddress;

  let changeInfo = mainInfo;
  if (changePubKeyHex && String(changePubKeyHex).trim()) {
    const chgPt = SECP256K1.decompressPoint(Buffer.from(String(changePubKeyHex).trim(), 'hex'));
    changeInfo = addressForPointAndScript(chgPt, scriptType);
    changeAddress = changeInfo.activeAddress;
  } else if (childSegments.length > 0 && rootChainCode && rootChainCode.length === 32) {
    // Derive fresh internal change address (1/0) from the same account public key!
    const chgSegments = ['1', childSegments[1] || '0'];
    const chgPt = deriveNonHardenedPublicPoint(rootPt, rootChainCode, chgSegments).pt;
    changeInfo = addressForPointAndScript(chgPt, scriptType);
    changeAddress = changeInfo.activeAddress;
  }

  // Build multi-index candidate addresses (Receive 0/0..0/4 & Change 1/0..1/2) when account chainCode is available
  const scanAddresses = [{ address: mainInfo.activeAddress, derivationPath, branch: 'receive', index: 0, publicKeyHex: mainInfo.publicKeyHex }];
  if (childSegments.length > 0 && rootChainCode && rootChainCode.length === 32) {
    const fullParts = String(derivationPath || "m/84'/0'/0'/0/0")
      .trim()
      .replace(/^m\/?/i, '')
      .split('/')
      .filter(Boolean);
    const acctPrefixStr = fullParts.length >= 3 ? 'm/' + fullParts.slice(0, 3).join('/') : "m/84'/0'/0'";
    scanAddresses.length = 0;
    for (let idx = 0; idx < 5; idx++) {
      const childPt = deriveNonHardenedPublicPoint(rootPt, rootChainCode, ['0', String(idx)]).pt;
      const info = addressForPointAndScript(childPt, scriptType);
      scanAddresses.push({
        address: info.activeAddress,
        derivationPath: `${acctPrefixStr}/0/${idx}`,
        branch: 'receive',
        index: idx,
        publicKeyHex: info.publicKeyHex,
      });
    }
    for (let idx = 0; idx < 3; idx++) {
      const childPt = deriveNonHardenedPublicPoint(rootPt, rootChainCode, ['1', String(idx)]).pt;
      const info = addressForPointAndScript(childPt, scriptType);
      scanAddresses.push({
        address: info.activeAddress,
        derivationPath: `${acctPrefixStr}/1/${idx}`,
        branch: 'change',
        index: idx,
        publicKeyHex: info.publicKeyHex,
      });
    }
  }

  return {
    path: derivationPath,
    changePath,
    changeAddress,
    changePublicKeyHex: changeInfo ? changeInfo.publicKeyHex : '',
    xpub: xpub || '',
    scanAddresses,
    scriptType,
    activeAddress: mainInfo.activeAddress,
    masterFingerprint: fp,
    publicKeyHex: mainInfo.publicKeyHex,
    pubKeyHashHex: mainInfo.pubKeyHashHex,
    taprootAddress: mainInfo.taprootAddress,
    segwitAddress: mainInfo.segwitAddress,
    nestedSegwitAddress: mainInfo.nestedSegwitAddress,
    legacyAddress: mainInfo.legacyAddress,
  };
}

// ============================================================================
// 4. Multi-Script Bitcoin Transaction & PSBT Builder (Seed OR Hardware Wallet)
// ============================================================================
function toSafeSatsBigInt(val) {
  if (typeof val === 'bigint') return val;
  const num = Number(val);
  if (!Number.isFinite(num) || num <= 0) return 0n;
  return BigInt(Math.round(num));
}

function encodeVarInt(n) {
  if (n < 0xfd) return Buffer.from([n]);
  if (n <= 0xffff) {
    const b = Buffer.alloc(3);
    b[0] = 0xfd;
    b.writeUInt16LE(n, 1);
    return b;
  }
  if (n <= 0xffffffff) {
    const b = Buffer.alloc(5);
    b[0] = 0xfe;
    b.writeUInt32LE(n, 1);
    return b;
  }
  const b = Buffer.alloc(9);
  b[0] = 0xff;
  b.writeBigUInt64LE(toSafeSatsBigInt(n), 1);
  return b;
}

function writeUInt64LE(sats) {
  const b = Buffer.alloc(8);
  b.writeBigUInt64LE(toSafeSatsBigInt(sats), 0);
  return b;
}

/**
 * Builds a Bitcoin transaction from selected UTXOs and outputs.
 * - If `signWithSeed === true`, signs with the provided 12..24-word Seed + optional 25th Passphrase.
 * - If `signWithSeed === false` (Hardware Wallet Trezor/Ledger Direct Mode), does NOT require any Seedphrase!
 *   Generates the unsigned transaction & BIP174 PSBT Base64 ready for Hardware Wallet signing.
 */
function buildAndSignBitcoinTransaction(params) {
  const {
    words = [],
    passphrase25 = '',
    scriptType = 'NATIVE_SEGWIT', // 'TAPROOT' | 'NATIVE_SEGWIT' | 'NESTED_SEGWIT' | 'LEGACY'
    derivationPath = "m/84'/0'/0'/0/0",
    senderAddress = '', // Used in Hardware Wallet mode when Seed is not unlocked
    inputs = [],
    outputs = [],
    signWithSeed = true,
  } = params;

  if (!Array.isArray(inputs) || inputs.length === 0) {
    throw new Error('กรุณาเลือกรายการ UTXO ขาเข้าอย่างน้อย 1 รายการ');
  }
  if (!Array.isArray(outputs) || outputs.length === 0) {
    throw new Error('กรุณาระบุปลายทางโอนเหรียญ (Output Address & Amount) อย่างน้อย 1 รายการ');
  }

  let totalIn = 0n;
  const cleanInputs = inputs.map((inp, idx) => {
    const txid = String(inp.txid || '').trim();
    if (!/^[0-9a-fA-F]{64}$/.test(txid)) {
      throw new Error(`UTXO #${idx + 1}: TXID ต้องเป็นเลขฐานสิบหก 64 ตัวอักษร`);
    }
    const vout = Math.round(Number(inp.vout) || 0);
    const amountSats = toSafeSatsBigInt(inp.amountSats);
    if (vout < 0 || amountSats <= 0n) {
      throw new Error(`UTXO #${idx + 1}: vout หรือจำนวน Satoshis ไม่ถูกต้อง`);
    }
    totalIn += amountSats;
    return {
      txid,
      txidLE: Buffer.from(txid, 'hex').reverse(),
      vout,
      amountSats,
      sequence: 0xfffffffd,
    };
  });

  let totalOut = 0n;
  const cleanOutputs = outputs.map((out, idx) => {
    const address = String(out.address || '').trim();
    const amountSats = toSafeSatsBigInt(out.amountSats);
    if (!address || amountSats <= 0n) {
      throw new Error(`Output #${idx + 1}: กรุณาระบุ Address และจำนวน Satoshis ให้ครบถ้วน`);
    }
    const scriptPubKey = addressToScriptPubKey(address);
    totalOut += amountSats;
    return {
      address,
      amountSats,
      scriptPubKey,
    };
  });

  if (totalOut > totalIn) {
    throw new Error(
      `จำนวนเหรียญที่โอนออก (${totalOut} sats) มากกว่ายอดรวม UTXO ที่เลือก (${totalIn} sats)`
    );
  }
  const feeSats = totalIn - totalOut;

  const versionBuf = Buffer.alloc(4);
  versionBuf.writeUInt32LE(2, 0);
  const locktimeBuf = Buffer.alloc(4);
  locktimeBuf.writeUInt32LE(0, 0);

  const txInsNoWitness = cleanInputs.map((inp) => {
    const voutBuf = Buffer.alloc(4);
    voutBuf.writeUInt32LE(inp.vout, 0);
    const seqBuf = Buffer.alloc(4);
    seqBuf.writeUInt32LE(inp.sequence, 0);
    return Buffer.concat([inp.txidLE, voutBuf, Buffer.from([0x00]), seqBuf]);
  });

  const txOutsBufs = cleanOutputs.map((out) =>
    Buffer.concat([
      writeUInt64LE(out.amountSats),
      encodeVarInt(out.scriptPubKey.length),
      out.scriptPubKey,
    ])
  );

  const unsignedTxBuf = Buffer.concat([
    versionBuf,
    encodeVarInt(cleanInputs.length),
    ...txInsNoWitness,
    encodeVarInt(cleanOutputs.length),
    ...txOutsBufs,
    locktimeBuf,
  ]);

  const txid = hash256(unsignedTxBuf).reverse().toString('hex');

  // Determine input scriptPubKey for PSBT Witness UTXO
  let derivedWallet = null;
  let inputScriptPubKey;
  if (signWithSeed) {
    const seed = mnemonicToSeed(words, passphrase25);
    derivedWallet = derivePath(seed, derivationPath, scriptType);
    seed.fill(0);
    inputScriptPubKey = addressToScriptPubKey(derivedWallet.activeAddress);
  } else {
    inputScriptPubKey = senderAddress
      ? addressToScriptPubKey(senderAddress)
      : Buffer.concat([Buffer.from([0x00, 0x14]), Buffer.alloc(20, 0)]);
  }

  // Build BIP174 PSBT (Base64) for Trezor / Ledger / Sparrow / Electrum
  const psbtMagic = Buffer.from([0x70, 0x73, 0x62, 0x74, 0xff]);
  const globalUnsignedEntry = Buffer.concat([
    Buffer.from([0x01, 0x00]),
    encodeVarInt(unsignedTxBuf.length),
    unsignedTxBuf,
    Buffer.from([0x00]),
  ]);

  const psbtInputs = cleanInputs.map((inp) => {
    const witUtxoVal = Buffer.concat([
      writeUInt64LE(inp.amountSats),
      encodeVarInt(inputScriptPubKey.length),
      inputScriptPubKey,
    ]);
    return Buffer.concat([
      Buffer.from([0x01, 0x01]),
      encodeVarInt(witUtxoVal.length),
      witUtxoVal,
      Buffer.from([0x00]),
    ]);
  });

  const psbtOutputs = cleanOutputs.map(() => Buffer.from([0x00]));
  const psbtBuffer = Buffer.concat([psbtMagic, globalUnsignedEntry, ...psbtInputs, ...psbtOutputs]);
  const unsignedPsbtBase64 = psbtBuffer.toString('base64');

  // Hardware Wallet Mode (No Seed Required): Return Unsigned PSBT & TX summary immediately
  if (!signWithSeed) {
    return {
      signed: false,
      mode: 'HARDWARE_WALLET_PSBT',
      scriptType,
      txid,
      vsize: unsignedTxBuf.length + cleanInputs.length * 27,
      feeSats: Number(feeSats),
      totalInSats: Number(totalIn),
      totalOutSats: Number(totalOut),
      unsignedPsbtBase64,
      unsignedTxHex: unsignedTxBuf.toString('hex'),
      signerAddress: senderAddress || '(Hardware Wallet)',
      derivationPath,
      binOutputs: cleanOutputs.map((o) => ({
        address: o.address,
        amountSats: Number(o.amountSats),
        scriptPubKeyHex: o.scriptPubKey.toString('hex'),
        isChange: o.isChange || false,
      })),
      cleanInputs: cleanInputs.map((i) => ({
        txid: i.txid,
        txidLE: i.txidLE.toString('hex'),
        vout: i.vout,
        sequence: i.sequence,
        amountSats: Number(i.amountSats),
        scriptPubKeyHex: inputScriptPubKey ? inputScriptPubKey.toString('hex') : '',
        derivationPath: i.derivationPath || derivationPath,
      })),
    };
  }

  // Seed Signing Mode (Vault Seed or Manual Imported Seed)
  const pubKeyBuf = Buffer.from(derivedWallet.publicKeyHex, 'hex');
  const pubKeyHashBuf = Buffer.from(derivedWallet.pubKeyHashHex, 'hex');

  const prevoutsConcat = Buffer.concat(
    cleanInputs.map((inp) => {
      const v = Buffer.alloc(4);
      v.writeUInt32LE(inp.vout, 0);
      return Buffer.concat([inp.txidLE, v]);
    })
  );
  const hashPrevouts = hash256(prevoutsConcat);

  const sequencesConcat = Buffer.concat(
    cleanInputs.map((inp) => {
      const s = Buffer.alloc(4);
      s.writeUInt32LE(inp.sequence, 0);
      return s;
    })
  );
  const hashSequence = hash256(sequencesConcat);
  const hashOutputs = hash256(Buffer.concat(txOutsBufs));

  const scriptCode = Buffer.concat([
    Buffer.from([0x19, 0x76, 0xa9, 0x14]),
    pubKeyHashBuf,
    Buffer.from([0x88, 0xac]),
  ]);

  const sighashTypeBuf = Buffer.alloc(4);
  sighashTypeBuf.writeUInt32LE(0x01, 0);

  const witnesses = cleanInputs.map((inp) => {
    const voutBuf = Buffer.alloc(4);
    voutBuf.writeUInt32LE(inp.vout, 0);
    const outpoint = Buffer.concat([inp.txidLE, voutBuf]);
    const amountBuf = writeUInt64LE(inp.amountSats);
    const seqBuf = Buffer.alloc(4);
    seqBuf.writeUInt32LE(inp.sequence, 0);

    const preimage = Buffer.concat([
      versionBuf,
      hashPrevouts,
      hashSequence,
      outpoint,
      scriptCode,
      amountBuf,
      seqBuf,
      hashOutputs,
      locktimeBuf,
      sighashTypeBuf,
    ]);

    const sighash = hash256(preimage);

    if (scriptType === 'TAPROOT') {
      const schnorrSig64 = SECP256K1.signSchnorrBIP340(sighash, derivedWallet.tweakedPrivateKey);
      return Buffer.concat([
        Buffer.from([0x01]),
        encodeVarInt(schnorrSig64.length),
        schnorrSig64,
      ]);
    }

    const derSig = SECP256K1.signECDSA(sighash, derivedWallet.privateKey);
    const sigWithHashType = Buffer.concat([derSig, Buffer.from([0x01])]);

    return Buffer.concat([
      Buffer.from([0x02]),
      encodeVarInt(sigWithHashType.length),
      sigWithHashType,
      encodeVarInt(pubKeyBuf.length),
      pubKeyBuf,
    ]);
  });

  derivedWallet.privateKey.fill(0);
  derivedWallet.tweakedPrivateKey.fill(0);

  // Build final tx (include redeemScript in scriptSig if Nested SegWit P2SH-P2WPKH)
  const finalTxIns = cleanInputs.map((inp) => {
    const voutBuf = Buffer.alloc(4);
    voutBuf.writeUInt32LE(inp.vout, 0);
    const seqBuf = Buffer.alloc(4);
    seqBuf.writeUInt32LE(inp.sequence, 0);
    if (scriptType === 'NESTED_SEGWIT') {
      const redeem = Buffer.concat([Buffer.from([0x16, 0x00, 0x14]), pubKeyHashBuf]);
      return Buffer.concat([inp.txidLE, voutBuf, encodeVarInt(redeem.length), redeem, seqBuf]);
    }
    return Buffer.concat([inp.txidLE, voutBuf, Buffer.from([0x00]), seqBuf]);
  });

  const signedSegwitTxBuf = Buffer.concat([
    versionBuf,
    Buffer.from([0x00, 0x01]),
    encodeVarInt(cleanInputs.length),
    ...finalTxIns,
    encodeVarInt(cleanOutputs.length),
    ...txOutsBufs,
    ...witnesses,
    locktimeBuf,
  ]);

  return {
    signed: true,
    scriptType,
    txid,
    vsize: Math.ceil((unsignedTxBuf.length * 3 + signedSegwitTxBuf.length) / 4),
    feeSats: Number(feeSats),
    totalInSats: Number(totalIn),
    totalOutSats: Number(totalOut),
    signedTxHex: signedSegwitTxBuf.toString('hex'),
    unsignedPsbtBase64,
    signerAddress: derivedWallet.activeAddress,
    signerPublicKey: derivedWallet.publicKeyHex,
    masterFingerprint: derivedWallet.masterFingerprint,
    derivationPath,
  };
}

/**
 * Parses a raw Bitcoin transaction hex (SegWit or Legacy) into the exact structure required by
 * `trezor-firmware` (`messages-bitcoin.proto` -> `TransactionType` for `TXMETA` / `prev_tx` verification):
 * { txid, version, lockTime, inputsCount, outputsCount, inputs: [{ prevHashHex, prevIndex, scriptSigHex, sequence }], binOutputs: [{ amountSats, scriptPubKeyHex }] }
 */
function parseRawBitcoinTransaction(rawTxHex) {
  const buf = Buffer.from(String(rawTxHex || '').trim(), 'hex');
  if (buf.length < 10) {
    throw new Error('Raw transaction hex สั้นเกินไปหรือไม่ถูกต้อง');
  }

  let offset = 0;
  function readUInt32() {
    const v = buf.readUInt32LE(offset);
    offset += 4;
    return v;
  }
  function readUInt64() {
    const v = buf.readBigUInt64LE(offset);
    offset += 8;
    return v;
  }
  function readVarInt() {
    const first = buf[offset++];
    if (first < 0xfd) return first;
    if (first === 0xfd) {
      const v = buf.readUInt16LE(offset);
      offset += 2;
      return v;
    }
    if (first === 0xfe) {
      const v = buf.readUInt32LE(offset);
      offset += 4;
      return v;
    }
    const v = Number(buf.readBigUInt64LE(offset));
    offset += 8;
    return v;
  }

  const version = readUInt32();
  let isSegwit = false;
  if (buf[offset] === 0x00 && buf[offset + 1] === 0x01) {
    isSegwit = true;
    offset += 2;
  }

  const inStartOffset = offset;
  const inputsCount = readVarInt();
  const inputs = [];
  for (let i = 0; i < inputsCount; i++) {
    const prevHashLE = buf.subarray(offset, offset + 32);
    const prevHashBE = Buffer.from(prevHashLE).reverse();
    offset += 32;
    const prevIndex = readUInt32();
    const scriptLen = readVarInt();
    const scriptSig = buf.subarray(offset, offset + scriptLen);
    offset += scriptLen;
    const sequence = readUInt32();
    inputs.push({
      prevHashHex: prevHashBE.toString('hex'),
      prevIndex,
      scriptSigHex: scriptSig.toString('hex'),
      sequence,
    });
  }

  const outputsCount = readVarInt();
  const binOutputs = [];
  for (let o = 0; o < outputsCount; o++) {
    const amountSats = readUInt64();
    const spkLen = readVarInt();
    const scriptPubKey = buf.subarray(offset, offset + spkLen);
    offset += spkLen;
    binOutputs.push({
      amountSats: Number(amountSats),
      scriptPubKeyHex: scriptPubKey.toString('hex'),
    });
  }
  const outEndOffset = offset;

  if (isSegwit) {
    for (let i = 0; i < inputsCount; i++) {
      const witCount = readVarInt();
      for (let w = 0; w < witCount; w++) {
        const itemLen = readVarInt();
        offset += itemLen;
      }
    }
  }

  const lockTime = readUInt32();

  // Compute non-witness txid
  const nonWitBuf = Buffer.concat([
    buf.subarray(0, 4),
    buf.subarray(inStartOffset, outEndOffset),
    buf.subarray(offset - 4, offset),
  ]);
  const txid = hash256(nonWitBuf).reverse().toString('hex');

  return {
    txid,
    version,
    lockTime,
    inputsCount,
    outputsCount,
    inputs,
    binOutputs,
  };
}

/**
 * Assembles a broadcast-ready Signed Raw Bitcoin Transaction from inputs, outputs, and hardware wallet signatures
 * Supports: Taproot (BIP86), Native SegWit (BIP84), Nested SegWit (BIP49), and Legacy (BIP44)
 */
function assembleSignedTransaction(params = {}) {
  const {
    scriptType = 'NATIVE_SEGWIT',
    inputs = [],
    outputs = [],
    signatures = [],
    lockTime = 0,
    version = 2,
  } = params;

  if (!inputs.length || !outputs.length || !signatures.length) {
    throw new Error('ข้อมูลสำหรับประกอบธุรกรรมไม่ครบถ้วน (inputs/outputs/signatures)');
  }

  const versionBuf = Buffer.alloc(4);
  versionBuf.writeUInt32LE(version >>> 0, 0);
  const locktimeBuf = Buffer.alloc(4);
  locktimeBuf.writeUInt32LE(lockTime >>> 0, 0);

  const sigMap = {};
  for (const s of signatures) {
    sigMap[Number(s.inputIndex)] = s;
  }

  const cleanInputs = inputs.map((inp) => {
    const txidLE = Buffer.from(inp.txid, 'hex').reverse();
    const vout = Number(inp.vout);
    const sequence = inp.sequence !== undefined ? Number(inp.sequence) : 0xffffffff;
    return { txidLE, vout, sequence, amountSats: Number(inp.amountSats || 0) };
  });

  const txOutsBufs = outputs.map((out) => {
    const spk = out.scriptPubKeyHex
      ? Buffer.from(out.scriptPubKeyHex, 'hex')
      : addressToScriptPubKey(out.address);
    const amountSats = BigInt(Math.round(Number(out.amountSats)));
    return Buffer.concat([
      writeUInt64LE(amountSats),
      encodeVarInt(spk.length),
      spk,
    ]);
  });

  const isSegwit = scriptType === 'NATIVE_SEGWIT' || scriptType === 'NESTED_SEGWIT' || scriptType === 'TAPROOT';

  const witnesses = [];
  const finalTxIns = cleanInputs.map((inp, idx) => {
    const voutBuf = Buffer.alloc(4);
    voutBuf.writeUInt32LE(inp.vout, 0);
    const seqBuf = Buffer.alloc(4);
    seqBuf.writeUInt32LE(inp.sequence, 0);

    const sigObj = sigMap[idx];
    if (!sigObj) {
      throw new Error(`ไม่พบ Signature ของ Input #${idx}`);
    }

    let sigBuf = Buffer.from(sigObj.signatureHex, 'hex');
    let pkBuf = sigObj.pubKeyHex ? Buffer.from(sigObj.pubKeyHex, 'hex') : Buffer.alloc(0);

    if (scriptType === 'TAPROOT') {
      witnesses.push(Buffer.concat([
        Buffer.from([0x01]),
        encodeVarInt(sigBuf.length),
        sigBuf,
      ]));
      return Buffer.concat([inp.txidLE, voutBuf, Buffer.from([0x00]), seqBuf]);
    }

    // Ensure DER signature ends with SIGHASH_ALL (0x01)
    if (sigBuf.length > 0 && sigBuf[0] === 0x30) {
      const derLen = sigBuf[1];
      if (sigBuf.length === derLen + 2) {
        sigBuf = Buffer.concat([sigBuf, Buffer.from([0x01])]);
      }
    }

    if (scriptType === 'NATIVE_SEGWIT') {
      witnesses.push(Buffer.concat([
        Buffer.from([0x02]),
        encodeVarInt(sigBuf.length),
        sigBuf,
        encodeVarInt(pkBuf.length),
        pkBuf,
      ]));
      return Buffer.concat([inp.txidLE, voutBuf, Buffer.from([0x00]), seqBuf]);
    }

    if (scriptType === 'NESTED_SEGWIT') {
      const pkHash = hash160(pkBuf);
      const redeem = Buffer.concat([Buffer.from([0x16, 0x00, 0x14]), pkHash]);
      witnesses.push(Buffer.concat([
        Buffer.from([0x02]),
        encodeVarInt(sigBuf.length),
        sigBuf,
        encodeVarInt(pkBuf.length),
        pkBuf,
      ]));
      return Buffer.concat([inp.txidLE, voutBuf, encodeVarInt(redeem.length), redeem, seqBuf]);
    }

    // Legacy (P2PKH)
    const scriptSig = Buffer.concat([
      encodeVarInt(sigBuf.length),
      sigBuf,
      encodeVarInt(pkBuf.length),
      pkBuf,
    ]);
    return Buffer.concat([inp.txidLE, voutBuf, encodeVarInt(scriptSig.length), scriptSig, seqBuf]);
  });

  let signedTxBuf;
  if (isSegwit) {
    signedTxBuf = Buffer.concat([
      versionBuf,
      Buffer.from([0x00, 0x01]),
      encodeVarInt(cleanInputs.length),
      ...finalTxIns,
      encodeVarInt(txOutsBufs.length),
      ...txOutsBufs,
      ...witnesses,
      locktimeBuf,
    ]);
  } else {
    signedTxBuf = Buffer.concat([
      versionBuf,
      encodeVarInt(cleanInputs.length),
      ...finalTxIns,
      encodeVarInt(txOutsBufs.length),
      ...txOutsBufs,
      locktimeBuf,
    ]);
  }

  const unsignedTxIns = cleanInputs.map((inp) => {
    const voutBuf = Buffer.alloc(4);
    voutBuf.writeUInt32LE(inp.vout, 0);
    const seqBuf = Buffer.alloc(4);
    seqBuf.writeUInt32LE(inp.sequence, 0);
    return Buffer.concat([inp.txidLE, voutBuf, Buffer.from([0x00]), seqBuf]);
  });
  const nonWitnessBuf = Buffer.concat([
    versionBuf,
    encodeVarInt(cleanInputs.length),
    ...unsignedTxIns,
    encodeVarInt(txOutsBufs.length),
    ...txOutsBufs,
    locktimeBuf,
  ]);
  const txid = hash256(nonWitnessBuf).reverse().toString('hex');
  const vsize = isSegwit
    ? Math.ceil((nonWitnessBuf.length * 3 + signedTxBuf.length) / 4)
    : signedTxBuf.length;

  return {
    txid,
    signedTxHex: signedTxBuf.toString('hex'),
    vsize,
  };
}

module.exports = Object.freeze({
  SCRIPT_TYPES,
  SECP256K1,
  mnemonicToSeed,
  derivePath,
  deriveFromHardwarePublicKey,
  buildAndSignBitcoinTransaction,
  parseRawBitcoinTransaction,
  assembleSignedTransaction,
  addressToScriptPubKey,
});

