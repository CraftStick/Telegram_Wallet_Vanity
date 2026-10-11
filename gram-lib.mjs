// Address + key derivation for Telegram's Gram ("Money") wallet: the WalletTg trampoline contract.
// Source: https://github.com/ton-blockchain/tg-wallet-contract (contracts/WalletTrampoline.boc, storage.tolk)
import { createHash, pbkdf2Sync, randomBytes } from 'node:crypto';
import { beginCell, Cell, contractAddress } from '@ton/core';
import { WalletContractV4, WalletContractV5R1 } from '@ton/ton';
import {
  deriveEd25519Path, keyPairFromSeed, mnemonicNew, mnemonicToPrivateKey, mnemonicWordList,
} from '@ton/crypto';

// Immutable trampoline every Gram wallet stores as its code: JMP to config[-123].
const TRAMPOLINE = Cell.fromBoc(Buffer.from(
  'b5ee9c7241010101001a000030ff00209821d7498308b9f240df8085f833d0ed1e20ed53d969427e39', 'hex'))[0];
export const TRAMPOLINE_CODE_HASH = TRAMPOLINE.hash().toString('hex');

export const MAINNET_SUBWALLET_ID = 0x7fff7f11;

// struct (0x00) Storage { seqno: uint32, subwalletId: uint32, publicKey: uint256 }
export function gramAddress(publicKey, subwalletId = MAINNET_SUBWALLET_ID) {
  const data = beginCell()
    .storeUint(0, 8)
    .storeUint(0, 32)
    .storeUint(subwalletId, 32)
    .storeBuffer(publicKey, 32)
    .endCell();
  return contractAddress(0, { code: TRAMPOLINE, data });
}

// Wallet contracts a phrase can be searched against: Telegram's, or the traditional ones other apps show.
export const WALLETS = {
  tg: (publicKey) => gramAddress(publicKey),
  v5r1: (publicKey) => WalletContractV5R1.create({ workchain: 0, publicKey }).address,
  v4r2: (publicKey) => WalletContractV4.create({ workchain: 0, publicKey }).address,
};

export const friendly = (address, bounceable = false) =>
  address.toString({ bounceable, testOnly: false, urlSafe: true });

// --- key schemes -------------------------------------------------------------

const words = mnemonicWordList; // standard BIP39 English list, same one TON uses

// 16 bytes of entropy -> 12 BIP39 words (4-bit sha256 checksum).
export function entropyToWords(entropy) {
  const checksum = createHash('sha256').update(entropy).digest()[0] >> 4;
  let bits = BigInt('0x' + Buffer.from(entropy).toString('hex')) << 4n | BigInt(checksum);
  const out = new Array(12);
  for (let i = 11; i >= 0; i -= 1) { out[i] = words[Number(bits & 2047n)]; bits >>= 11n; }
  return out;
}

function bip39New12() {
  const entropy = randomBytes(16);
  const out = entropyToWords(entropy);
  entropy.fill(0);
  return out;
}

export async function bip39Key(mnemonic, account = 0) {
  const seed = pbkdf2Sync(mnemonic.join(' ').normalize('NFKD'), 'mnemonic', 2048, 64, 'sha512');
  const child = await deriveEd25519Path(seed, [44, 607, account]);
  seed.fill(0);
  return keyPairFromSeed(child);
}

export const SCHEMES = {
  // TON-native mnemonic (what Tonkeeper/@ton/crypto use for 24 words; works for 12 too)
  ton: { generate: (count = 12) => mnemonicNew(count), key: (m) => mnemonicToPrivateKey(m) },
  // BIP39 + SLIP-0010 m/44'/607'/0' (Ledger / multichain-style TON derivation)
  bip39: { generate: async (count = 12) => { if (count !== 12) throw new Error('bip39 scheme supports 12 words only'); return bip39New12(); }, key: (m) => bip39Key(m, 0) },
};
