#!/usr/bin/env node
// Re-derives a GPU candidate on the CPU (reads {"entropy","suffix","attempts","seconds"} JSON on stdin).
// Prints the wallet only if the independent derivation reproduces an address with the suffix.
// Exit status: 0 verified, 2 the derivation does not match; anything else means node could not run it.
import { bip39Key, entropyToWords, friendly, gramAddress } from './gram-lib.mjs';

let input = '';
for await (const chunk of process.stdin) input += chunk;
const request = JSON.parse(input);
input = '';

// {"selfTest":true}: derive a known vector (entropy 0x…2a, the one the GPU self-test uses) and exit 0 if
// node and the dependencies reproduce it. gram-gpu runs this before searching.
if (request.selfTest) {
  const known = await bip39Key(entropyToWords(Buffer.from('0000000000000000000000000000002a', 'hex')));
  process.exit(friendly(gramAddress(known.publicKey)) === 'UQD4xIMcfWMPvlfpWvr9AHgRE-Q7fKRt7wOjGdxccq0itvCa' ? 0 : 2);
}

const { entropy, suffix, exact = false, attempts = 0, seconds = 0 } = request;

const bytes = Buffer.from(entropy, 'hex');
if (bytes.length !== 16) { process.stderr.write('Verification failed: bad entropy length.\n'); process.exit(2); }
const mnemonic = entropyToWords(bytes);
bytes.fill(0);
const keyPair = await bip39Key(mnemonic);
keyPair.secretKey.fill(0);
const wallet = gramAddress(keyPair.publicKey);
const address = friendly(wallet);
const matches = exact ? address.endsWith(String(suffix)) : address.toLowerCase().endsWith(String(suffix).toLowerCase());
if (!matches) {
  mnemonic.fill('');
  process.stderr.write(`Verification failed: CPU derived ${address}, which does not end with "${suffix}". Nothing was kept.\n`);
  process.exit(2);
}

process.stdout.write(`\nMATCH FOUND (GPU, verified on CPU)\n\n`);
process.stdout.write(`Safe receive (UQ): ${address}\n`);
process.stdout.write(`Bounceable  (EQ): ${friendly(wallet, true)}\n`);
process.stdout.write(`Wallet: tg · scheme: bip39 · 12 words\n`);
process.stdout.write(`Attempts: ${Number(attempts).toLocaleString()} in ${Number(seconds).toFixed(1)}s (${(attempts / Math.max(seconds, 0.01)).toFixed(1)}/sec)\n\n`);
process.stdout.write('RECOVERY PHRASE — keep offline; anyone with these words controls the wallet\n\n');
process.stdout.write(`${mnemonic.join(' ')}\n`);
process.stdout.write('\nImport it into Telegram and confirm the address matches before funding it.\n');
mnemonic.fill('');
