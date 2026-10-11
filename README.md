# Telegram Wallet Vanity

Finds a Telegram Wallet (Gram / "Money") address that ends with the text you choose, using the Apple GPU.

```
$ ./gpu/gram-gpu goog
GPU: Apple M2 · self-test passed

MATCH FOUND (GPU, verified on CPU)

Safe receive (UQ): UQAS0mLArGMoI0qVrDL1gvEFpRMvGMBlpKxHR5X1URerGOoG
Wallet: tg · scheme: bip39 · 12 words
Attempts: 1,272,971 in 94.3s (13503.4/sec)
```

Unofficial project, not affiliated with Telegram or the TON Foundation.

## Requirements

- A Mac with a Metal GPU (developed and measured on an Apple M2)
- Xcode Command Line Tools: `xcode-select --install`
- Node.js 20 or newer

## Build

```sh
./gpu/build-mac.sh
```

This installs the Node dependencies, compiles `gpu/gram-gpu` and runs a 5-second benchmark.

## Use

```sh
./gpu/gram-gpu <suffix>
```

The suffix is 1–8 address characters: letters, digits, `_` or `-`. Matching ignores case unless you pass `-c`.

| Option | Meaning |
|---|---|
| `-c`, `--case-sensitive` | Match upper/lower case exactly (about 2x slower per letter) |
| `-v`, `--verbose` | Show setup details and one line per GPU batch |
| `-b`, `--batch <n>` | Candidates per GPU dispatch (default: auto-tuned) |
| `--benchmark <s>` | Measure speed for `<s>` seconds without keeping any wallet |

On long searches, keep the Mac awake: `caffeinate -i ./gpu/gram-gpu <suffix>`.

## How long it takes

Each letter multiplies the work by 32 (64 with `-c`); each digit, `_` or `-` by 64.
At about 13,500 wallets per second (Apple M2):

| Letters | Average attempts | Average time |
|---|---|---|
| 1–2 | up to ~1 thousand | instant |
| 3 | ~33 thousand | ~3 seconds |
| 4 | ~1 million | ~1.5 minutes |
| 5 | ~34 million | ~40 minutes |
| 6 | ~1.07 billion | ~22 hours |
| 7 | ~34 billion | ~4 weeks |

The search is random, so these are averages: half of all runs finish in about 70% of that time, and one in twenty
takes three times longer. Stopping and restarting loses nothing.

Only the non-bounceable address (`UQ…`) carries the suffix. The bounceable form (`EQ…`) of the same wallet ends
differently.

## Keeping the wallet safe

- The recovery phrase is printed once, in the terminal, and is never written to disk. Write the 12 words down
  before you close the window.
- Anyone who sees the phrase controls the wallet. Do not paste it into chats, notes or screenshots.
- Import the phrase into Telegram and check that the address matches before you send anything to it.
- Run the search on a machine you trust.

## How it works

For every candidate the GPU kernel (`gpu/gram-gpu.metal`) runs the full derivation:

1. 128 bits of entropy → 12-word BIP39 phrase
2. PBKDF2-HMAC-SHA512, 2048 rounds → seed
3. SLIP-0010 ed25519, path `m/44'/607'/0'` → private key
4. ed25519 public key (fixed-base table, 32 lookups)
5. Wallet state hash for the [tg-wallet-contract](https://github.com/ton-blockchain/tg-wallet-contract)
   trampoline → address → suffix check

The entropy base comes from the system random generator and is fresh for every batch.

The GPU only reports which candidate matched. `gram-verify.mjs` then derives the wallet again on the CPU with
`@ton/crypto` and `@ton/ton`, and the phrase is printed only if that independent result has the suffix. The
program also checks itself at start-up: the GPU kernel against known addresses, and the CPU verifier against a
known vector, so a broken setup stops before the search rather than after it.

## Files

| File | Role |
|---|---|
| `gpu/gram-gpu.swift` | Host program: options, Metal setup, search loop |
| `gpu/gram-gpu.metal` | GPU kernel |
| `gpu/gram-gpu-words.txt` | BIP39 English word list |
| `gram-verify.mjs` | CPU verification and output of a match |
| `gram-lib.mjs` | Address and key derivation used by the verifier |
