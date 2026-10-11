// Gram (Telegram Money) wallet vanity search on the Apple GPU (Metal).
// Build: ./build-mac.sh   Run: ./gram-gpu <suffix>
//
// The GPU only reports which candidate matched. The phrase is re-derived and printed by
// ../gram-verify.mjs on the CPU, so a kernel bug can never hand out a wrong phrase.

import Foundation
import Metal
import Security

setvbuf(stdout, nil, _IONBF, 0)

func fail(_ message: String, _ code: Int32 = 1) -> Never {
  FileHandle.standardError.write((message + "\n").data(using: .utf8)!)
  exit(code)
}

let help = """
TON Atelier — Gram (Telegram Money) wallet suffix finder, Apple GPU

Usage:
  gram-gpu <suffix> [options]
  gram-gpu --benchmark <seconds> [options]

Suffix:
  1–8 URL-safe address characters: letters, numbers, _ or -
  Matching is case-insensitive unless -c is given. Wallet: tg · scheme: bip39 · 12 words.

Options:
  -c, --case-sensitive  Match upper/lower case exactly (much slower: ~2x per letter)
  -v, --verbose         Show setup details and one line per GPU batch
  -b, --batch <n>       Candidates per GPU dispatch (default: auto-tuned to ~1s)
      --benchmark <s>   Measure throughput without keeping any wallet
  -h, --help            Show this help

"""

let args = Array(CommandLine.arguments.dropFirst())
let valueOptions: Set<String> = ["-b", "--batch", "--benchmark"]
func option(_ names: String...) -> String? {
  guard let index = args.firstIndex(where: { names.contains($0) }), index + 1 < args.count else { return nil }
  return args[index + 1]
}
if args.contains("-h") || args.contains("--help") || args.isEmpty { print(help, terminator: ""); exit(0) }
let knownOptions = valueOptions.union(["-c", "--case-sensitive", "-v", "--verbose"])
let verbose = args.contains("-v") || args.contains("--verbose")
func vlog(_ message: String) { if verbose { FileHandle.standardError.write("[v] \(message)\n".data(using: .utf8)!) } }
for arg in args where arg.hasPrefix("-") && !knownOptions.contains(arg) {
  fail("Error: unknown option \(arg) (see --help; long options use two dashes, e.g. --benchmark 10).")
}

let benchmarkSeconds = Double(option("--benchmark") ?? "") ?? 0
let benchmark = benchmarkSeconds > 0
var positional: String?
for (index, arg) in args.enumerated() where !arg.hasPrefix("-") {
  if index > 0 && valueOptions.contains(args[index - 1]) { continue }
  positional = arg
  break
}
let exact = args.contains("-c") || args.contains("--case-sensitive")
let suffix = exact ? (positional ?? "") : (positional ?? "").lowercased()
if !benchmark {
  let allowed = Set("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-")
  if suffix.isEmpty || suffix.count > 8 || !suffix.allSatisfy({ allowed.contains($0) }) {
    fail("Error: provide a 1–8 character suffix using letters, numbers, _ or -.")
  }
}
let fixedBatch = option("-b", "--batch").flatMap { Int($0) }
if let fixedBatch, fixedBatch < 1 || fixedBatch > 1 << 24 { fail("Error: batch must be from 1 to 16777216.") }

// --- files next to the binary -------------------------------------------------

let gpuDir = Bundle.main.executableURL!.resolvingSymlinksInPath().deletingLastPathComponent()
let verifyScript = gpuDir.deletingLastPathComponent().appendingPathComponent("gram-verify.mjs")

guard let source = try? String(contentsOf: gpuDir.appendingPathComponent("gram-gpu.metal"), encoding: .utf8) else {
  fail("Cannot read gram-gpu.metal next to the binary (\(gpuDir.path)).")
}
guard let wordText = try? String(contentsOf: gpuDir.appendingPathComponent("gram-gpu-words.txt"), encoding: .utf8) else {
  fail("Cannot read gram-gpu-words.txt next to the binary.")
}
let wordList = wordText.split(separator: "\n").map(String.init)
guard wordList.count == 2048, wordList.allSatisfy({ $0.utf8.count <= 8 }) else { fail("Word list is corrupt.") }
if !benchmark && !FileManager.default.fileExists(atPath: verifyScript.path) {
  fail("Cannot find \(verifyScript.path) (needed to verify matches on the CPU).")
}

/// Pipes one JSON request into gram-verify.mjs; returns node's exit status and what it wrote to stderr.
func runVerifier(_ json: String, captureErrors: Bool = false) -> (status: Int32, errors: String) {
  let process = Process()
  process.executableURL = URL(fileURLWithPath: "/usr/bin/env")
  process.arguments = ["node", verifyScript.path]
  let input = Pipe(), errors = Pipe()
  process.standardInput = input
  if captureErrors { process.standardOutput = FileHandle.nullDevice; process.standardError = errors }
  do { try process.run() } catch { return (127, "\(error)") }
  input.fileHandleForWriting.write((json + "\n").data(using: .utf8)!)
  try? input.fileHandleForWriting.close()
  let text = captureErrors ? String(data: errors.fileHandleForReading.readDataToEndOfFile(), encoding: .utf8) ?? "" : ""
  process.waitUntilExit()
  return (process.terminationStatus, text)
}

// A match is worthless if the CPU verifier cannot run, so prove it works before searching.
if !benchmark {
  let check = runVerifier("{\"selfTest\":true}", captureErrors: true)
  if check.status == 127 {
    fail("Cannot run node (needed to verify matches on the CPU). Install Node.js 20+ and make sure it is on PATH.")
  }
  if check.status != 0 {
    let root = verifyScript.deletingLastPathComponent().path
    fail("CPU verifier self-test failed — are the dependencies installed? Run: cd \"\(root)\" && npm install\n"
         + (check.errors.split(separator: "\n").first { $0.contains("Error") } ?? ""))
  }
  vlog("CPU verifier self-test passed")
}

// --- ed25519 fixed-base table ---------------------------------------------------
// Same arithmetic as the kernel (10 limbs, radix 2^25.5). Entry [i][d] = d * 256^i * B stored as
// (y+x, y-x, 2dxy), so the kernel computes a public key with 32 lookups and no doublings.

typealias Fe = [Int32]

func feAdd(_ a: Fe, _ b: Fe) -> Fe { (0..<10).map { a[$0] &+ b[$0] } }
func feSub(_ a: Fe, _ b: Fe) -> Fe { (0..<10).map { a[$0] &- b[$0] } }

func feMul(_ f: Fe, _ g: Fe) -> Fe {
  var t = [Int64](repeating: 0, count: 10)
  for i in 0..<10 {
    for j in 0..<10 {
      let a = Int64(f[i]) * (i & j & 1 == 1 ? 2 : 1)
      if i + j < 10 { t[i + j] += a * Int64(g[j]) } else { t[i + j - 10] += a * 19 * Int64(g[j]) }
    }
  }
  for i in 0..<10 {
    let bits = Int64(26 - (i & 1))
    let c = (t[i] + (1 << (bits - 1))) >> bits
    t[i] -= c << bits
    if i < 9 { t[i + 1] += c } else { t[0] += 19 * c }
  }
  let c = (t[0] + (1 << 25)) >> 26
  t[0] -= c << 26
  t[1] += c
  return t.map { Int32($0) }
}

func feInv(_ z: Fe) -> Fe {
  var c = z
  for a in stride(from: 253, through: 0, by: -1) {
    c = feMul(c, c)
    if a != 2 && a != 4 { c = feMul(c, z) }
  }
  return c
}

func feToBytes(_ f: Fe) -> [UInt8] {
  var h = f
  var q = (19 * h[9] + (1 << 24)) >> 25
  for i in 0..<10 { q = (h[i] + q) >> Int32(26 - (i & 1)) }
  h[0] += 19 * q
  for i in 0..<10 {
    let bits = Int32(26 - (i & 1))
    let c = h[i] >> bits
    h[i] -= c << bits
    if i < 9 { h[i + 1] += c }
  }
  var out = [UInt8](repeating: 0, count: 32)
  var bit = 0
  for i in 0..<10 {
    for b in 0..<(26 - (i & 1)) {
      out[(bit + b) >> 3] |= UInt8((h[i] >> Int32(b)) & 1) << UInt8((bit + b) & 7)
    }
    bit += 26 - (i & 1)
  }
  return out
}

func feFromBytes(_ s: [UInt8]) -> Fe {
  var out = Fe(repeating: 0, count: 10)
  var bit = 0
  for i in 0..<10 {
    for b in 0..<(26 - (i & 1)) {
      out[i] |= Int32((s[(bit + b) >> 3] >> UInt8((bit + b) & 7)) & 1) << Int32(b)
    }
    bit += 26 - (i & 1)
  }
  return out
}

// 16-bit little-endian limbs (TweetNaCl constants): base point x, y and 2d.
func feFromLimbs16(_ limbs: [UInt16]) -> Fe { feFromBytes(limbs.flatMap { [UInt8($0 & 0xff), UInt8($0 >> 8)] }) }
let edX = feFromLimbs16([0xd51a, 0x8f25, 0x2d60, 0xc956, 0xa7b2, 0x9525, 0xc760, 0x692c, 0xdc5c, 0xfdd6, 0xe231, 0xc0a4, 0x53fe, 0xcd6e, 0x36d3, 0x2169])
let edY = feFromLimbs16([0x6658, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666])
let edD2 = feFromLimbs16([0xf159, 0x26b2, 0x9b94, 0xebd6, 0xb156, 0x8283, 0x149a, 0x00e0, 0xd130, 0xeef3, 0x80f2, 0x198e, 0xfce7, 0x56df, 0xd9dc, 0x2406])

struct EdPoint { var x: Fe, y: Fe, z: Fe, t: Fe }

func edAdd(_ p: EdPoint, _ q: EdPoint) -> EdPoint {
  let a = feMul(feSub(p.y, p.x), feSub(q.y, q.x))
  let b = feMul(feAdd(p.y, p.x), feAdd(q.y, q.x))
  let c = feMul(feMul(p.t, q.t), edD2)
  let zz = feMul(p.z, q.z)
  let d = feAdd(zz, zz)
  let e = feSub(b, a), f = feSub(d, c), g = feAdd(d, c), h = feAdd(b, a)
  return EdPoint(x: feMul(e, f), y: feMul(h, g), z: feMul(g, f), t: feMul(e, h))
}

func buildEdTable() -> [Int32] {
  let one: Fe = [1, 0, 0, 0, 0, 0, 0, 0, 0, 0]
  let zero = Fe(repeating: 0, count: 10)
  // Multiples in projective form first, then one shared inversion (Montgomery's trick) to make them affine.
  var points: [EdPoint] = []
  points.reserveCapacity(32 * 256)
  var base = EdPoint(x: edX, y: edY, z: one, t: feMul(edX, edY))
  for _ in 0..<32 {
    var acc = EdPoint(x: zero, y: one, z: one, t: zero)
    for _ in 0..<256 { points.append(acc); acc = edAdd(acc, base) }
    base = acc
  }
  var prefix: [Fe] = []
  prefix.reserveCapacity(points.count)
  var product = one
  for p in points { prefix.append(product); product = feMul(product, p.z) }
  var inverse = feInv(product)
  var table = [Int32](repeating: 0, count: points.count * 30)
  for n in stride(from: points.count - 1, through: 0, by: -1) {
    let zi = feMul(inverse, prefix[n])
    inverse = feMul(inverse, points[n].z)
    let x = feMul(points[n].x, zi), y = feMul(points[n].y, zi)
    let entry = feFromBytes(feToBytes(feAdd(y, x))) + feFromBytes(feToBytes(feSub(y, x))) + feMul(feMul(x, y), edD2)
    table.replaceSubrange(n * 30..<n * 30 + 30, with: entry)
  }
  return table
}

// --- Metal setup --------------------------------------------------------------

guard let device = MTLCreateSystemDefaultDevice() else { fail("No Metal GPU found.") }
vlog("device: \(device.name) · max threadgroup memory \(device.maxThreadgroupMemoryLength) B")
let compileStart = Date()
let library: MTLLibrary
do { library = try device.makeLibrary(source: source, options: MTLCompileOptions()) } catch {
  fail("Metal kernel failed to compile:\n\(error)")
}
vlog(String(format: "kernel compiled in %.2fs", Date().timeIntervalSince(compileStart)))
guard let function = library.makeFunction(name: "search") else { fail("Kernel function 'search' missing.") }
let pipeline: MTLComputePipelineState
do { pipeline = try device.makeComputePipelineState(function: function) } catch { fail("Pipeline error: \(error)") }
guard let queue = device.makeCommandQueue() else { fail("Cannot create Metal command queue.") }

var wordBytes = [UInt8](repeating: 0, count: 2048 * 8)
var wordLens = [UInt8](repeating: 0, count: 2048)
for (i, word) in wordList.enumerated() {
  for (j, byte) in word.utf8.enumerated() { wordBytes[i * 8 + j] = byte }
  wordLens[i] = UInt8(word.utf8.count)
}
let wordsBuffer = device.makeBuffer(bytes: wordBytes, length: wordBytes.count, options: .storageModeShared)!
let lensBuffer = device.makeBuffer(bytes: wordLens, length: wordLens.count, options: .storageModeShared)!
let foundBuffer = device.makeBuffer(length: 8, options: .storageModeShared)!
let tableStart = Date()
let edTable = buildEdTable()
let edBuffer = device.makeBuffer(bytes: edTable, length: edTable.count * 4, options: .storageModeShared)!
vlog(String(format: "ed25519 table: %d KB built in %.2fs", edTable.count * 4 / 1024, Date().timeIntervalSince(tableStart)))
let found = foundBuffer.contents().bindMemory(to: UInt32.self, capacity: 2)
let threadsPerGroup = min(pipeline.maxTotalThreadsPerThreadgroup, 64)

// Params layout must match the kernel: uint base[4] (LE limbs, limb 0 lowest) | uchar suffix[8] | uint suffixLen | uint exact
func params(base: [UInt8], suffix: String, exact: Bool) -> [UInt8] {
  var out = [UInt8](repeating: 0, count: 32)
  for limb in 0..<4 {
    for k in 0..<4 { out[limb * 4 + k] = base[15 - (limb * 4 + k)] }
  }
  let chars = Array(suffix.utf8)
  for (i, c) in chars.enumerated() { out[16 + 8 - chars.count + i] = c }
  out[24] = UInt8(chars.count)
  out[28] = exact ? 1 : 0
  return out
}

// entropy = base + gid mod 2^128, big-endian (same as the kernel)
func entropy(base: [UInt8], plus gid: UInt32) -> [UInt8] {
  var out = base
  var carry = UInt64(gid)
  var i = 15
  while i >= 0 && carry > 0 {
    let sum = UInt64(out[i]) + (carry & 0xff)
    out[i] = UInt8(sum & 0xff)
    carry = (carry >> 8) + (sum >> 8)
    i -= 1
  }
  return out
}

/// Runs one dispatch; returns the matching thread index, if any.
func dispatch(base: [UInt8], suffix: String, exact: Bool = false, count: Int) -> UInt32? {
  found[0] = 0
  found[1] = 0
  var p = params(base: base, suffix: suffix, exact: exact)
  guard let commands = queue.makeCommandBuffer(), let encoder = commands.makeComputeCommandEncoder() else {
    fail("Cannot create Metal command buffer.")
  }
  encoder.setComputePipelineState(pipeline)
  encoder.setBuffer(wordsBuffer, offset: 0, index: 0)
  encoder.setBuffer(lensBuffer, offset: 0, index: 1)
  encoder.setBytes(&p, length: p.count, index: 2)
  encoder.setBuffer(foundBuffer, offset: 0, index: 3)
  encoder.setBuffer(edBuffer, offset: 0, index: 4)
  encoder.dispatchThreads(MTLSize(width: count, height: 1, depth: 1),
                          threadsPerThreadgroup: MTLSize(width: threadsPerGroup, height: 1, depth: 1))
  encoder.endEncoding()
  commands.commit()
  commands.waitUntilCompleted()
  if commands.status == .error { fail("GPU error: \(commands.error.map { "\($0)" } ?? "unknown")", 2) }
  return found[0] > 0 ? found[1] : nil
}

// --- self-test: known vectors computed by the CPU implementation ----------------
// base 0, thread 42  -> UQD4xIMcfWMPvlfpWvr9AHgRE-Q7fKRt7wOjGdxccq0itvCa
// base 2^128-1, t 0  -> UQAWOlfZ2bT3BTNKGuXa_yuHxh3nB0qyiX0Q5k7MzPAVnCgX

let zero = [UInt8](repeating: 0, count: 16)
let ones = [UInt8](repeating: 0xff, count: 16)
let selfTestStart = Date()
let t1 = dispatch(base: zero, suffix: "q0itvca", count: 64)
let t2 = dispatch(base: ones, suffix: "zpavncgx", count: 1)
let t3 = dispatch(base: zero, suffix: "q0itvCa", exact: true, count: 64)
let t4 = dispatch(base: zero, suffix: "q0itvca", exact: true, count: 64)
guard t1 == 42, t2 == 0, t3 == 42, t4 == nil else {
  fail("GPU self-test FAILED (got \(t1.map(String.init) ?? "none"), \(t2.map(String.init) ?? "none"), \(t3.map(String.init) ?? "none"), \(t4.map(String.init) ?? "none")). Not searching; please report this.", 2)
}

vlog(String(format: "self-test: %@, %@, %@, %@ (expected 42, 0, 42, none) in %.2fs · threads/group %d",
           t1.map(String.init) ?? "none", t2.map(String.init) ?? "none", t3.map(String.init) ?? "none",
           t4.map(String.init) ?? "none", Date().timeIntervalSince(selfTestStart), threadsPerGroup))

// --- search loop ---------------------------------------------------------------

func randomBase() -> [UInt8] {
  var bytes = [UInt8](repeating: 0, count: 16)
  guard SecRandomCopyBytes(kSecRandomDefault, bytes.count, &bytes) == errSecSuccess else { fail("System RNG failed.") }
  return bytes
}

func candidateJSON(_ candidate: [UInt8], attempts: Int, seconds: Double) -> String {
  let hex = candidate.map { String(format: "%02x", $0) }.joined()
  return "{\"entropy\":\"\(hex)\",\"suffix\":\"\(suffix)\",\"exact\":\(exact),\"attempts\":\(attempts),\"seconds\":\(seconds)}"
}

FileHandle.standardError.write("GPU: \(device.name) · self-test passed\n".data(using: .utf8)!)

var batch = fixedBatch ?? 4096
var attempts = 0
let started = Date()
var lastProgress = Date.distantPast
var batchNumber = 0
// Average attempts for a match: 1/32 per letter (1/64 with -c), 1/64 per digit, _ or -.
let expected = suffix.reduce(1.0) { total, c in total * (c.isLetter && !exact ? 32 : 64) }
if !benchmark {
  vlog(String(format: "suffix \"%@\" · case-sensitive: %@ · ~%.0f attempts on average", suffix, exact ? "yes" : "no", expected))
}

while true {
  let base = randomBase()
  let batchStart = Date()
  let hit = dispatch(base: base, suffix: benchmark ? "" : suffix, exact: exact, count: batch)
  let took = Date().timeIntervalSince(batchStart)
  let seconds = Date().timeIntervalSince(started)
  batchNumber += 1

  if let gid = hit {
    attempts += Int(gid) + 1
    vlog("batch #\(batchNumber): match at thread \(gid) — verifying on the CPU")
    FileHandle.standardError.write("\r\u{1B}[K".data(using: .utf8)!)
    let json = candidateJSON(entropy(base: base, plus: gid), attempts: attempts, seconds: seconds)
    let status = runVerifier(json).status
    if status == 0 { exit(0) }
    if status == 2 { fail("GPU match failed CPU verification — kernel bug; nothing was kept. Please report this.", 2) }
    // node itself broke after passing the start-up check: hand the candidate over instead of losing it.
    print("\nThe CPU verifier could not run (node exit status \(status)), so this match is UNVERIFIED.")
    print("The line below is the wallet secret — keep it private. Once node works again, verify it with:")
    print("  node \"\(verifyScript.path)\"   (paste the line, then press Ctrl-D)\n")
    print(json)
    exit(3)
  }
  attempts += batch
  if verbose {
    let progress = benchmark ? "" : String(format: " · %.0f%% of average", 100 * Double(attempts) / expected)
    vlog(String(format: "batch #%d: %d in %.3fs (%.0f/sec) · total %d · avg %.1f/sec%@", batchNumber, batch, took,
               Double(batch) / took, attempts, Double(attempts) / seconds, progress))
  }

  if benchmark && seconds >= benchmarkSeconds {
    FileHandle.standardError.write("\r\u{1B}[K".data(using: .utf8)!)
    print(String(format: "Benchmark: %d wallets in %.2fs · %.1f/sec on %@ (batch %d)", attempts, seconds,
                 Double(attempts) / seconds, device.name, batch))
    exit(0)
  }
  if fixedBatch == nil && took < 0.5 && batch < 1 << 22 { batch *= 2 }
  if !verbose && Date().timeIntervalSince(lastProgress) > 0.25 {
    lastProgress = Date()
    let line = String(format: "%d attempts · %.1f/sec · batch %d", attempts, Double(attempts) / max(seconds, 0.01), batch)
    FileHandle.standardError.write("\r\(line)\u{1B}[K".data(using: .utf8)!)
  }
}
