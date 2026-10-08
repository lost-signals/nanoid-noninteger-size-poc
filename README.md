# nanoid: predictable IDs for non-integer size (5.1.8 - 5.1.16)

Proof of concept for a flaw in [nanoid](https://github.com/ai/nanoid) where `customAlphabet()` / `customRandom()` return a fully predictable string when the generator is called with a non-integer size.

| | |
|---|---|
| Package | `nanoid` (npm) |
| Affected | 5.1.8 through 5.1.16 |
| Fixed | 6.0.0 ([ai/nanoid#616](https://github.com/ai/nanoid/pull/616)) |
| Builds | Node.js (`index.js`) and browser (`index.browser.js`) |
| Weakness | CWE-330: Use of Insufficiently Random Values |
| CVE | Requested from MITRE CNA-LR (pending) |
| Reported by | Nufyl H. ([@lost-signals](https://github.com/lost-signals)) |

## Summary

On affected versions, calling a `customAlphabet()` generator with a non-integer size and an alphabet whose length is a power of two returns a string made entirely of the alphabet's first character:

```js
import { customAlphabet } from 'nanoid'

const gen = customAlphabet('0123456789abcdef')
gen(16.5) // '00000000000000000' on every call
gen(16)   // '96db4d56943867b3' (normal)
```

Any identifier generated this way (session token, invite code, reset link, object ID) is identical across calls and trivially guessable.

## Root cause

`customRandom()` uses `size` directly as the loop counter:

```js
let bytes = getRandom(size)
let i = size            // 16.5
while (i--) {           // 15.5, 14.5, ... 0.5, -0.5
  id += alphabet[bytes[i] & mask]
  ...
}
```

Every index `i` is fractional, so `bytes[i]` is `undefined` on the typed array. `undefined & mask` evaluates to `0`, so every character is `alphabet[0]`. With a power-of-two alphabet, every lookup passes the bounds check and the loop runs until the output length reaches `size`.

The fix truncates the size first:

```js
let i = (size |= 0)
```

## Conditions

- The generator receives a non-integer size, for example from user input, a config value, or floating-point arithmetic such as `Math.log(...) * k` or `len / 2`.
- The alphabet length is a power of two (2, 4, 8, 16, 32, 64, ...). Hex and URL-safe base64 alphabets both qualify.

Integer sizes are not affected.

## Reproduce

### Node.js

```bash
npm install
npm run poc
```

Expected output (abridged):

```
nanoid 5.1.7
  customAlphabet(...)(16.5)       -> ca385c2cc1b59db5c
  unique IDs in 1000 calls         -> 1000
  result                           -> not affected

nanoid 5.1.8
  customAlphabet(...)(16.5)       -> 00000000000000000
  unique IDs in 1000 calls         -> 1
  result                           -> VULNERABLE (fully predictable output)

nanoid 5.1.16
  customAlphabet(...)(16.5)       -> 00000000000000000
  unique IDs in 1000 calls         -> 1
  result                           -> VULNERABLE (fully predictable output)

nanoid 6.0.0
  customAlphabet(...)(16.5)       -> aa1aa85be4caa851
  unique IDs in 1000 calls         -> 1000
  result                           -> not affected
```

The script exits with code 1 if any tested version is vulnerable.

### Browser

Open `poc.html` in a browser served over HTTP (for example `npx serve .`). It loads the browser build of each version from esm.sh and shows the same comparison as a table.

## Remediation

- Upgrade to nanoid 6.0.0 or later. There is no patched 5.x release.
- If you cannot upgrade, make sure the size is an integer before calling the generator (`gen(Math.floor(size))` or `gen(size | 0)`).

## Timeline

| Date | Event |
|---|---|
| 2026-10 | Reported to the maintainer |
| 2026-10-05 | Fix merged as [ai/nanoid#616](https://github.com/ai/nanoid/pull/616) |
| 2026-10-08 | CVE requested from MITRE CNA-LR |

## Related

- CVE-2024-55565: earlier nanoid issue with non-integer values, fixed in 3.3.8 and 5.0.9.
