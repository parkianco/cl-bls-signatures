# cl-bls-signatures

Pure Common Lisp implementation of BLS (Boneh-Lynn-Shacham) aggregate signatures using the BLS12-381 curve.

## Features

- **BLS12-381 Signatures**: Generate, sign, and verify BLS signatures
- **Signature Aggregation**: Combine N signatures into a single 48-byte signature
- **Public Key Aggregation**: Combine multiple public keys for efficient verification
- **Batch Verification**: Verify multiple signatures faster than individual checks
- **Threshold Signatures**: t-of-n threshold signing with Shamir secret sharing
- **Proof of Possession**: Prevent rogue key attacks with PoP
- **Safe Aggregation**: Coefficient-weighted aggregation for untrusted keys
- **Zero Dependencies**: Pure Common Lisp, no external libraries required

## Installation

Clone this repository and load the system:

```lisp
(asdf:load-system :cl-bls-signatures)
```

## Quick Start

```lisp
(use-package :cl-bls-signatures)

;; Generate a keypair
(defvar *keypair* (bls-keygen))

;; Sign a message
(defvar *message* (string-to-octets "Hello, BLS!"))
(defvar *signature* (bls-sign *keypair* *message*))

;; Verify the signature
(bls-verify (bls-keypair-public *keypair*) *message* *signature*)
;; => T
```

## API Reference

### Key Generation

```lisp
;; Random keypair generation
(bls-keygen) ; => bls-keypair

;; Deterministic keypair from seed
(bls-keygen-deterministic seed &optional info) ; => bls-keypair

;; Derive public key from secret key
(bls-derive-public secret-key) ; => 96-byte vector
```

### Signing

```lisp
;; Sign with default DST
(bls-sign keypair message) ; => bls-signature

;; Sign with custom domain separation tag
(bls-sign-with-dst keypair message dst) ; => bls-signature
```

### Verification

```lisp
;; Verify signature
(bls-verify public-key message signature) ; => T or NIL

;; Verify with custom DST
(bls-verify-with-dst public-key message signature dst) ; => T or NIL
```

### Aggregation

```lisp
;; Aggregate multiple signatures
(bls-aggregate-signatures signatures) ; => bls-aggregate-sig

;; Aggregate public keys
(bls-aggregate-public-keys public-keys) ; => 96-byte vector

;; Verify aggregate signature
(bls-verify-aggregate public-keys message aggregate-sig) ; => T or NIL

;; Batch verify multiple (pk, msg, sig) tuples
(bls-batch-verify verification-tuples) ; => T or NIL

;; Batch verify same message with different signers
(bls-batch-verify-same-message public-keys message signatures) ; => T or NIL
```

### Proof of Possession

```lisp
;; Generate PoP
(bls-pop-prove keypair) ; => bls-pop

;; Verify PoP
(bls-pop-verify pop) ; => T or NIL

;; Safe aggregation with PoP verification
(bls-aggregate-with-pop keypairs-with-pops) ; => aggregated public key
```

### Threshold Signatures

```lisp
;; Generate key shares for t-of-n scheme
(bls-threshold-keygen n threshold)
;; => (values shares master-public-key verification-vector)

;; Create partial signature
(bls-threshold-sign share message)
;; => (values partial-signature index)

;; Combine partial signatures
(bls-threshold-combine partial-signatures indices threshold)
;; => bls-signature

;; Verify threshold signature
(bls-threshold-verify master-public-key message signature)
;; => T or NIL
```

### Rogue Key Protection

```lisp
;; Derive aggregation coefficients
(bls-derive-coefficients public-keys) ; => list of coefficients

;; Safe aggregate without PoP
(bls-safe-aggregate public-keys signatures) ; => bls-aggregate-sig
```

## Running Tests

```lisp
(asdf:test-system :cl-bls-signatures)
```

## Standards Compliance

This implementation follows:
- IETF draft-irtf-cfrg-bls-signature-05
- IETF draft-irtf-cfrg-hash-to-curve-16
- Ethereum 2.0 BLS specification

## Security Properties

- 128-bit security level (BLS12-381)
- Deterministic signatures (no nonce vulnerabilities)
- Rogue key attack prevention via PoP or coefficient weighting
- Constant-time comparison for side-channel resistance

## License

MIT License. See LICENSE file.
