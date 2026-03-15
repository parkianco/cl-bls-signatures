;;;; Copyright (c) 2024-2026 Parkian Company LLC. All rights reserved.
;;;; SPDX-License-Identifier: Apache-2.0

;;;; src/package.lisp
;;;; Package definitions for cl-bls-signatures

(in-package #:cl-user)

(defpackage #:cl-bls-signatures.util
  (:use #:cl)
  (:export
   ;; Byte utilities
   #:string-to-octets
   #:octets-to-string
   #:bytes-to-integer
   #:integer-to-bytes
   #:constant-time-bytes=
   ;; Cryptographic primitives
   #:sha256
   #:hmac-sha256
   #:get-random-bytes
   #:mod-expt))

(defpackage #:cl-bls-signatures.curve
  (:use #:cl #:cl-bls-signatures.util)
  (:export
   ;; Constants
   #:+bls-curve-order+
   #:+bls-field-modulus+
   #:+bls-g1-cofactor+
   #:+bls-dst-sign+
   #:+bls-dst-pop+
   ;; Field arithmetic
   #:bls-mod-r
   #:bls-mod-q
   #:bls-mod-inverse
   #:bls-bytes-to-scalar
   #:bls-scalar-to-bytes
   ;; Curve operations
   #:bls-hash-to-g1
   #:bls-expand-message-xmd
   #:bls-derive-public-internal
   #:bls-g1-scalar-mul-sim
   #:bls-g1-add-inplace
   #:bls-g2-add-inplace
   #:make-g1-identity))

(defpackage #:cl-bls-signatures.core
  (:use #:cl #:cl-bls-signatures.util #:cl-bls-signatures.curve)
  (:export
   ;; Re-export constants
   #:+bls-curve-order+
   #:+bls-field-modulus+
   #:+bls-dst-sign+
   #:+bls-dst-pop+

   ;; Re-export util functions
   #:string-to-octets
   #:octets-to-string
   #:bytes-to-integer
   #:integer-to-bytes
   #:sha256
   #:hmac-sha256
   #:constant-time-bytes=

   ;; Types
   #:bls-keypair
   #:bls-keypair-p
   #:bls-keypair-secret
   #:bls-keypair-public
   #:bls-keypair-pop
   #:bls-signature
   #:bls-signature-p
   #:bls-signature-point
   #:bls-signature-dst
   #:bls-aggregate-sig
   #:bls-aggregate-sig-p
   #:bls-aggregate-sig-point
   #:bls-aggregate-sig-count
   #:bls-aggregate-sig-mode
   #:bls-threshold-share
   #:bls-threshold-share-p
   #:bls-threshold-share-index
   #:bls-threshold-share-secret
   #:bls-threshold-share-public
   #:bls-threshold-share-verification-vector
   #:bls-pop
   #:bls-pop-p
   #:bls-pop-public-key
   #:bls-pop-proof

   ;; Key Generation
   #:bls-keygen
   #:bls-keygen-deterministic
   #:bls-derive-public

   ;; Signing
   #:bls-sign
   #:bls-sign-with-dst

   ;; Verification
   #:bls-verify
   #:bls-verify-with-dst

   ;; Aggregation
   #:bls-aggregate-signatures
   #:bls-aggregate-public-keys
   #:bls-verify-aggregate

   ;; Batch Verification
   #:bls-batch-verify
   #:bls-batch-verify-same-message

   ;; Proof of Possession
   #:bls-pop-prove
   #:bls-pop-verify
   #:bls-aggregate-with-pop

   ;; Threshold Signatures
   #:bls-threshold-keygen
   #:bls-threshold-sign
   #:bls-threshold-combine
   #:bls-threshold-verify

   ;; Rogue Key Protection
   #:bls-safe-aggregate
   #:bls-derive-coefficients))
