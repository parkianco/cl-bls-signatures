;;;; package.lisp
;;;; Root package definition for cl-bls-signatures
;;;; Re-exports all public symbols from cl-bls-signatures.core

(in-package #:cl-user)

(defpackage #:cl-bls-signatures
  (:nicknames #:bls)
  (:use #:cl #:cl-bls-signatures.core)
  (:export
   ;; Constants
   #:+bls-curve-order+
   #:+bls-field-modulus+
   #:+bls-dst-sign+
   #:+bls-dst-pop+

   ;; Types
   #:bls-keypair
   #:bls-signature
   #:bls-aggregate-sig
   #:bls-threshold-share
   #:bls-pop

   ;; Type accessors
   #:bls-keypair-secret
   #:bls-keypair-public
   #:bls-keypair-pop
   #:bls-signature-point
   #:bls-signature-dst
   #:bls-aggregate-sig-point
   #:bls-aggregate-sig-count
   #:bls-aggregate-sig-mode
   #:bls-threshold-share-index
   #:bls-threshold-share-secret
   #:bls-threshold-share-public
   #:bls-threshold-share-verification-vector
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
