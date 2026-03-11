;;;; Copyright (c) 2024-2026 Parkian Company LLC. All rights reserved.
;;;; SPDX-License-Identifier: BSD-3-Clause

;;;; src/aggregate.lisp
;;;; BLS signature aggregation for cl-bls-signatures

(in-package #:cl-bls-signatures.core)

;;; ============================================================================
;;; Aggregate Signature Type
;;; ============================================================================

(defstruct (bls-aggregate-sig (:constructor %make-bls-aggregate-sig))
  "An aggregated BLS signature combining multiple individual signatures.

   FIELDS:
   - point: 48-byte compressed aggregate (same size as individual!)
   - count: Number of signatures aggregated
   - mode: :same-message or :multi-message"
  (point nil :type (or null (simple-array (unsigned-byte 8) (48))) :read-only t)
  (count 0 :type fixnum :read-only t)
  (mode :same-message :type (member :same-message :multi-message) :read-only t))

;;; ============================================================================
;;; Signature Aggregation
;;; ============================================================================

(defun bls-aggregate-signatures (signatures)
  "Aggregate multiple signatures into a single compact signature.

   PURPOSE:
   Combines N BLS signatures into one signature of the same size (48 bytes).
   This is the key feature of BLS - constant-size aggregation.

   PARAMETERS:
   - SIGNATURES [list]: List of bls-signature or 48-byte signature vectors

   RETURN:
   bls-aggregate-sig structure

   ALGORITHM:
   agg_sig = sig_1 + sig_2 + ... + sig_n (point addition in G1)

   PROPERTIES:
   - Output size is constant (48 bytes) regardless of input count
   - Aggregation is associative and commutative

   EXAMPLES:
   (bls-aggregate-signatures (list sig1 sig2 sig3))"
  (when (null signatures)
    (return-from bls-aggregate-signatures
      (%make-bls-aggregate-sig :point (make-g1-identity) :count 0)))
  (let ((result (make-array 48 :element-type '(unsigned-byte 8) :initial-element 0))
        (count 0))
    (dolist (sig signatures)
      (let ((bytes (etypecase sig
                     (bls-signature (bls-signature-point sig))
                     ((vector (unsigned-byte 8)) sig))))
        (bls-g1-add-inplace result bytes)
        (incf count)))
    (%make-bls-aggregate-sig :point result :count count :mode :same-message)))

;;; ============================================================================
;;; Public Key Aggregation
;;; ============================================================================

(defun bls-aggregate-public-keys (public-keys)
  "Aggregate multiple public keys into one.

   PURPOSE:
   For same-message aggregate verification, public keys can be
   combined to enable O(1) pairing verification.

   PARAMETERS:
   - PUBLIC-KEYS [list]: List of 96-byte public key vectors

   RETURN:
   96-byte aggregated public key

   ALGORITHM:
   agg_pk = pk_1 + pk_2 + ... + pk_n (point addition in G2)

   SECURITY WARNING:
   Without proof of possession verification, this is vulnerable
   to rogue key attacks. Use bls-aggregate-with-pop for safety."
  (when (null public-keys)
    (error "Cannot aggregate empty public key list"))
  (let ((result (make-array 96 :element-type '(unsigned-byte 8) :initial-element 0)))
    (dolist (pk public-keys)
      (bls-g2-add-inplace result pk))
    result))

;;; ============================================================================
;;; Safe Aggregation with PoP
;;; ============================================================================

(defun bls-aggregate-with-pop (keypairs-with-pops)
  "Safely aggregate public keys after verifying PoPs.

   PARAMETERS:
   - KEYPAIRS-WITH-POPS [list]: List of (public-key pop) pairs

   RETURN:
   Aggregated public key if all PoPs valid, signals error otherwise

   SECURITY:
   This is the SAFE way to aggregate public keys from untrusted sources."
  (let ((verified-pks '()))
    (dolist (entry keypairs-with-pops)
      (destructuring-bind (pk pop) entry
        (unless (bls-pop-verify pop)
          (error "Invalid proof of possession for public key"))
        (push pk verified-pks)))
    (bls-aggregate-public-keys (nreverse verified-pks))))

;;; ============================================================================
;;; Rogue Key Attack Prevention
;;; ============================================================================

(defun bls-derive-coefficients (public-keys)
  "Derive deterministic coefficients for safe aggregation.

   PURPOSE:
   Computes coefficients c_i = H(pk_i || H(all_pks)) that make
   rogue key attacks computationally infeasible.

   PARAMETERS:
   - PUBLIC-KEYS [list]: All public keys being aggregated

   RETURN:
   List of integer coefficients in F_r

   ALGORITHM:
   1. L = H(pk_1 || pk_2 || ... || pk_n)
   2. For each pk_i: c_i = H(pk_i || L) mod r"
  (when (null public-keys)
    (return-from bls-derive-coefficients nil))
  (let* ((all-pks (apply #'concatenate '(vector (unsigned-byte 8)) public-keys))
         (L (sha256 all-pks))
         (coefficients '()))
    (dolist (pk public-keys)
      (let* ((input (concatenate '(vector (unsigned-byte 8)) pk L))
             (c-hash (sha256 input))
             (c (bls-mod-r (bytes-to-integer c-hash :big-endian t))))
        (when (zerop c) (setf c 1))
        (push c coefficients)))
    (nreverse coefficients)))

(defun bls-safe-aggregate (public-keys signatures)
  "Rogue-key-safe signature aggregation without PoP.

   PURPOSE:
   Aggregates signatures using coefficient weighting to prevent
   rogue key attacks even without proof of possession.

   PARAMETERS:
   - PUBLIC-KEYS [list]: Public keys corresponding to signatures
   - SIGNATURES [list]: Signatures to aggregate

   RETURN:
   bls-aggregate-sig structure

   ALGORITHM:
   1. Derive coefficients c_i from public key set
   2. agg_sig = sum(c_i * sig_i)

   USE CASE:
   When you cannot or have not verified proofs of possession."
  (unless (= (length public-keys) (length signatures))
    (error "Public key and signature counts must match"))
  (let* ((coefficients (bls-derive-coefficients public-keys))
         (result (make-array 48 :element-type '(unsigned-byte 8) :initial-element 0))
         (count 0))
    (loop for sig in signatures
          for c in coefficients
          do (let* ((sig-bytes (etypecase sig
                                 (bls-signature (bls-signature-point sig))
                                 ((vector (unsigned-byte 8)) sig)))
                    (weighted (bls-g1-scalar-mul-sim c sig-bytes)))
               (bls-g1-add-inplace result weighted)
               (incf count)))
    (%make-bls-aggregate-sig :point result :count count :mode :same-message)))
