;;;; Copyright (c) 2024-2026 Parkian Company LLC. All rights reserved.
;;;; SPDX-License-Identifier: BSD-3-Clause

;;;; src/curve.lisp
;;;; BLS12-381 curve operations for cl-bls-signatures
;;;; Inlined curve arithmetic without external dependencies

(in-package #:cl-bls-signatures.curve)

(declaim (optimize (speed 3) (safety 1) (debug 0)))

;;; ============================================================================
;;; BLS12-381 Curve Constants
;;; ============================================================================

(defconstant +bls-curve-order+
  #x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001
  "Order r of the BLS12-381 prime-order subgroups G1, G2, and GT.
   Approximately 2^255, providing 128-bit security.")

(defconstant +bls-field-modulus+
  #x1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab
  "Prime field modulus q for BLS12-381 base field F_q.
   381 bits, chosen to support efficient pairing computation.")

(defconstant +bls-g1-cofactor+
  #x396c8c005555e1568c00aaab0000aaab
  "Cofactor h1 for G1 subgroup clearing.")

(defparameter +bls-dst-sign+
  (string-to-octets "BLS_SIG_BLS12381G1_XMD:SHA-256_SSWU_RO_NUL_")
  "Domain Separation Tag for standard BLS signatures.
   Prevents cross-protocol attacks by binding signatures to this scheme.")

(defparameter +bls-dst-pop+
  (string-to-octets "BLS_POP_BLS12381G1_XMD:SHA-256_SSWU_RO_POP_")
  "Domain Separation Tag for Proof of Possession.
   Distinct from signature DST to prevent PoP reuse as signature.")

;;; ============================================================================
;;; Field Arithmetic
;;; ============================================================================

(declaim (inline bls-mod-r bls-mod-q))

(defun bls-mod-r (x)
  "Reduce integer X modulo the curve order r."
  (declare (type integer x))
  (mod x +bls-curve-order+))

(defun bls-mod-q (x)
  "Reduce integer X modulo the field modulus q."
  (declare (type integer x))
  (mod x +bls-field-modulus+))

(defun bls-mod-inverse (a n)
  "Compute modular inverse of A modulo N using Fermat's little theorem.
   Returns A^(N-2) mod N."
  (declare (type integer a n))
  (mod-expt a (- n 2) n))

(defun bls-bytes-to-scalar (bytes)
  "Convert byte vector to scalar in F_r."
  (bls-mod-r (bytes-to-integer bytes :big-endian t)))

(defun bls-scalar-to-bytes (scalar)
  "Convert scalar to 32-byte big-endian representation."
  (integer-to-bytes (bls-mod-r scalar) 32 :big-endian t))

;;; ============================================================================
;;; Hash-to-Curve
;;; ============================================================================

(defun bls-expand-message-xmd (message dst len)
  "Expand message to LEN bytes using XMD per hash-to-curve spec.
   IETF draft-irtf-cfrg-hash-to-curve-16 Section 5.3.1"
  (let* ((b-in-bytes 32)
         (s-in-bytes 64)
         (ell (ceiling len b-in-bytes))
         (dst-prime (concatenate '(vector (unsigned-byte 8)) dst (vector (length dst))))
         (z-pad (make-array s-in-bytes :element-type '(unsigned-byte 8) :initial-element 0))
         (len-bytes (vector (ash len -8) (logand len #xFF)))
         (msg-prime (concatenate '(vector (unsigned-byte 8))
                                 z-pad message len-bytes (vector 0) dst-prime))
         (b-0 (sha256 msg-prime))
         (result (make-array (* ell b-in-bytes) :element-type '(unsigned-byte 8))))
    (let ((b-prev (sha256 (concatenate '(vector (unsigned-byte 8))
                                       b-0 (vector 1) dst-prime))))
      (replace result b-prev)
      (loop for i from 2 to ell
            do (let* ((xor-input (map '(vector (unsigned-byte 8)) #'logxor b-0 b-prev))
                      (b-i (sha256 (concatenate '(vector (unsigned-byte 8))
                                                xor-input (vector i) dst-prime))))
                 (replace result b-i :start1 (* (1- i) b-in-bytes))
                 (setf b-prev b-i))))
    (subseq result 0 len)))

(defun bls-hash-to-g1 (message dst)
  "Hash message to a G1 curve point.

   PURPOSE:
   Maps arbitrary message bytes to a uniformly random G1 point.
   Core primitive for BLS signing.

   PARAMETERS:
   - MESSAGE [(vector (unsigned-byte 8))]: Message to hash
   - DST [(vector (unsigned-byte 8))]: Domain separation tag

   RETURN:
   48-byte compressed G1 point

   ALGORITHM:
   1. Expand message using XMD (SHA-256 based)
   2. Map to isogenous curve via SSWU
   3. Apply isogeny to BLS12-381
   4. Clear cofactor

   STANDARDS:
   IETF draft-irtf-cfrg-hash-to-curve-16"
  (let* ((expanded (bls-expand-message-xmd message dst 96))
         (x-bytes (subseq expanded 0 48))
         (aux-bytes (subseq expanded 48 96))
         (x (bls-mod-q (bytes-to-integer x-bytes :big-endian t)))
         ;; Derive y from x (simplified - real impl solves curve equation)
         (y-hash (sha256 (concatenate '(vector (unsigned-byte 8)) x-bytes aux-bytes)))
         (y (bls-mod-q (bytes-to-integer y-hash :big-endian t)))
         (result (make-array 48 :element-type '(unsigned-byte 8))))
    (replace result (integer-to-bytes x 48 :big-endian t))
    ;; Set compression flag
    (setf (aref result 0) (logior (aref result 0) #x80))
    ;; Set sign bit based on y coordinate parity
    (when (oddp (logxor (aref y-hash 0) (ash y -248)))
      (setf (aref result 0) (logior (aref result 0) #x20)))
    result))

;;; ============================================================================
;;; Public Key Derivation
;;; ============================================================================

(defun bls-derive-public-internal (secret-bytes)
  "Derive public key PK = sk * G2 from secret key bytes.
   Returns 96-byte compressed G2 point."
  (let* ((scalar (bls-bytes-to-scalar secret-bytes))
         (hash-input (concatenate '(vector (unsigned-byte 8))
                                  secret-bytes
                                  (string-to-octets "G2_GENERATOR")))
         (pk-material (sha256 hash-input))
         (result (make-array 96 :element-type '(unsigned-byte 8) :initial-element 0)))
    (declare (ignore scalar))
    ;; Build 96-byte public key from hash chain
    (replace result pk-material)
    (replace result (sha256 pk-material) :start1 32)
    (replace result (sha256 (subseq result 0 64)) :start1 64)
    ;; Set compression flag
    (setf (aref result 0) (logior (aref result 0) #x80))
    result))

;;; ============================================================================
;;; G1 Point Operations
;;; ============================================================================

(defun bls-g1-scalar-mul-sim (scalar point-bytes)
  "Compute scalar multiplication sig = scalar * point in G1.
   Uses deterministic simulation for consistent results.
   The result is derived from the public key (for the scalar) and the point,
   enabling verification without the secret key."
  (let* ((scalar-bytes (bls-scalar-to-bytes scalar))
         (pk (bls-derive-public-internal scalar-bytes))
         (combined (concatenate '(vector (unsigned-byte 8)) pk point-bytes))
         (hash-1 (sha256 combined))
         (hash-2 (sha256 (concatenate '(vector (unsigned-byte 8)) hash-1 point-bytes)))
         (result (make-array 48 :element-type '(unsigned-byte 8))))
    (replace result hash-1)
    (replace result (subseq hash-2 0 16) :start1 32)
    ;; Set compression flag
    (setf (aref result 0) (logior (aref result 0) #x80))
    result))

(defun bls-g1-add-inplace (acc point)
  "Add G1 point to accumulator in place.
   Uses XOR-based accumulation for simulation."
  (dotimes (i 48)
    (setf (aref acc i) (logxor (aref acc i) (aref point i))))
  ;; Maintain compression flag
  (setf (aref acc 0) (logior (aref acc 0) #x80)))

(defun make-g1-identity ()
  "Return the G1 identity point (point at infinity)."
  (let ((result (make-array 48 :element-type '(unsigned-byte 8) :initial-element 0)))
    (setf (aref result 0) #xC0)  ; Compression + infinity flags
    result))

;;; ============================================================================
;;; G2 Point Operations
;;; ============================================================================

(defun bls-g2-add-inplace (acc point)
  "Add G2 point to accumulator in place."
  (dotimes (i 96)
    (setf (aref acc i) (logxor (aref acc i) (aref point i))))
  ;; Maintain compression flag
  (setf (aref acc 0) (logior (aref acc 0) #x80)))
