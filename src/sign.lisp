;;;; Copyright (c) 2024-2026 Parkian Company LLC. All rights reserved.
;;;; SPDX-License-Identifier: Apache-2.0

;;;; src/sign.lisp
;;;; BLS key generation and signing for cl-bls-signatures

(in-package #:cl-bls-signatures.core)

(declaim (optimize (speed 3) (safety 1) (debug 0)))

;;; ============================================================================
;;; Type Definitions
;;; ============================================================================

(defstruct (bls-keypair (:constructor %make-bls-keypair))
  "A complete BLS keypair containing secret and public key.

   FIELDS:
   - secret: Scalar in F_r (32 bytes)
   - public: G2 point (96 bytes compressed)
   - pop: Optional proof of possession"
  (secret nil :type (or null (simple-array (unsigned-byte 8) (32))) :read-only t)
  (public nil :type (or null (simple-array (unsigned-byte 8) (96))) :read-only t)
  (pop nil :type (or null (simple-array (unsigned-byte 8) (48)))))

(defstruct (bls-signature (:constructor %make-bls-signature))
  "A BLS signature as a compressed G1 point.

   FIELDS:
   - point: 48-byte compressed G1 point
   - dst: Domain separation tag used during signing"
  (point nil :type (or null (simple-array (unsigned-byte 8) (48))) :read-only t)
  (dst nil :type (or null (simple-array (unsigned-byte 8) *)) :read-only t))

(defstruct (bls-threshold-share (:constructor %make-bls-threshold-share))
  "A participant's share in a threshold BLS scheme.

   FIELDS:
   - index: Participant index (1-based)
   - secret: Secret share scalar
   - public: Public verification key for this share
   - verification-vector: Feldman VSS commitments"
  (index 0 :type (integer 1 *) :read-only t)
  (secret nil :type (or null (simple-array (unsigned-byte 8) (32))) :read-only t)
  (public nil :type (or null (simple-array (unsigned-byte 8) (96))) :read-only t)
  (verification-vector nil :type (or null vector) :read-only t))

(defstruct (bls-pop (:constructor %make-bls-pop))
  "Proof of Possession for a BLS public key.

   PURPOSE:
   Proves knowledge of the secret key corresponding to a public key.
   Essential for preventing rogue key attacks in aggregation.

   FIELDS:
   - public-key: The public key this PoP certifies
   - proof: G1 signature on the public key itself"
  (public-key nil :type (or null (simple-array (unsigned-byte 8) (96))) :read-only t)
  (proof nil :type (or null (simple-array (unsigned-byte 8) (48))) :read-only t))

;;; ============================================================================
;;; Key Generation
;;; ============================================================================

(defun bls-keygen ()
  "Generate a new random BLS keypair.

   PURPOSE:
   Creates a cryptographically secure BLS keypair using system entropy.
   The secret key is a random scalar in [1, r-1].
   The public key is sk * G2 where G2 is the generator.

   RETURN:
   bls-keypair structure with fresh random keys.

   SECURITY:
   Uses cryptographically secure random number generation.
   Secret key bytes should be handled with care and zeroed after use.

   EXAMPLES:
   (let ((kp (bls-keygen)))
     (bls-sign kp message))"
  (let* ((secret-bytes (get-random-bytes 32))
         (scalar (bls-bytes-to-scalar secret-bytes)))
    ;; Ensure non-zero scalar
    (loop while (zerop scalar)
          do (setf secret-bytes (get-random-bytes 32))
             (setf scalar (bls-bytes-to-scalar secret-bytes)))
    (let* ((secret (bls-scalar-to-bytes scalar))
           (public (bls-derive-public-internal secret)))
      (%make-bls-keypair :secret secret :public public))))

(defun bls-keygen-deterministic (seed &optional (info ""))
  "Derive BLS keypair deterministically from seed.

   PURPOSE:
   Creates a BLS keypair from a seed using HKDF key derivation.
   Same seed always produces same keypair, enabling key recovery.

   PARAMETERS:
   - SEED [(vector (unsigned-byte 8))]: At least 32 bytes of entropy
   - INFO [string]: Optional context string for domain separation

   RETURN:
   bls-keypair structure

   ALGORITHM:
   Uses HKDF-SHA256 expansion per IETF BLS KeyGen specification.

   SECURITY:
   Seed should come from a secure source (e.g., BIP39 mnemonic).

   EXAMPLES:
   (bls-keygen-deterministic (sha256 master-secret) \"validator-0\")"
  (unless (>= (length seed) 32)
    (error "Seed must be at least 32 bytes for security"))
  (let* ((salt +bls-dst-sign+)
         (info-bytes (string-to-octets info))
         ;; HKDF-Extract
         (prk (hmac-sha256 salt seed))
         ;; HKDF-Expand to 48 bytes for full coverage of F_r
         (okm-1 (hmac-sha256 prk (concatenate '(vector (unsigned-byte 8))
                                              info-bytes (vector 1))))
         (okm-2 (hmac-sha256 prk (concatenate '(vector (unsigned-byte 8))
                                              okm-1 info-bytes (vector 2))))
         (okm (concatenate '(vector (unsigned-byte 8)) okm-1 (subseq okm-2 0 16)))
         (scalar (bls-mod-r (bytes-to-integer okm :big-endian t))))
    (when (zerop scalar) (setf scalar 1))
    (let* ((secret (bls-scalar-to-bytes scalar))
           (public (bls-derive-public-internal secret)))
      (%make-bls-keypair :secret secret :public public))))

(defun bls-derive-public (secret-key)
  "Derive public key from secret key bytes.

   PARAMETERS:
   - SECRET-KEY [(vector (unsigned-byte 8))]: 32-byte secret key

   RETURN:
   96-byte compressed G2 public key"
  (bls-derive-public-internal secret-key))

;;; ============================================================================
;;; Signing
;;; ============================================================================

(defun bls-sign (keypair message)
  "Sign a message with a BLS secret key.

   PURPOSE:
   Creates a BLS signature on the given message. Signatures are
   deterministic - same (key, message) always produces same signature.

   PARAMETERS:
   - KEYPAIR [bls-keypair]: Keypair containing secret key
   - MESSAGE [(vector (unsigned-byte 8)) or string]: Message to sign

   RETURN:
   bls-signature structure

   ALGORITHM:
   sig = sk * H(m) where H maps to G1.

   SECURITY:
   - Deterministic: no nonce-related vulnerabilities
   - Unforgeable under co-CDH assumption

   EXAMPLES:
   (bls-sign keypair (string-to-octets \"Hello\"))"
  (bls-sign-with-dst keypair message +bls-dst-sign+))

(defun bls-sign-with-dst (keypair message dst)
  "Sign message with custom domain separation tag.

   PARAMETERS:
   - KEYPAIR [bls-keypair]: Signing keypair
   - MESSAGE: Message bytes or string
   - DST [(vector (unsigned-byte 8))]: Domain separation tag

   RETURN:
   bls-signature structure"
  (let* ((msg-bytes (etypecase message
                      ((vector (unsigned-byte 8)) message)
                      (string (string-to-octets message))))
         (h-point (bls-hash-to-g1 msg-bytes dst))
         (secret (bls-keypair-secret keypair))
         (scalar (bls-bytes-to-scalar secret))
         ;; Compute sig = sk * H(m)
         (sig-point (bls-g1-scalar-mul-sim scalar h-point)))
    (%make-bls-signature :point sig-point :dst dst)))

;;; ============================================================================
;;; Proof of Possession
;;; ============================================================================

(defun bls-pop-prove (keypair)
  "Generate a Proof of Possession for a keypair.

   PURPOSE:
   Creates a proof that the holder knows the secret key for a public key.
   Essential for preventing rogue key attacks in aggregation.

   PARAMETERS:
   - KEYPAIR [bls-keypair]: Keypair to prove possession of

   RETURN:
   bls-pop structure containing the proof

   ALGORITHM:
   pop = sk * H(pk) where H uses the PoP domain separation tag.

   SECURITY:
   PoP must be verified before including a public key in aggregation."
  (let* ((public (bls-keypair-public keypair))
         (h-pk (bls-hash-to-g1 public +bls-dst-pop+))
         (secret (bls-keypair-secret keypair))
         (scalar (bls-bytes-to-scalar secret))
         (proof (bls-g1-scalar-mul-sim scalar h-pk)))
    (%make-bls-pop :public-key public :proof proof)))

;;; ============================================================================
;;; Threshold Key Generation
;;; ============================================================================

(defun bls-threshold-keygen (n threshold)
  "Generate key shares for t-of-n threshold BLS scheme.

   PURPOSE:
   Creates N key shares such that any T shares can reconstruct
   a valid signature, but fewer than T reveal nothing.

   PARAMETERS:
   - N [integer]: Total number of participants
   - THRESHOLD [integer]: Minimum shares needed to sign (t <= n)

   RETURN:
   (values shares master-public-key verification-vector)
   - shares: List of bls-threshold-share structures
   - master-public-key: Combined public key for verification
   - verification-vector: Feldman VSS commitments

   ALGORITHM:
   Uses Shamir Secret Sharing with Feldman VSS commitments.
   1. Generate random polynomial f(x) of degree t-1
   2. Share_i = f(i) for i in 1..n
   3. Commitments C_j = g^(a_j) for coefficients a_j

   SECURITY:
   - Any t-1 shares reveal nothing about master secret
   - Each share verifiable against commitments"
  (unless (and (plusp threshold) (<= threshold n))
    (error "Invalid threshold parameters: need 1 <= t <= n"))
  (let* (;; Generate random polynomial coefficients a_0, a_1, ..., a_{t-1}
         (coefficients (loop repeat threshold
                             collect (bls-bytes-to-scalar (get-random-bytes 32))))
         ;; Compute verification vector (commitments)
         (verification-vector
          (coerce (loop for coef in coefficients
                        collect (bls-derive-public-internal (bls-scalar-to-bytes coef)))
                  'vector))
         ;; Generate shares f(i) for i = 1 to n
         (shares
          (loop for i from 1 to n
                collect (let* ((share-scalar (evaluate-polynomial coefficients i))
                               (share-secret (bls-scalar-to-bytes share-scalar))
                               (share-public (bls-derive-public-internal share-secret)))
                          (%make-bls-threshold-share
                           :index i
                           :secret share-secret
                           :public share-public
                           :verification-vector verification-vector))))
         ;; Master public key
         (master-public (aref verification-vector 0)))
    (values shares master-public verification-vector)))

(defun evaluate-polynomial (coefficients x)
  "Evaluate polynomial with given coefficients at point x using Horner's method."
  (let ((result 0))
    (loop for coef in (reverse coefficients)
          do (setf result (bls-mod-r (+ coef (bls-mod-r (* result x))))))
    result))

(defun bls-threshold-sign (share message)
  "Create a partial signature using a threshold share.

   PARAMETERS:
   - SHARE [bls-threshold-share]: Participant's share
   - MESSAGE: Message to sign

   RETURN:
   (values partial-signature share-index)

   ALGORITHM:
   partial_sig_i = share_i * H(m)"
  (let* ((msg-bytes (etypecase message
                      ((vector (unsigned-byte 8)) message)
                      (string (string-to-octets message))))
         (h-point (bls-hash-to-g1 msg-bytes +bls-dst-sign+))
         (scalar (bls-bytes-to-scalar (bls-threshold-share-secret share)))
         (partial-sig (bls-g1-scalar-mul-sim scalar h-point)))
    (values partial-sig (bls-threshold-share-index share))))

(defun bls-threshold-combine (partial-signatures indices threshold)
  "Combine threshold partial signatures into full signature.

   PARAMETERS:
   - PARTIAL-SIGNATURES [list]: At least t partial signatures
   - INDICES [list]: Corresponding participant indices
   - THRESHOLD [integer]: The threshold value t

   RETURN:
   bls-signature representing the combined signature

   ALGORITHM:
   Uses Lagrange interpolation to reconstruct signature:
   sig = sum(lambda_i * partial_sig_i)
   where lambda_i are Lagrange coefficients."
  (unless (>= (length partial-signatures) threshold)
    (error "Need at least ~D partial signatures, got ~D" threshold (length partial-signatures)))
  ;; Compute Lagrange coefficients
  (let ((lambdas (compute-lagrange-coefficients indices)))
    (let ((result (make-array 48 :element-type '(unsigned-byte 8) :initial-element 0)))
      (loop for sig in partial-signatures
            for lambda in lambdas
            do (let ((weighted (bls-g1-scalar-mul-sim lambda sig)))
                 (bls-g1-add-inplace result weighted)))
      (%make-bls-signature :point result :dst +bls-dst-sign+))))

(defun compute-lagrange-coefficients (indices)
  "Compute Lagrange interpolation coefficients for given indices at x=0."
  (let ((n (length indices)))
    (loop for i from 0 below n
          for x-i = (nth i indices)
          collect (let ((num 1) (den 1))
                    (loop for j from 0 below n
                          for x-j = (nth j indices)
                          when (/= i j)
                            do (setf num (bls-mod-r (* num (- x-j))))
                               (setf den (bls-mod-r (* den (- x-j x-i)))))
                    (bls-mod-r (* num (bls-mod-inverse den +bls-curve-order+)))))))
