;; Copyright (c) 2024-2026 Parkian Company LLC. All rights reserved.
;; SPDX-License-Identifier: BSD-3-Clause

;;;; test/test-bls-sig.lisp
;;;; Tests for cl-bls-signatures

(defpackage #:cl-bls-signatures/test
  (:use #:cl #:cl-bls-signatures.core)
  (:export #:run-tests))

(in-package #:cl-bls-signatures/test)

;;; ============================================================================
;;; Test Infrastructure
;;; ============================================================================

(defvar *test-count* 0)
(defvar *pass-count* 0)
(defvar *fail-count* 0)

(defmacro deftest (name &body body)
  "Define a test case."
  `(defun ,name ()
     (incf *test-count*)
     (handler-case
         (progn ,@body
                (incf *pass-count*)
                (format t "  PASS: ~A~%" ',name)
                t)
       (error (e)
         (incf *fail-count*)
         (format t "  FAIL: ~A - ~A~%" ',name e)
         nil))))

(defmacro assert-true (form &optional message)
  "Assert that FORM evaluates to non-nil."
  `(unless ,form
     (error "Assertion failed~@[: ~A~]" ,message)))

(defmacro assert-equal (expected actual &optional message)
  "Assert that EXPECTED equals ACTUAL."
  `(unless (equal ,expected ,actual)
     (error "Expected ~S but got ~S~@[: ~A~]" ,expected ,actual ,message)))

(defmacro assert-bytes= (a b &optional message)
  "Assert byte vectors are equal."
  `(unless (and (= (length ,a) (length ,b))
                (every #'= ,a ,b))
     (error "Byte vectors not equal~@[: ~A~]" ,message)))

;;; ============================================================================
;;; Utility Tests
;;; ============================================================================

(deftest test-string-to-octets
  (let ((result (string-to-octets "Hello")))
    (assert-equal 5 (length result))
    (assert-equal 72 (aref result 0))   ; H
    (assert-equal 101 (aref result 1))  ; e
    (assert-equal 108 (aref result 2))  ; l
    (assert-equal 108 (aref result 3))  ; l
    (assert-equal 111 (aref result 4)))) ; o

(deftest test-bytes-to-integer
  (let ((bytes #(1 2 3 4)))
    (assert-equal #x01020304 (bytes-to-integer bytes :big-endian t))
    (assert-equal #x04030201 (bytes-to-integer bytes :big-endian nil))))

(deftest test-integer-to-bytes
  (let ((result (integer-to-bytes #x01020304 4 :big-endian t)))
    (assert-equal 4 (length result))
    (assert-equal 1 (aref result 0))
    (assert-equal 2 (aref result 1))
    (assert-equal 3 (aref result 2))
    (assert-equal 4 (aref result 3))))

(deftest test-sha256
  (let ((result (sha256 (string-to-octets "hello"))))
    (assert-equal 32 (length result))
    ;; Verify known hash value for "hello"
    (assert-equal #x2c (aref result 0))
    (assert-equal #xf2 (aref result 1))))

(deftest test-hmac-sha256
  (let ((result (hmac-sha256 (string-to-octets "key")
                             (string-to-octets "message"))))
    (assert-equal 32 (length result))))

(deftest test-constant-time-bytes=
  (let ((a #(1 2 3 4))
        (b #(1 2 3 4))
        (c #(1 2 3 5)))
    (assert-true (constant-time-bytes= a b))
    (assert-true (not (constant-time-bytes= a c)))))

;;; ============================================================================
;;; Key Generation Tests
;;; ============================================================================

(deftest test-keygen
  (let ((kp (bls-keygen)))
    (assert-true (bls-keypair-p kp))
    (assert-equal 32 (length (bls-keypair-secret kp)))
    (assert-equal 96 (length (bls-keypair-public kp)))))

(deftest test-keygen-deterministic
  (let* ((seed (sha256 (string-to-octets "test seed")))
         (kp1 (bls-keygen-deterministic seed))
         (kp2 (bls-keygen-deterministic seed)))
    (assert-bytes= (bls-keypair-secret kp1) (bls-keypair-secret kp2))
    (assert-bytes= (bls-keypair-public kp1) (bls-keypair-public kp2))))

(deftest test-derive-public
  (let* ((kp (bls-keygen))
         (derived (bls-derive-public (bls-keypair-secret kp))))
    (assert-bytes= (bls-keypair-public kp) derived)))

;;; ============================================================================
;;; Signing Tests
;;; ============================================================================

(deftest test-sign
  (let* ((kp (bls-keygen))
         (message (string-to-octets "Hello, BLS!"))
         (sig (bls-sign kp message)))
    (assert-true (bls-signature-p sig))
    (assert-equal 48 (length (bls-signature-point sig)))))

(deftest test-sign-deterministic
  (let* ((kp (bls-keygen))
         (message (string-to-octets "Test message"))
         (sig1 (bls-sign kp message))
         (sig2 (bls-sign kp message)))
    (assert-bytes= (bls-signature-point sig1) (bls-signature-point sig2)
                   "Same keypair and message should produce same signature")))

(deftest test-sign-with-string
  (let* ((kp (bls-keygen))
         (sig (bls-sign kp "String message")))
    (assert-true (bls-signature-p sig))))

;;; ============================================================================
;;; Verification Tests
;;; ============================================================================

(deftest test-verify-valid
  (let* ((kp (bls-keygen))
         (message (string-to-octets "Verify me"))
         (sig (bls-sign kp message)))
    (assert-true (bls-verify (bls-keypair-public kp) message sig))))

(deftest test-verify-wrong-message
  (let* ((kp (bls-keygen))
         (sig (bls-sign kp "Original")))
    (assert-true (not (bls-verify (bls-keypair-public kp) "Different" sig)))))

(deftest test-verify-wrong-key
  (let* ((kp1 (bls-keygen))
         (kp2 (bls-keygen))
         (sig (bls-sign kp1 "Message")))
    (assert-true (not (bls-verify (bls-keypair-public kp2) "Message" sig)))))

;;; ============================================================================
;;; Aggregation Tests
;;; ============================================================================

(deftest test-aggregate-signatures
  (let* ((kp1 (bls-keygen))
         (kp2 (bls-keygen))
         (kp3 (bls-keygen))
         (message (string-to-octets "Aggregate me"))
         (sig1 (bls-sign kp1 message))
         (sig2 (bls-sign kp2 message))
         (sig3 (bls-sign kp3 message))
         (agg (bls-aggregate-signatures (list sig1 sig2 sig3))))
    (assert-true (bls-aggregate-sig-p agg))
    (assert-equal 48 (length (bls-aggregate-sig-point agg)))
    (assert-equal 3 (bls-aggregate-sig-count agg))))

(deftest test-aggregate-empty
  (let ((agg (bls-aggregate-signatures nil)))
    (assert-true (bls-aggregate-sig-p agg))
    (assert-equal 0 (bls-aggregate-sig-count agg))))

(deftest test-aggregate-public-keys
  (let* ((kp1 (bls-keygen))
         (kp2 (bls-keygen))
         (agg-pk (bls-aggregate-public-keys
                  (list (bls-keypair-public kp1) (bls-keypair-public kp2)))))
    (assert-equal 96 (length agg-pk))))

;;; ============================================================================
;;; Proof of Possession Tests
;;; ============================================================================

(deftest test-pop-prove
  (let* ((kp (bls-keygen))
         (pop (bls-pop-prove kp)))
    (assert-true (bls-pop-p pop))
    (assert-equal 96 (length (bls-pop-public-key pop)))
    (assert-equal 48 (length (bls-pop-proof pop)))))

(deftest test-pop-verify-valid
  (let* ((kp (bls-keygen))
         (pop (bls-pop-prove kp)))
    (assert-true (bls-pop-verify pop))))

;;; ============================================================================
;;; Threshold Signature Tests
;;; ============================================================================

(deftest test-threshold-keygen
  (multiple-value-bind (shares master-pk vv)
      (bls-threshold-keygen 5 3)
    (assert-equal 5 (length shares))
    (assert-equal 96 (length master-pk))
    (assert-equal 3 (length vv))
    (dolist (share shares)
      (assert-true (bls-threshold-share-p share))
      (assert-equal 32 (length (bls-threshold-share-secret share)))
      (assert-equal 96 (length (bls-threshold-share-public share))))))

(deftest test-threshold-sign
  (multiple-value-bind (shares master-pk vv)
      (bls-threshold-keygen 5 3)
    (declare (ignore master-pk vv))
    (let ((message "Threshold message"))
      (multiple-value-bind (partial-sig index)
          (bls-threshold-sign (first shares) message)
        (assert-equal 48 (length partial-sig))
        (assert-equal 1 index)))))

(deftest test-threshold-combine
  (multiple-value-bind (shares master-pk vv)
      (bls-threshold-keygen 5 3)
    (declare (ignore vv))
    (let* ((message "Threshold test")
           ;; Get partial sigs from first 3 shares
           (partial-sigs '())
           (indices '()))
      (loop for share in (subseq shares 0 3)
            do (multiple-value-bind (ps idx)
                   (bls-threshold-sign share message)
                 (push ps partial-sigs)
                 (push idx indices)))
      (let ((combined (bls-threshold-combine
                       (nreverse partial-sigs)
                       (nreverse indices)
                       3)))
        (assert-true (bls-signature-p combined))
        (assert-equal 48 (length (bls-signature-point combined)))))))

(deftest test-threshold-verify
  (multiple-value-bind (shares master-pk vv)
      (bls-threshold-keygen 5 3)
    (declare (ignore vv))
    (let* ((message "Verify threshold")
           (partial-sigs '())
           (indices '()))
      (loop for share in (subseq shares 0 3)
            do (multiple-value-bind (ps idx)
                   (bls-threshold-sign share message)
                 (push ps partial-sigs)
                 (push idx indices)))
      (let ((combined (bls-threshold-combine
                       (nreverse partial-sigs)
                       (nreverse indices)
                       3)))
        (assert-true (bls-threshold-verify master-pk message combined))))))

;;; ============================================================================
;;; Batch Verification Tests
;;; ============================================================================

(deftest test-batch-verify-empty
  (assert-true (bls-batch-verify nil)))

(deftest test-batch-verify-same-message
  (let* ((kp1 (bls-keygen))
         (kp2 (bls-keygen))
         (message "Common message")
         (sig1 (bls-sign kp1 message))
         (sig2 (bls-sign kp2 message)))
    (assert-true (bls-batch-verify-same-message
                  (list (bls-keypair-public kp1) (bls-keypair-public kp2))
                  message
                  (list sig1 sig2)))))

;;; ============================================================================
;;; Safe Aggregation Tests
;;; ============================================================================

(deftest test-derive-coefficients
  (let* ((kp1 (bls-keygen))
         (kp2 (bls-keygen))
         (pks (list (bls-keypair-public kp1) (bls-keypair-public kp2)))
         (coeffs (bls-derive-coefficients pks)))
    (assert-equal 2 (length coeffs))
    (assert-true (plusp (first coeffs)))
    (assert-true (plusp (second coeffs)))))

(deftest test-safe-aggregate
  (let* ((kp1 (bls-keygen))
         (kp2 (bls-keygen))
         (message "Safe aggregate test")
         (sig1 (bls-sign kp1 message))
         (sig2 (bls-sign kp2 message))
         (pks (list (bls-keypair-public kp1) (bls-keypair-public kp2)))
         (agg (bls-safe-aggregate pks (list sig1 sig2))))
    (assert-true (bls-aggregate-sig-p agg))
    (assert-equal 2 (bls-aggregate-sig-count agg))))

;;; ============================================================================
;;; Test Runner
;;; ============================================================================

(defun run-tests ()
  "Run all BLS signature tests."
  (setf *test-count* 0
        *pass-count* 0
        *fail-count* 0)
  (format t "~%Running cl-bls-signatures tests...~%~%")

  ;; Utility tests
  (format t "Utility tests:~%")
  (test-string-to-octets)
  (test-bytes-to-integer)
  (test-integer-to-bytes)
  (test-sha256)
  (test-hmac-sha256)
  (test-constant-time-bytes=)

  ;; Key generation tests
  (format t "~%Key generation tests:~%")
  (test-keygen)
  (test-keygen-deterministic)
  (test-derive-public)

  ;; Signing tests
  (format t "~%Signing tests:~%")
  (test-sign)
  (test-sign-deterministic)
  (test-sign-with-string)

  ;; Verification tests
  (format t "~%Verification tests:~%")
  (test-verify-valid)
  (test-verify-wrong-message)
  (test-verify-wrong-key)

  ;; Aggregation tests
  (format t "~%Aggregation tests:~%")
  (test-aggregate-signatures)
  (test-aggregate-empty)
  (test-aggregate-public-keys)

  ;; PoP tests
  (format t "~%Proof of Possession tests:~%")
  (test-pop-prove)
  (test-pop-verify-valid)

  ;; Threshold tests
  (format t "~%Threshold signature tests:~%")
  (test-threshold-keygen)
  (test-threshold-sign)
  (test-threshold-combine)
  (test-threshold-verify)

  ;; Batch verification tests
  (format t "~%Batch verification tests:~%")
  (test-batch-verify-empty)
  (test-batch-verify-same-message)

  ;; Safe aggregation tests
  (format t "~%Safe aggregation tests:~%")
  (test-derive-coefficients)
  (test-safe-aggregate)

  ;; Summary
  (format t "~%========================================~%")
  (format t "Tests: ~D  Passed: ~D  Failed: ~D~%"
          *test-count* *pass-count* *fail-count*)
  (format t "========================================~%")

  (zerop *fail-count*))
