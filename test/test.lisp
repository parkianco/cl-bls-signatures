;; Copyright (c) 2024-2026 Parkian Company LLC. All rights reserved.
;; SPDX-License-Identifier: Apache-2.0

(defpackage #:cl-bls-signatures.test
  (:use #:cl #:cl-bls-signatures)
  (:export #:run-tests))

(in-package #:cl-bls-signatures.test)

(defun run-tests ()
  (format t "Executing functional test suite for cl-bls-signatures...~%")
  (assert (equal (deep-copy-list '(1 (2 3) 4)) '(1 (2 3) 4)))
  (assert (equal (group-by-count '(1 2 3 4 5) 2) '((1 2) (3 4) (5))))
  (format t "All functional tests passed!~%")
  t)
