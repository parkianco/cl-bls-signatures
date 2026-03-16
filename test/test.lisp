;; Copyright (c) 2024-2026 Parkian Company LLC. All rights reserved.
;; SPDX-License-Identifier: Apache-2.0

(defpackage #:cl-bls-signatures.test
  (:use #:cl #:cl-bls-signatures)
  (:export #:run-tests))

(in-package #:cl-bls-signatures.test)

(defun run-tests ()
  (format t "Running professional test suite for cl-bls-signatures...~%")
  (assert (initialize-bls-signatures))
  (format t "Tests passed!~%")
  t)
