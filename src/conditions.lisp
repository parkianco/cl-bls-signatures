;; Copyright (c) 2024-2026 Parkian Company LLC. All rights reserved.
;; SPDX-License-Identifier: Apache-2.0

(in-package #:cl-bls-signatures)

(define-condition cl-bls-signatures-error (error)
  ((message :initarg :message :reader cl-bls-signatures-error-message))
  (:report (lambda (condition stream)
             (format stream "cl-bls-signatures error: ~A" (cl-bls-signatures-error-message condition)))))
