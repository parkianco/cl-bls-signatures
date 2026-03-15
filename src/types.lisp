;; Copyright (c) 2024-2026 Parkian Company LLC. All rights reserved.
;; SPDX-License-Identifier: Apache-2.0

(in-package #:cl-bls-signatures)

;;; Core types for cl-bls-signatures
(deftype cl-bls-signatures-id () '(unsigned-byte 64))
(deftype cl-bls-signatures-status () '(member :ready :active :error :shutdown))
