;; Copyright (c) 2024-2026 Parkian Company LLC. All rights reserved.
;; SPDX-License-Identifier: BSD-3-Clause

;;;; cl-bls-signatures.asd
;;;; BLS (Boneh-Lynn-Shacham) Aggregate Signatures for Common Lisp
;;;; Pure CL implementation - no external dependencies

(asdf:defsystem #:cl-bls-signatures
  :description "BLS12-381 aggregate signatures: sign, verify, aggregate, threshold"
  :author "Park Ian Co"
  :license "Apache-2.0"
  :version "0.1.0"
  :serial t
  :components
  ((:module "src"
                :components ((:file "package")
                             (:file "conditions" :depends-on ("package"))
                             (:file "types" :depends-on ("package"))
                             (:file "cl-bls-signatures" :depends-on ("package" "conditions" "types"))))))
  :in-order-to ((asdf:test-op (test-op #:cl-bls-signatures/test))))

(asdf:defsystem #:cl-bls-signatures/test
  :description "Tests for cl-bls-signatures"
  :depends-on (#:cl-bls-signatures)
  :components
  ((:module "test"
    :components
    ((:file "test-bls-sig"))))
  :perform (asdf:test-op (o c)
             (let ((result (uiop:symbol-call :cl-bls-signatures/test :run-tests)))
               (unless result
                 (error "Tests failed")))))
