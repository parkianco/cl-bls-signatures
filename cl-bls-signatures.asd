;;;; cl-bls-signatures.asd
;;;; BLS (Boneh-Lynn-Shacham) Aggregate Signatures for Common Lisp
;;;; Pure CL implementation - no external dependencies

(asdf:defsystem #:cl-bls-signatures
  :description "BLS12-381 aggregate signatures: sign, verify, aggregate, threshold"
  :author "Parkian Company LLC"
  :license "MIT"
  :version "1.0.0"
  :serial t
  :components
  ((:module "src"
    :serial t
    :components
    ((:file "package")
     (:file "util")
     (:file "curve")
     (:file "sign")
     (:file "aggregate")
     (:file "verify"))))
  :in-order-to ((test-op (test-op #:cl-bls-signatures/test))))

(asdf:defsystem #:cl-bls-signatures/test
  :description "Tests for cl-bls-signatures"
  :depends-on (#:cl-bls-signatures)
  :components
  ((:module "test"
    :components
    ((:file "test-bls-sig"))))
  :perform (test-op (o c)
             (uiop:symbol-call :cl-bls-signatures/test :run-tests)))
