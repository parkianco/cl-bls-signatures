(asdf:defsystem #:cl-bls-signatures
  :depends-on (#:alexandria #:bordeaux-threads)
  :components ((:module "src"
                :components ((:file "package")
                             (:file "cl-bls-signatures" :depends-on ("package"))))))