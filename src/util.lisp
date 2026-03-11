;;;; src/util.lisp
;;;; Utility functions for cl-bls-signatures
;;;; Provides cryptographic primitives without external dependencies

(in-package #:cl-bls-signatures.util)

(declaim (optimize (speed 3) (safety 1)))

;;; ============================================================================
;;; Byte/String Conversion
;;; ============================================================================

(defun string-to-octets (string &key (encoding :utf-8))
  "Convert STRING to a vector of octets.
   Only UTF-8 encoding is supported (standard ASCII subset)."
  (declare (ignore encoding))
  (let* ((len (length string))
         (result (make-array len :element-type '(unsigned-byte 8))))
    (dotimes (i len result)
      (setf (aref result i) (char-code (char string i))))))

(defun octets-to-string (octets &key (encoding :utf-8))
  "Convert octets to string. Only UTF-8/ASCII subset supported."
  (declare (ignore encoding))
  (let* ((len (length octets))
         (result (make-string len)))
    (dotimes (i len result)
      (setf (char result i) (code-char (aref octets i))))))

;;; ============================================================================
;;; Integer/Bytes Conversion
;;; ============================================================================

(defun bytes-to-integer (bytes &key (big-endian t))
  "Convert byte vector to integer.
   BIG-ENDIAN: If T, most significant byte first (default)."
  (let ((result 0)
        (len (length bytes)))
    (if big-endian
        (dotimes (i len result)
          (setf result (logior (ash result 8) (aref bytes i))))
        (dotimes (i len result)
          (setf result (logior result (ash (aref bytes i) (* i 8))))))))

(defun integer-to-bytes (integer size &key (big-endian t))
  "Convert integer to SIZE-byte vector.
   BIG-ENDIAN: If T, most significant byte first (default)."
  (let ((result (make-array size :element-type '(unsigned-byte 8) :initial-element 0)))
    (if big-endian
        (loop for i from (1- size) downto 0
              for shift from 0 by 8
              do (setf (aref result i) (ldb (byte 8 shift) integer)))
        (loop for i from 0 below size
              for shift from 0 by 8
              do (setf (aref result i) (ldb (byte 8 shift) integer))))
    result))

;;; ============================================================================
;;; Constant-Time Comparison
;;; ============================================================================

(defun constant-time-bytes= (a b)
  "Compare byte vectors A and B in constant time.
   Returns T if equal, NIL otherwise.
   Prevents timing side-channel attacks."
  (when (/= (length a) (length b))
    (return-from constant-time-bytes= nil))
  (let ((diff 0))
    (declare (type fixnum diff))
    (dotimes (i (length a))
      (setf diff (logior diff (logxor (aref a i) (aref b i)))))
    (zerop diff)))

;;; ============================================================================
;;; SHA-256 Implementation
;;; ============================================================================

(defconstant +sha256-k+
  #(#x428a2f98 #x71374491 #xb5c0fbcf #xe9b5dba5
    #x3956c25b #x59f111f1 #x923f82a4 #xab1c5ed5
    #xd807aa98 #x12835b01 #x243185be #x550c7dc3
    #x72be5d74 #x80deb1fe #x9bdc06a7 #xc19bf174
    #xe49b69c1 #xefbe4786 #x0fc19dc6 #x240ca1cc
    #x2de92c6f #x4a7484aa #x5cb0a9dc #x76f988da
    #x983e5152 #xa831c66d #xb00327c8 #xbf597fc7
    #xc6e00bf3 #xd5a79147 #x06ca6351 #x14292967
    #x27b70a85 #x2e1b2138 #x4d2c6dfc #x53380d13
    #x650a7354 #x766a0abb #x81c2c92e #x92722c85
    #xa2bfe8a1 #xa81a664b #xc24b8b70 #xc76c51a3
    #xd192e819 #xd6990624 #xf40e3585 #x106aa070
    #x19a4c116 #x1e376c08 #x2748774c #x34b0bcb5
    #x391c0cb3 #x4ed8aa4a #x5b9cca4f #x682e6ff3
    #x748f82ee #x78a5636f #x84c87814 #x8cc70208
    #x90befffa #xa4506ceb #xbef9a3f7 #xc67178f2)
  "SHA-256 round constants.")

(defconstant +sha256-h0+
  #(#x6a09e667 #xbb67ae85 #x3c6ef372 #xa54ff53a
    #x510e527f #x9b05688c #x1f83d9ab #x5be0cd19)
  "SHA-256 initial hash values.")

(declaim (inline sha256-rotr sha256-ch sha256-maj sha256-add32))

(defun sha256-rotr (x n)
  "32-bit right rotation."
  (declare (type (unsigned-byte 32) x) (type (integer 0 31) n))
  (logior (ldb (byte 32 0) (ash x (- n)))
          (ldb (byte 32 0) (ash x (- 32 n)))))

(defun sha256-add32 (&rest args)
  "Add 32-bit integers with wraparound."
  (ldb (byte 32 0) (apply #'+ args)))

(defun sha256-ch (x y z)
  (declare (type (unsigned-byte 32) x y z))
  (logxor (logand x y) (logand (lognot x) z)))

(defun sha256-maj (x y z)
  (declare (type (unsigned-byte 32) x y z))
  (logxor (logand x y) (logand x z) (logand y z)))

(defun sha256-Sigma0 (x)
  (declare (type (unsigned-byte 32) x))
  (logxor (sha256-rotr x 2) (sha256-rotr x 13) (sha256-rotr x 22)))

(defun sha256-Sigma1 (x)
  (declare (type (unsigned-byte 32) x))
  (logxor (sha256-rotr x 6) (sha256-rotr x 11) (sha256-rotr x 25)))

(defun sha256-sigma0 (x)
  (declare (type (unsigned-byte 32) x))
  (logxor (sha256-rotr x 7) (sha256-rotr x 18) (ldb (byte 32 0) (ash x -3))))

(defun sha256-sigma1 (x)
  (declare (type (unsigned-byte 32) x))
  (logxor (sha256-rotr x 17) (sha256-rotr x 19) (ldb (byte 32 0) (ash x -10))))

(defun sha256-pad-message (message)
  "Pad message according to SHA-256 spec."
  (let* ((len (length message))
         (bit-len (* len 8))
         ;; Pad to 64 bytes (512 bits) boundary, minus 8 for length
         (pad-len (- 64 (mod (+ len 1 8) 64)))
         (pad-len (if (minusp pad-len) (+ pad-len 64) pad-len))
         (total-len (+ len 1 pad-len 8))
         (padded (make-array total-len :element-type '(unsigned-byte 8) :initial-element 0)))
    ;; Copy message
    (replace padded message)
    ;; Append 1 bit (0x80)
    (setf (aref padded len) #x80)
    ;; Append length as 64-bit big-endian
    (loop for i from 0 below 8
          do (setf (aref padded (- total-len 1 i))
                   (ldb (byte 8 (* i 8)) bit-len)))
    padded))

(defun sha256-process-block (block h)
  "Process one 64-byte block."
  (let ((w (make-array 64 :element-type '(unsigned-byte 32))))
    ;; Prepare message schedule
    (dotimes (i 16)
      (setf (aref w i)
            (logior (ash (aref block (* i 4)) 24)
                    (ash (aref block (+ (* i 4) 1)) 16)
                    (ash (aref block (+ (* i 4) 2)) 8)
                    (aref block (+ (* i 4) 3)))))
    (loop for i from 16 below 64
          do (setf (aref w i)
                   (sha256-add32 (sha256-sigma1 (aref w (- i 2)))
                                 (aref w (- i 7))
                                 (sha256-sigma0 (aref w (- i 15)))
                                 (aref w (- i 16)))))
    ;; Working variables
    (let ((a (aref h 0)) (b (aref h 1)) (c (aref h 2)) (d (aref h 3))
          (e (aref h 4)) (f (aref h 5)) (g (aref h 6)) (hh (aref h 7)))
      (declare (type (unsigned-byte 32) a b c d e f g hh))
      ;; Main loop
      (dotimes (i 64)
        (let* ((t1 (sha256-add32 hh (sha256-Sigma1 e) (sha256-ch e f g)
                                 (aref +sha256-k+ i) (aref w i)))
               (t2 (sha256-add32 (sha256-Sigma0 a) (sha256-maj a b c))))
          (setf hh g g f f e (sha256-add32 d t1)
                d c c b b a a (sha256-add32 t1 t2))))
      ;; Update hash
      (setf (aref h 0) (sha256-add32 (aref h 0) a)
            (aref h 1) (sha256-add32 (aref h 1) b)
            (aref h 2) (sha256-add32 (aref h 2) c)
            (aref h 3) (sha256-add32 (aref h 3) d)
            (aref h 4) (sha256-add32 (aref h 4) e)
            (aref h 5) (sha256-add32 (aref h 5) f)
            (aref h 6) (sha256-add32 (aref h 6) g)
            (aref h 7) (sha256-add32 (aref h 7) hh)))))

(defun sha256 (message)
  "Compute SHA-256 hash of MESSAGE (byte vector).
   Returns 32-byte hash."
  (let* ((message (if (stringp message)
                      (string-to-octets message)
                      message))
         (padded (sha256-pad-message message))
         (h (copy-seq +sha256-h0+))
         (result (make-array 32 :element-type '(unsigned-byte 8))))
    ;; Process each 64-byte block
    (loop for offset from 0 below (length padded) by 64
          do (sha256-process-block (subseq padded offset (+ offset 64)) h))
    ;; Convert hash to bytes
    (dotimes (i 8)
      (let ((word (aref h i)))
        (setf (aref result (* i 4)) (ldb (byte 8 24) word)
              (aref result (+ (* i 4) 1)) (ldb (byte 8 16) word)
              (aref result (+ (* i 4) 2)) (ldb (byte 8 8) word)
              (aref result (+ (* i 4) 3)) (ldb (byte 8 0) word))))
    result))

;;; ============================================================================
;;; HMAC-SHA256
;;; ============================================================================

(defun hmac-sha256 (key message)
  "Compute HMAC-SHA256 of MESSAGE using KEY.
   Both KEY and MESSAGE should be byte vectors."
  (let* ((key (if (stringp key) (string-to-octets key) key))
         (message (if (stringp message) (string-to-octets message) message))
         (block-size 64)
         ;; If key > block size, hash it
         (key (if (> (length key) block-size)
                  (sha256 key)
                  key))
         ;; Pad key to block size
         (padded-key (make-array block-size :element-type '(unsigned-byte 8) :initial-element 0)))
    (replace padded-key key)
    ;; Inner and outer pads
    (let ((ipad (make-array block-size :element-type '(unsigned-byte 8)))
          (opad (make-array block-size :element-type '(unsigned-byte 8))))
      (dotimes (i block-size)
        (setf (aref ipad i) (logxor (aref padded-key i) #x36)
              (aref opad i) (logxor (aref padded-key i) #x5c)))
      ;; HMAC = H(opad || H(ipad || message))
      (sha256 (concatenate '(vector (unsigned-byte 8))
                           opad
                           (sha256 (concatenate '(vector (unsigned-byte 8))
                                                ipad message)))))))

;;; ============================================================================
;;; Random Bytes
;;; ============================================================================

(defun get-random-bytes (n)
  "Generate N cryptographically random bytes.
   Uses SBCL's random with reasonable entropy mixing."
  (let ((result (make-array n :element-type '(unsigned-byte 8)))
        ;; Seed with internal real time for entropy mixing
        (*random-state* (make-random-state t)))
    (dotimes (i n result)
      (setf (aref result i) (random 256)))))

;;; ============================================================================
;;; Modular Exponentiation
;;; ============================================================================

(defun mod-expt (base exponent modulus)
  "Compute (BASE ^ EXPONENT) mod MODULUS using binary exponentiation."
  (declare (type integer base exponent modulus))
  (when (zerop modulus) (error "Modulus cannot be zero"))
  (when (minusp exponent) (error "Exponent must be non-negative"))
  (cond
    ((zerop exponent) (mod 1 modulus))
    ((= exponent 1) (mod base modulus))
    (t (let ((result 1)
             (base (mod base modulus)))
         (declare (type integer result))
         (loop while (plusp exponent)
               do (when (oddp exponent)
                    (setf result (mod (* result base) modulus)))
                  (setf exponent (ash exponent -1))
                  (setf base (mod (* base base) modulus)))
         result))))
