;;;; -*- mode: lisp; indent-tabs-mode: nil -*-
(in-package :crypto-tests)

;;; Test vectors based on calling crypto_scrypt library function in
;;; the original scrypt utility.

(defvar *scrypt1-password*
  (coerce #(112 97 115 115 119 111 114 100)
          '(vector (unsigned-byte 8))))
(defvar *scrypt1-salt*
  (coerce #(115 97 108 116)
          '(vector (unsigned-byte 8))))

(defvar *scrypt1-key*
  (coerce #(116 87 49 175 68 132 243 35 150 137 105 237 162 137 174 238 0 91 89
            3 172 86 30 100 165 172 161 33 121 123 247 115)
          '(vector (unsigned-byte 8))))

(rtest:deftest scryptkdf1
    (run-kdf-test (crypto:make-kdf 'crypto:scrypt-kdf :N 16384 :r 8 :p 1)
                  *scrypt1-password* *scrypt1-salt* 1000 (length *scrypt1-key*) *scrypt1-key*)
  t)

(defvar *scrypt2-password*
  (coerce #(112 97 115 115 119 111 114 100)
          '(vector (unsigned-byte 8))))
(defvar *scrypt2-salt*
  (coerce #(115 97 108 116)
          '(vector (unsigned-byte 8))))

(defvar *scrypt2-key*
  (coerce #(243 198 84 124 73 207 248 197 175 189 52 186 30 224 136 138 229 99
            59 58 111 136 95 54 139 227 241 159 14 126 231 215)
          '(vector (unsigned-byte 8))))

(rtest:deftest scryptkdf2
    (run-kdf-test (crypto:make-kdf 'crypto:scrypt-kdf :N 16384 :r 8 :p 2)
                  *scrypt2-password* *scrypt2-salt* 1000 (length *scrypt2-key*) *scrypt2-key*)
  t)

(defvar *scrypt3-password*
  (coerce #(112 97 115 115 119 111 114 100)
          '(vector (unsigned-byte 8))))
(defvar *scrypt3-salt*
  (coerce #(115 97 108 116)
          '(vector (unsigned-byte 8))))

(defvar *scrypt3-key*
  (coerce #(136 189 94 219 82 209 221 0 24 135 114 173 54 23 18 144 34 78 116
            130 149 37 177 141 115 35 165 127 145 150 60 55) 
          '(vector (unsigned-byte 8))))

(rtest:deftest scryptkdf3
    (run-kdf-test (crypto:make-kdf 'crypto:scrypt-kdf :N 16 :r 100 :p 100)
                  *scrypt3-password* *scrypt3-salt* 1000 (length *scrypt3-key*) *scrypt3-key*)
  t)
