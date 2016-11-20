;;;; -*- mode: lisp; indent-tabs-mode: nil -*-
;; Implementation of the Diffie-Hellman key-exchange algorithm
;; Roughly:
;; Bob generetes p, g and a calculates X = g^a mod p and sends p,g and Ys to Alice
;; Alice generates b and calculates Y = g^b mod p and sends Y back to Bob
;; Bob calculates Y^a mod p and arrives at an integer N
;; Alice calculates X^b mod p and arrives at an integer M
;; Results should be N = M = K(secret key)

;; Ported from cryptcl
;; @######################################################################
;; ##
;; ##    Copyright (C) 2003-2007
;; ##    Taale Skogan
;; ##
;; ## Filename:      LICENSE
;; ## Description:   Defines the terms under which this software may be copied.
;; ## Author:        Taale Skogan
;; ##
;; ######################################################################
;; Redistribution and use in source and binary forms, with or without
;; modification, are permitted for any use provided that the
;; following conditions are met:

;; 1. Redistributions of source code must retain the above copyright
;; notice, this list of conditions and the following disclaimer.
;; 2. Redistributions in binary form must reproduce the above copyright
;; notice, this list of conditions and the following disclaimer in the
;; documentation and/or other materials provided with the distribution.

;; THIS SOFTWARE IS PROVIDED ``AS IS'' AND ANY EXPRESS OR IMPLIED
;; WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
;; MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
;; IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY
;; DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
;; DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE
;; 		    GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
;; 		    INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER
;; IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR
;; 						  OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF
;; ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

(in-package :crypto)


;;; class definitions

(defclass dh-params ()
  ((p :initarg :p :reader prime-modulus :type integer)
   (g :initarg :g :reader generator :type integer)))


;;; generic definitions

(defun mod-expt (base exponent modulus)
  "Fast modular exponentiation using the standard square-and-multiply algorithm"
  (let ((result 1))
    (if (= exponent 0)
	1
	(loop
	   (cond
	     ((= exponent 1)
	      (return (mod (* result base) modulus)))
	     ((oddp exponent)
	      (setq result (mod (* result base) modulus)
		    exponent (1- exponent)))
	     (t (setq base (mod (* base base) modulus)
		      exponent (/ exponent 2))))))))

(defun octet-vector-to-integer
    (vector &optional (start 0) (end (length vector)))
  "Represents 8 bits byte string as integer. Assumes byte is 8 bits. Uses big endian format. Vector must be an array of bytes"
  (let ((integer 0))
    (do ((i start (1+ i)))
	((>= i end))
      (setq integer (+ (* integer 256) (aref vector i))))
        integer))

(defun random-secure-bignum (bitsize)
  "Return bignum from a cryptographically secure PRNG."
  (let* ((size (ceiling bitsize 8))
	 (keep (mod bitsize 8))
	 (ov (let ((prng (make-prng :fortuna :seed :random)))
               (random-data size prng))))
    ;; Remove extra bits if bitsize not a multiple of 8.
    ;; This is done by only keeping the least (bitsize mod 8) significant
    ;; bits in the most significant byte.
    (unless (= keep 0)
      (setf (aref ov 0) (mask-field (byte keep 0) (aref ov 0))))
    (octet-vector-to-integer ov)))

(defun random-bignum-max-odd (bitsize)
  "Return random, bitsize bits long, odd integer. In other words, the least and most significant bit is always 1. Used by RSA and DSA."
  (let ((n (random-secure-bignum bitsize)))
    (setf n (dpb 1 (byte 1 (1- bitsize)) n)
	  n (dpb 1 (byte 1 0) n))))

(defun random-secure-bignum-range (low high)
  "Return bignum in the range [low,high] from secure PRNG."
  ;; Be lazy and retry a few times
  (let ((bitsize (integer-length high)))
    (do ((n (- low 1) (random-secure-bignum bitsize)))
	((and (<= n high) (>= n low)) n))))

(defun generate-dh-params (&key p g (bit-size 2048))
  "Generates DH parameters. If you have a pre-computed p and g, they are used instead of generating new ones"
  (unless p
    (setf p (random-bignum-max-odd bit-size)))
  (unless g
    (setf g (do ((n 2 (+ n 1)))
		((/= (mod-expt n p p) 1) n))))
  (make-instance 'dh-params :p p :g g))

(defun compute-dh-public-value (dh-params)
  "Generates a or b and computes X or Y"
  (with-slots (p g) dh-params
    (let ((secret-exp (random-secure-bignum-range 1 (- p 2))))
      (values secret-exp (mod-expt g secret-exp p)))))

(defun compute-dh-secret (dh-params secret-exp dh-public-value)
  "Generates the final secret, given the dh-params and the dh-public-value of the other party"
  (with-slots (p) dh-params
    (mod-expt dh-public-value secret-exp p)))
