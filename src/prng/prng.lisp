;;;; -*- mode: lisp; indent-tabs-mode: nil -*-
;;;; prng.lisp -- common functions for pseudo-random number generators

(in-package :crypto)


(defvar *prng* nil
  "Default pseudo-random-number generator for use by all crypto
  functions; the user must initialize it, e.g. with (setf
  crypto:*prng* (crypto:make-prng :fortuna)).")

(defclass pseudo-random-number-generator ()
  ()
  (:documentation "A pseudo random number generator.  Base class for
  other PRNGs; not intended to be instantiated."))

(defun list-all-prngs ()
  '(fortuna))

(defgeneric make-prng (name &key seed)
  (:documentation "Create a new NAME-type random number generator,
  seeding it from SEED.  If SEED is a pathname or namestring, read data
  from the indicated file; if it is sequence of bytes, use those bytes
  directly; if it is :RANDOM then read from /dev/random; if it
  is :URANDOM then read from /dev/urandom; if it is NIL then the
  generator is not seeded."))

(defmethod make-prng :around (name &key (seed :random))
  (let ((prng (call-next-method)))
    (cond
      ((eq seed nil))
      ((find seed '(:random :urandom)) (read-os-random-seed seed prng))
      ((or (pathnamep seed) (stringp seed)) (read-seed seed prng))
      ((typep seed 'simple-octet-vector)
       (reseed (slot-value prng 'generator) seed)
       (incf (slot-value prng 'reseed-count)))
      (t (error "SEED must be an octet vector, pathname indicator, :random or :urandom")))
    prng))

(defun random-data (num-bytes &optional (pseudo-random-number-generator *prng*))
  (internal-random-data num-bytes pseudo-random-number-generator))

(defgeneric internal-random-data (num-bytes pseudo-random-number-generator)
  (:documentation "Generate NUM-BYTES bytes using
  PSEUDO-RANDOM-NUMBER-GENERATOR"))

(defun random-bits (num-bits &optional (pseudo-random-number-generator *prng*))
  (logand (1- (expt 2 num-bits))
          (octets-to-integer
           (internal-random-data (ceiling num-bits 8) pseudo-random-number-generator))))

(defun strong-random (limit &optional (prng *prng*))
  "Return a strong random number from 0 to limit-1 inclusive.  A drop-in
replacement for COMMON-LISP:RANDOM."
  (assert (plusp limit))
  (assert prng)
  (etypecase limit
    (integer
     (let* ((log-limit (log limit 2))
            (num-bytes (ceiling log-limit 8))
            (mask (1- (expt 2 (ceiling log-limit)))))
       (loop for random = (logand (ironclad:octets-to-integer
                                   (internal-random-data num-bytes prng))
                                  mask)
          until (< random limit)
          finally (return random))))
    (float
     (float (let ((floor (floor 1 long-float-epsilon)))
              (* limit
                 (/ (strong-random floor)
                    floor)))))))

(defun os-random-seed (source num-bytes)
  #+unix(let ((path (cond
                      ((eq source :random) #P"/dev/random")
                      ((eq source :urandom) #P"/dev/urandom")
                      (t (error "Source must be either :random or :urandom"))))
              (seq (make-array num-bytes :element-type '(unsigned-byte 8))))
          (with-open-file (seed-file path :element-type '(unsigned-byte 8))
            (assert (>= (read-sequence seq seed-file) num-bytes))
            seq))
  ;; FIXME: this is _untested_!
  #+(and win32 sb-dynamic-core)(sb-win32:crypt-gen-random num-bytes)
  #-(or unix (and win32 sb-dynamic-core))(error "OS-RANDOM-SEED is not supported on your platform."))

(defun read-os-random-seed (source &optional (prng *prng*))
  (internal-read-os-random-seed source prng)
  t)

(defgeneric internal-read-os-random-seed (source prng)
  (:documentation "(Re)seed PRNG from SOURCE.  SOURCE may be :random
  or :urandom"))

(defun read-seed (path &optional (pseudo-random-number-generator *prng*))
  "Reseed PSEUDO-RANDOM-NUMBER-GENERATOR from PATH.  If PATH doesn't
exist, reseed from /dev/random and then write that seed to PATH."
  (if (probe-file path)
      (internal-read-seed path pseudo-random-number-generator)
      (progn
        (read-os-random-seed pseudo-random-number-generator)
        (write-seed path pseudo-random-number-generator)
        ;; FIXME: this only works under SBCL.  It's important, though,
        ;; as it sets the proper permissions for reading a seedfile.
        #+sbcl(sb-posix:chmod path (logior sb-posix:S-IRUSR sb-posix:S-IWUSR))))
  t)

(defgeneric internal-read-seed (path prng)
  (:documentation "Reseed PRNG from PATH."))

(defun write-seed (path &optional (prng *prng*))
  (internal-write-seed path prng))

(defgeneric internal-write-seed (path prng)
  (:documentation "Write enough random data from PRNG to PATH to
  properly reseed it."))
