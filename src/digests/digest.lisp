;;;; digest.lisp -- common functions for hashing

(in-package :crypto)


;;; defining digest (hash) functions

(eval-when (:compile-toplevel :load-toplevel)
(defconstant +buffer-size+ (* 128 1024))
) ; EVAL-WHEN

(deftype buffer-index () `(integer 0 (,+buffer-size+)))

(defun update-digest-from-stream (digest stream &key buffer (start 0) end)
  (cond
    ((let ((element-type (stream-element-type stream)))
       (or (equal element-type '(unsigned-byte 8))
           (equal element-type '(integer 0 255))))
     (flet ((frob (read-buffer start end)
              (loop for last-updated = (read-sequence read-buffer stream
                                                      :start start :end end)
                 do (update-digest digest read-buffer
                                   :start start :end last-updated)
                 until (< last-updated end)
                 finally (return digest))))
       (if buffer
           (frob buffer start (or end (length buffer)))
           (let ((buffer (make-array +buffer-size+
                                     :element-type '(unsigned-byte 8))))
             (declare (dynamic-extent buffer))
             (frob buffer 0 +buffer-size+)))))
    (t
     (error "Unsupported stream element-type ~S for stream ~S."
            (stream-element-type stream) stream))))

;;; Storing a length at the end of the hashed data is very common and
;;; can be a small bottleneck when generating lots of hashes over small
;;; quantities of data.  We assume that the appropriate locations have
;;; already been zeroed if necessary.  LENGTH is also assumed to be an
;;; (effectively) 64-bit quantity.
(declaim (inline store-data-length))
(defun store-data-length (block length offset &optional big-endian-p)
  (let ((lo (if big-endian-p (1+ offset) offset))
        (hi (if big-endian-p offset (1+ offset))))
    #+(and sbcl 32-bit)
    (cond
      ((sb-int:fixnump length)
       (setf (aref block lo) length))
      ;; Otherwise, we have a bignum.
      (t
       (locally (declare (optimize (safety 0))
                         (type sb-bignum:bignum-type length))
         (cond
           ((= (sb-bignum:%bignum-length length) 1)
            (setf (aref block lo) (sb-bignum:%bignum-ref length 0)))
           (t
            (setf (aref block lo) (sb-bignum:%bignum-ref length 0)
                  (aref block hi) (sb-bignum:%bignum-ref length 1)))))))
    #+(and cmu 32-bit)
    (cond
      ((ext:fixnump length)
       (setf (aref block lo) length))
      ;; Otherwise, we have a bignum.
      (t
       (locally (declare (optimize (safety 0))
                         (type bignum:bignum-type length))
         (cond
           ((= (bignum:%bignum-length length) 1)
            (setf (aref block lo) (bignum:%bignum-ref length 0)))
           (t
            (setf (aref block lo) (bignum:%bignum-ref length 0)
                  (aref block hi) (bignum:%bignum-ref length 1)))))))
    #-(or (and sbcl 32-bit)
          (and cmu 32-bit))
    (setf (aref block lo) (ldb (byte 32 0) length)
          (aref block hi) (ldb (byte 32 32) length))))

;;; macros for "mid-level" functions

(defmacro define-digest-registers ((digest-name &key (endian :big) (size 4) (digest-registers nil)) &rest registers)
  (let* ((struct-name (intern (format nil "~A-~A" digest-name '#:regs)))
         (constructor (intern (format nil "~A-~A" '#:initial struct-name)))
         (copier (intern (format nil "%~A-~A" '#:copy struct-name)))
         (digest-fun (intern (format nil "~A~A" digest-name '#:regs-digest)))
         (register-bit-size (* size 8))
         (digest-size (* size (or digest-registers
                                  (length registers))))
         (ref-fun (ubref-fun-name register-bit-size (eq endian :big))))
    `(progn
       (eval-when (:compile-toplevel :load-toplevel :execute)
         (defstruct (,struct-name
                      (:type (vector (unsigned-byte ,register-bit-size)))
                      (:constructor ,constructor ())
                      (:copier ,copier))
           ,@registers)
         ;; Some versions of LispWorks incorrectly define STRUCT-NAME as
         ;; a type with DEFSTRUCT, so avoid gratuitous warnings.
         #-(and lispworks lispworks5.0)
         (deftype ,struct-name ()
           '(simple-array (unsigned-byte ,register-bit-size) (,(length registers)))))
       (defun ,digest-fun (regs buffer start)
         (declare (type ,struct-name regs)
                  (type (simple-array (unsigned-byte 8) (*)) buffer)
                  (type (integer 0 ,(- array-dimension-limit digest-size)) start)
                  ,(burn-baby-burn))
         ,(let ((inlined-unpacking
                 `(setf ,@(loop for (reg value) in registers
                             for index from 0 below digest-size by size
                             nconc `((,ref-fun buffer (+ start ,index))
                                     (,(intern (format nil "~A-~A-~A" digest-name '#:regs reg)) regs))))))
               (cond
                 #+(and sbcl :little-endian)
                 ((eq endian :little)
                  `(if (and (= start 0) (<= ,register-bit-size sb-vm:n-word-bits))
                       (sb-kernel:ub8-bash-copy regs 0 buffer 0 ,digest-size)
                       ,inlined-unpacking))
                 #+(and sbcl :big-endian)
                 ((eq endian :big)
                  `(if (and (= start 0) (<= ,register-bit-size sb-vm:n-word-bits))
                       (sb-kernel:ub8-bash-copy regs 0 buffer 0 ,digest-size)
                       ,inlined-unpacking))
                 (t inlined-unpacking)))
         buffer))))

(defmacro define-digest-updater (digest-name &body body)
  (destructuring-bind (maybe-doc-string &rest rest) body
    `(defmethod update-digest ((state ,digest-name) (sequence vector) &key (start 0) (end (length sequence)))
       ,@(when (stringp maybe-doc-string)
               `(,maybe-doc-string))
       (declare (type (simple-array (unsigned-byte 8) (*)) sequence))
       (declare (type index start end))
       ,(hold-me-back)
       ,@(if (stringp maybe-doc-string)
             rest
             body))))

;;; SPECS is either (DIGEST-NAME DIGEST-BYTES) or a list of the same.
;;; The latter spelling is for digests that are related, but have
;;; different output sizes (e.g. SHA2-512 and SHA2-384).  In that case,
;;; the first list is expected to be for the "major" variant of the
;;; pair; its digest type is expected to be the supertype of the
;;; variants.
(defmacro define-digest-finalizer (specs &body body)
  (let* ((single-digest-p (not (consp (car specs))))
         (specs (if single-digest-p (list specs) specs))
         (inner-fun-name (intern (format nil "%~A-~A-~A" '#:finalize (caar specs) '#:state))))
    (destructuring-bind (maybe-doc-string &rest rest) body
      (loop for (digest-name digest-size) in specs
         for regs-digest-fun = (intern (format nil "~A~A" digest-name '#:regs-digest))
         collect `(defmethod finalize-digest ((state ,digest-name)
                                              &optional buffer buffer-start)
                    ,@(when (stringp maybe-doc-string)
                            `(,maybe-doc-string))
                    (declare (type (or (simple-array (unsigned-byte 8) (*)) cl:null) buffer))
                    (cond
                      (buffer
                       ;; verify that the buffer is large enough
                       (let ((buffer-start (or buffer-start 0)))
                         (if (<= ,digest-size (- (length buffer) buffer-start))
                             (,inner-fun-name state buffer buffer-start
                                              ,@(unless single-digest-p
                                                       `(#',regs-digest-fun)))
                             (error 'insufficient-buffer-space
                                    :buffer buffer :start buffer-start
                                    :length ,digest-size))))
                      (t
                       (,inner-fun-name state
                                        (make-array ,digest-size
                                                    :element-type '(unsigned-byte 8))
                                        0
                                        ,@(unless single-digest-p
                                                 `(#',regs-digest-fun)))))) into finalizers
         finally
         (return
           `(progn
              ,@finalizers
              (defun ,inner-fun-name (state %buffer buffer-start ,@(unless single-digest-p
                                                                           '(reg-digest-fun)))
                ,(hold-me-back)
                (macrolet ((finalize-registers (state regs)
                             (declare (ignore state))
                             ,(if single-digest-p
                                  ``(,',(intern (format nil "~A~A" (caar specs) '#:regs-digest)) ,regs %buffer buffer-start)
                                  ``(funcall reg-digest-fun ,regs %buffer buffer-start))))
                  ,@(if (stringp maybe-doc-string)
                        rest
                        body)))))))))

;;; common superclass (superstructure?) for MD5-style digest functions

(defstruct (mdx
             (:constructor nil)
             (:copier nil))
  ;; This is technically an (UNSIGNED-BYTE 61).  But the type-checking
  ;; penalties that imposes on a good 32-bit implementation are
  ;; significant.  We've opted to omit the type declaration here.  If
  ;; you really need to digest exabytes of data, I'm sure we can work
  ;; something out.
  (amount 0)
  ;; Most "64-bit" digest functions (e.g. SHA512) will need to override
  ;; this initial value in an &AUX.
  (buffer (make-array 64 :element-type '(unsigned-byte 8)) :read-only t
   :type simple-octet-vector)
  ;; This fixed type should be big enough for "64-bit" digest functions.
  (buffer-index 0 :type (integer 0 128)))

(declaim (inline mdx-updater))
(defun mdx-updater (state compressor seq start end)
  (declare (type mdx state))
  (declare (type function compressor))
  (declare (type index start end))
  (let* ((buffer (mdx-buffer state))
         (buffer-index (mdx-buffer-index state))
         (buffer-length (length buffer))
         (length (- end start)))
    (declare (type fixnum length))
    (unless (zerop buffer-index)
      (let ((amount (min (- buffer-length buffer-index)
                         length)))
        (copy-to-buffer seq start amount buffer buffer-index)
        (setq start (+ start amount))
        (let ((new-index (logand (+ buffer-index amount)
                                 (1- buffer-length))))
          (when (zerop new-index)
            (funcall compressor state buffer 0))
          (when (>= start end)
            (setf (mdx-buffer-index state) new-index)
            (incf (mdx-amount state) length)
            (return-from mdx-updater state)))))
    (loop until (< (- end start) buffer-length)
          do (funcall compressor state seq start)
             (setq start (the fixnum (+ start buffer-length)))
          finally (return
                    (let ((amount (- end start)))
                      (unless (zerop amount)
                        (copy-to-buffer seq start amount buffer 0)
                        (setf (mdx-buffer-index state) amount))
                      (incf (mdx-amount state) length)
                      state)))))
(declaim (notinline mdx-updater))

;;; high-level generic function drivers

;;; These three functions are intended to be one-shot ways to digest
;;; an object of some kind.  You could write these in terms of the more
;;; familiar digest interface below, but these are likely to be slightly
;;; more efficient, as well as more obvious about what you're trying to
;;; do.
(defgeneric digest-file (digest-spec pathname &rest args
                                     &key buffer start end
                                     digest digest-start)
  (:documentation "Return the digest of the contents of the file named by PATHNAME using
the algorithm DIGEST-NAME.

If DIGEST is provided, the digest will be placed into DIGEST starting at
DIGEST-START.  DIGEST must be a (SIMPLE-ARRAY (UNSIGNED-BYTE 8) (*)).
An error will be signaled if there is insufficient room in DIGEST.

If BUFFER is provided, the portion of BUFFER between START and END will
be used to hold data read from the stream."))

(defmethod digest-file ((digest-name cons) pathname &rest kwargs)
  (apply #'digest-file (apply #'make-digest digest-name) pathname kwargs))
(defmethod digest-file ((digest-name symbol) pathname &rest kwargs)
  (apply #'digest-file (make-digest digest-name) pathname kwargs))

(defmethod digest-file (state pathname &key buffer (start 0) end
                        digest (digest-start 0))
  (with-open-file (stream pathname :element-type '(unsigned-byte 8)
                          :direction :input
                          :if-does-not-exist :error)
    (update-digest-from-stream state stream
                               :buffer buffer :start start :end end)
    (produce-digest state :digest digest :digest-start digest-start)))

(defgeneric digest-stream (digest-spec stream &rest args
                                       &key buffer start end
                                       digest digest-start)
  (:documentation "Return the digest of the contents of STREAM using the algorithm
DIGEST-NAME.  STREAM-ELEMENT-TYPE of STREAM should be (UNSIGNED-BYTE 8).

If DIGEST is provided, the digest will be placed into DIGEST starting at
DIGEST-START.  DIGEST must be a (SIMPLE-ARRAY (UNSIGNED-BYTE 8) (*)).
An error will be signaled if there is insufficient room in DIGEST.

If BUFFER is provided, the portion of BUFFER between START and END will
be used to hold data read from the stream."))

(defmethod digest-stream ((digest-name cons) stream &rest kwargs)
  (apply #'digest-stream (apply #'make-digest digest-name) stream kwargs))
(defmethod digest-stream ((digest-name symbol) stream &rest kwargs)
  (apply #'digest-stream (make-digest digest-name) stream kwargs))

(defmethod digest-stream (state stream &key buffer (start 0) end
                          digest (digest-start 0))
  (update-digest-from-stream state stream
                               :buffer buffer :start start :end end)
  (produce-digest state :digest digest :digest-start digest-start))

(defgeneric digest-sequence (digest-spec sequence &rest args
                                         &key start end digest digest-start)
  (:documentation "Return the digest of the subsequence of SEQUENCE
specified by START and END using the algorithm DIGEST-NAME.  For CMUCL
and SBCL, SEQUENCE can be any vector with an element-type
of (UNSIGNED-BYTE 8); for other implementations, SEQUENCE must be a
(SIMPLE-ARRAY (UNSIGNED-BYTE 8) (*)).

If DIGEST is provided, the digest will be placed into DIGEST starting at
DIGEST-START.  DIGEST must be a (SIMPLE-ARRAY (UNSIGNED-BYTE 8) (*)).
An error will be signaled if there is insufficient room in DIGEST."))

(defmethod digest-sequence ((digest-name symbol) sequence &rest kwargs)
  (apply #'digest-sequence (make-digest digest-name) sequence kwargs))

(defmethod digest-sequence (state sequence &key (start 0) end
                            digest (digest-start 0))
  (declare (type (vector (unsigned-byte 8)) sequence) (type index start))
  #+cmu
  ;; respect the fill-pointer
  (let ((end (or end (length sequence))))
    (declare (type index end))
    (lisp::with-array-data ((data sequence) (real-start start) (real-end end))
      (declare (ignore real-end))
      (update-digest state data
                     :start real-start :end (+ real-start (- end start)))))
  #+sbcl
  ;; respect the fill-pointer
  (let ((end (or end (length sequence))))
    (sb-kernel:with-array-data ((data sequence) (real-start start) (real-end end))
      (declare (ignore real-end))
      (update-digest state data
                     :start real-start :end (+ real-start (- end start)))))
  #-(or cmu sbcl)
  (let ((real-end (or end (length sequence))))
    (declare (type index real-end))
    (update-digest state sequence
                   :start start :end (or real-end (length sequence))))
  (produce-digest state :digest digest :digest-start digest-start))

;;; These four functions represent the common interface for digests in
;;; other crypto toolkits (OpenSSL, Botan, Python, etc.).  You obtain
;;; some state object for a particular digest, you update it with some
;;; data, and then you get the actual digest.  Flexibility is the name
;;; of the game with these functions.
(defun make-digest (digest-name &rest keys &key &allow-other-keys)
  "Return a digest object which uses the algorithm DIGEST-NAME."
  (typecase digest-name
    (symbol
     (let ((name (massage-symbol digest-name)))
       (if (digestp name)
           (apply (the function (get name '%make-digest)) keys)
           (error 'unsupported-digest :name digest-name))))
    (t
     (error 'type-error :datum digest-name :expected-type 'symbol))))

(defgeneric copy-digest (digester &optional copy)
  (:documentation "Return a copy of DIGESTER.  If COPY is not NIL, it
should be of the same type as DIGESTER and will receive the copied data,
rather than creating a new object.  The copy is a deep copy, not a
shallow copy as might be returned by COPY-STRUCTURE."))

(defgeneric update-digest (digester thing &key &allow-other-keys)
  (:documentation "Update the internal state of DIGESTER with THING.
The exact method is determined by the type of THING."))

(defgeneric produce-digest (digester &key digest digest-start)
  (:documentation "Return the hash of the data processed by
DIGESTER so far. This function modifies the internal state of DIGESTER.

If DIGEST is provided, the hash will be placed into DIGEST starting at
DIGEST-START.  DIGEST must be a (SIMPLE-ARRAY (UNSIGNED-BYTE 8) (*)).
An error will be signaled if there is insufficient room in DIGEST."))

(defmethod produce-digest (digester &key digest (digest-start 0))
  (finalize-digest digester digest digest-start))
 

;;; the digest-defining macro

(defun digestp (sym)
  (get sym '%digest-length))

(defun list-all-digests ()
  (loop for symbol being each external-symbol of (find-package :ironclad)
     if (digestp symbol)
     collect symbol))

(defun digest-supported-p (name)
  "Return T if the digest NAME is a valid digest name."
  (and (symbolp name)
       (not (cl:null (digestp name)))))

(defgeneric digest-length (digest)
  (:documentation "Return the number of bytes in a digest generated by DIGEST."))

(defmethod digest-length ((digest-name symbol))
  (or (digestp (massage-symbol digest-name))
      (error 'unsupported-digest :name digest-name)))

(defmethod digest-length (digest-name)
  (error 'unsupported-digest :name digest-name))

(defmethod update-digest (digester (stream stream) &key buffer (start 0) end
                          &allow-other-keys)
  (update-digest-from-stream digester stream
                             :buffer buffer :start start :end end))

(defun optimized-maker-name (name)
  (let ((*package* (find-package :ironclad)))
    ;; Ironclad gets compiled with *PRINT-CASE* set to :UPCASE; ensure
    ;; that names we return match what got compiled.n
    (intern (format nil "%~A-~A-~A" '#:make name '#:digest))))

(defmacro defdigest (name &key digest-length block-length)
  (let ((optimized-maker-name (optimized-maker-name name)))
    `(progn
       (eval-when (:compile-toplevel :load-toplevel)
         (export ',name :ironclad))
       (setf (get ',name '%digest-length) ,digest-length)
       (setf (get ',name '%make-digest) (symbol-function ',optimized-maker-name))
       (defmethod digest-length ((digest ,name))
         ,digest-length)
       (defmethod block-length ((digest ,name))
         ,block-length))))

;;; If we pass a constant argument to MAKE-DIGEST, convert the
;;; MAKE-DIGEST call to a direct call to the state creation function.
(define-compiler-macro make-digest (&whole form &environment env
                                           name &rest keys &key &allow-other-keys)
  (declare (ignore env))
  (cond
    ((or (keywordp name)
         (and (quotationp name) (symbolp name)))
     (let ((name (massage-symbol (unquote name))))
       (if (digestp name)
           `(,(optimized-maker-name name) ,@keys)
           form)))
    (t form)))

;;; And do the same for various one-shot digest functions.
(defun maybe-expand-one-shot-call (form funname name 2nd-arg keys)
  (cond
    ((or (keywordp name)
         (and (quotationp name) (symbolp name)))
     (let ((name (massage-symbol (unquote name))))
       (if (digestp name)
           `(,funname (,(optimized-maker-name name)) ,2nd-arg ,@keys)
           form)))
    (t form)))

(define-compiler-macro digest-sequence (&whole form &environment env
                                               name sequence &rest keys)
  (declare (ignore env))
  (maybe-expand-one-shot-call form 'digest-sequence name sequence keys))

(define-compiler-macro digest-stream (&whole form &environment env
                                             name stream &rest keys)
  (declare (ignore env))
  (maybe-expand-one-shot-call form 'digest-stream name stream keys))

(define-compiler-macro digest-file (&whole form &environment env
                                           name file &rest keys)
  (declare (ignore env))
  (maybe-expand-one-shot-call form 'digest-file name file keys))
