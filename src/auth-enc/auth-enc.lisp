;;;; -*- mode: lisp; indent-tabs-mode: nil -*-
;;;; auth-enc.lisp -- generic functions for symmetric authenticated
;;;; encryption

(in-package :crypto)

(defclass authenticated-mode ()
  ((key :accessor key
        :initarg :key)
   (initialization-vector :accessor initialization-vector
                          :initarg :initialization-vector)
   (cipher :accessor cipher
           :initarg :cipher)
   (authenticated-data :accessor authenticated-data
                       :initarg :authenticated-date
                       :initform (coerce #() '(vector (unsigned-byte 8))))
   (tag :accessor tag
        :initform nil)))

(defclass mode-info ()
  ((class-name :reader %class-name :initarg :class-name)
   (name :reader mode :initarg :mode)))

(defmethod print-object ((object mode-info) stream)
  (print-unreadable-object (object stream :type t)
    (format stream "~A" (mode object))))

(defun %find-mode (name)
  (and (symbolp name)
       (let ((name (massage-symbol name)))
         (and name (get name '%mode-info)))))

(defun (setf %find-mode) (mode-info name)
  (setf (get (massage-symbol name) '%mode-info) mode-info))

(defun list-all-modes ()
  (loop for symbol being each external-symbol of (find-package :ironclad)
     if (%find-mode symbol)
     collect symbol))

(defun mode-supported-p (name)
  "Return T if the mode NAME is supported as an argument to
MAKE-AUTHENTICATED-CIPHER."
  (not (cl:null (%find-mode name))))

(defun find-mode-or-lose (name)
  (format t "~a~&" name)
  (let ((mode-info (%find-mode name)))
    (unless mode-info
      (error 'unsupported-mode :name name))
    mode-info))

(defun validate-parameters-for-mode-info (mode-info cipher key initialization-vector)
  (declare (ignorable mode-info cipher key initialization-vector))
  ;; FIXME: perform some sanity checks, maybe on a per-mode basis?
  t)

(defun make-authenticated-cipher (mode cipher &key key initialization-vector)
  "Return an authenticated cipher object for the authenticated
  encryption mode MODE and the block cipher CIPHER."
  (let ((mode-info (find-mode-or-lose mode)))
    (find-cipher-or-lose cipher)
    (validate-parameters-for-mode-info mode-info cipher key initialization-vector)
    (make-instance (%class-name mode-info)
                   :key key
                   :initialization-vector initialization-vector
                   :cipher cipher)))

(define-compiler-macro make-authenticated-cipher (&whole form &environment env
                                                         mode
                                                         &rest keys
                                                         &key key cipher initialization-vector &allow-other-keys)
  (declare (ignore env keys))
  (cond
   ((or (keywordp cipher)
        (and (quotationp cipher) (symbolp cipher)))
    (let ((mode-info (ignore-errors
                       (validate-parameters-for-mode-info
                          (find-mode-or-lose (unquote mode))
                          (unquote cipher)
                          key
                          initialization-vector))))
      (if mode-info
          `(make-instance ',(%class-name mode-info)
                          :key ,key
                          :cipher ,cipher
                          :initialization-vector ,initialization-vector)
          form)))
   (t form)))

(defun generate-common-mode-methods (name encrypt-function decrypt-function)
  `(progn
     (defmethod authenticated-encrypt-function ((mode ,name))
       #',encrypt-function)
     (defmethod authenticated-decrypt-function ((mode ,name))
       #',decrypt-function)
     (setf (%find-mode ',name)
           (make-instance 'mode-info
                          :class-name ',name
                          :mode ',name))))

(defun %defmode (name initargs)
  (let ((encrypt-function nil)
        (decrypt-function nil))
    (loop for (arg value) in initargs
       do (case arg
            (:encrypt-function
             (if (not encrypt-function)
                 (setf encrypt-function value)
                 (error "Specified :ENCRYPT-FUNCTION multiple times.")))
            (:decrypt-function
             (if (not decrypt-function)
                 (setf decrypt-function value)
                 (error "Specified :DECRYPT-FUNCTION multiple times."))))
       finally (return
                 `(progn
                    ,(generate-common-mode-methods name
                                                   encrypt-function
                                                   decrypt-function))))))

(defmacro defmode (name &rest initargs)
  (%defmode name initargs))
