(in-package :crypto-tests)

(rtest:deftest make-digest.error
  (handler-case (crypto:make-digest :error)
    (crypto:unsupported-digest () :ok)
    (:no-error () :error))
  :ok)

(rtest:deftest digest-length.error
  (handler-case (crypto:digest-length :error)
    (crypto:unsupported-digest () :ok)
    (:no-error () :error))
  :ok)

(rtest:deftest produce-digest.buffer-space
  (let ((sequence (make-array 0 :element-type '(unsigned-byte 8))))
    (dolist (digest (crypto:list-all-digests) :ok)
      (let* ((digest-length (crypto:digest-length digest))
             (buffer (make-array (1- digest-length)
                                 :element-type '(unsigned-byte 8))))
        (handler-case (crypto:digest-sequence digest sequence
                                              :digest buffer
                                              :digest-start 0)
          (crypto:insufficient-buffer-space () :ok)
          (:no-error () (return :error))))))
  :ok)

(rtest:deftest produce-digest.using-buffers
  (let ((sequence (make-array 0 :element-type '(unsigned-byte 8))))
    (dolist (digest (crypto:list-all-digests) :ok)
      (let* ((digest-length (crypto:digest-length digest))
             (buffer (make-array digest-length
                                 :element-type '(unsigned-byte 8)))
             (returned (crypto:digest-sequence digest sequence
                                               :digest buffer
                                               :digest-start 0)))
        (unless (eq returned buffer)
          (return :error)))))
  :ok)

#.(loop for digest in (crypto:list-all-digests)
        collect `(rtest:deftest ,digest
                   (run-test-vector-file ',digest *digest-tests*) t) into forms
        finally (return `(progn ,@forms)))

#.(loop for digest in (crypto:list-all-digests)
        collect `(rtest:deftest ,(intern (format nil "~A/~A" digest '#:incremental))
                   (run-test-vector-file ',digest *digest-incremental-tests*) t) into forms
        finally (return `(progn ,@forms)))

#.(if (boundp '*digest-stream-tests*)
      (loop for digest in (crypto:list-all-digests)
         collect `(rtest:deftest ,(intern (format nil "~A/~A" digest '#:stream))
                      (run-test-vector-file ',digest *digest-stream-tests*) t) into forms
         finally (return `(progn ,@forms)))
      nil)

#.(loop for digest in (crypto:list-all-digests)
        collect `(rtest:deftest ,(intern (format nil "~A/~A" digest '#:reinitialize-instance))
                   (run-test-vector-file ',digest *digest-reinitialize-instance-tests*) t) into forms
        finally (return `(progn ,@forms)))

#.(if (boundp '*digest-fill-pointer-tests*)
      (loop for digest in (crypto:list-all-digests)
         collect `(rtest:deftest ,(intern (format nil "~A/~A" digest '#:fill-pointer))
                      (run-test-vector-file ',digest *digest-fill-pointer-tests*) t) into forms
         finally (return `(progn ,@forms)))
      nil)

(rtest:deftest digests.crypto-package
  (every #'(lambda (s)
             (and (eq (symbol-package s) (find-package :ironclad))
                  (eq (nth-value 1 (find-symbol (symbol-name s)
                                                (find-package :ironclad)))
                      :external)))
         (crypto:list-all-digests))
  t)

(rtest:deftest clean-symbols.digest
  (loop with n-digests = (length (crypto:list-all-digests))
     for s being each symbol of :crypto
     when (crypto::digestp s)
     count s into computed-n-digests
     finally (return (= n-digests computed-n-digests)))
  t)

(rtest:deftest copy-digest.null
  (dolist (digest (crypto:list-all-digests) t)
    (let* ((original (crypto:make-digest digest))
           (copy (crypto:copy-digest original)))
      ;; Ideally, here we'd also test that'd we'd properly copied
      ;; everything (we would probably also UPDATE-DIGEST ORIGINAL a bit
      ;; first, to ensure that we weren't just creating an entirely new
      ;; digest as our copy).  But that requires MOP smarts or separate
      ;; tests for every digest we support.  Ugh--at least for the
      ;; latter.
      (when (eq original copy)
        (return nil))))
  t)

(rtest:deftest copy-digest.copy
  (dolist (digest (crypto:list-all-digests) t)
    (let* ((original (crypto:make-digest digest))
           (copy (crypto:make-digest digest)))
      ;; Make sure we return the object getting passed in.
      ;;
      ;; Ideally, here we'd also test that'd we'd properly copied
      ;; everything (we would probably also UPDATE-DIGEST ORIGINAL a bit
      ;; first, to ensure that we weren't just creating an entirely new
      ;; digest as our copy).  But that requires MOP smarts or separate
      ;; tests for every digest we support.  Ugh--at least for the
      ;; latter.
      (unless (eq (crypto:copy-digest original copy) copy)
        (return nil))))
  t)

(rtest:deftest copy-digest.error
  (dolist (digest (crypto:list-all-digests) t)
    (let* ((original (crypto:make-digest digest)))
      (handler-case (crypto:copy-digest original (make-array 10))
        (error () nil)
        (:no-error () (return nil)))))
  t)
