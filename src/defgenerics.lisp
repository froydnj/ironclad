(in-package :crypto)

(defgeneric derive-key (kdf passphrase salt iteration-count key-length))

(defgeneric make-public-key (kind &key &allow-other-keys)
  (:documentation "Return a public key of KIND, initialized according to
the specified keyword arguments."))

(defgeneric make-private-key (kind &key &allow-other-keys)
  (:documentation "Return a private key of KIND, initialized according to
the specified keyword arguments."))

(defgeneric sign-message (key message &key start end)
  (:documentation "Produce a key-specific signature of MESSAGE; MESSAGE is a
(VECTOR (UNSIGNED-BYTE 8)).  START and END bound the extent of the
message."))

(defgeneric verify-signature (key message signature &key start end)
  (:documentation "Verify that SIGNATURE is the signature of MESSAGE using
KEY.  START and END bound the extent of the message."))

(defgeneric encrypt-message (key message &key start end)
  (:documentation "Encrypt MESSAGE with KEY.  START and END bound the extent
of the message.  Returns a fresh octet vector."))

(defgeneric decrypt-message (key message &key start end)
  (:documentation "Decrypt MESSAGE with KEY.  START and END bound the extent
of the message.  Returns a fresh octet vector."))

(defgeneric make-prng (name &key seed)
  (:documentation "Create a new NAME-type random number generator,
  seeding it from SEED.  If SEED is a pathname or namestring, read data
  from the indicated file; if it is sequence of bytes, use those bytes
  directly; if it is :RANDOM then read from /dev/random; if it
  is :URANDOM then read from /dev/urandom; if it is NIL then the
  generator is not seeded."))

(defgeneric internal-random-data (num-bytes pseudo-random-number-generator)
  (:documentation "Generate NUM-BYTES bytes using
  PSEUDO-RANDOM-NUMBER-GENERATOR"))

(defgeneric internal-read-os-random-seed (source prng)
  (:documentation "(Re)seed PRNG from SOURCE.  SOURCE may be :random
  or :urandom"))

(defgeneric internal-read-seed (path prng)
  (:documentation "Reseed PRNG from PATH."))

(defgeneric internal-write-seed (path prng)
  (:documentation "Write enough random data from PRNG to PATH to
  properly reseed it."))

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

(defgeneric digest-length (digest)
  (:documentation "Return the number of bytes in a digest generated by DIGEST."))

(defgeneric add-padding-bytes (padding text start block-offset block-size)
  (:documentation "Add padding to the block in TEXT beginning at position
START.  Padding is done according to PADDING and assumes that text
prior to BLOCK-OFFSET is user-supplied.

This function assumes that the portion of TEXT from START to
 (+ START BLOCK-SIZE) is writable."))

(defgeneric count-padding-bytes (padding text start block-size)
  (:documentation "Return the number of bytes of padding in the block in
TEXT beginning at START.  The padding algorithm used for the block is
PADDING."))

(defgeneric encrypted-message-length (cipher mode length
                                      &optional handle-final-block)
  (:documentation "Return the length a message of LENGTH would be if it
were to be encrypted (decrypted) with CIPHER in MODE.  HANDLE-FINAL-BLOCK
indicates whether we are encrypting up to and including the final block
 (so that short blocks may be taken into account, if applicable).

Note that this computation may involve MODE's state."))

(defgeneric mode-crypt-functions (cipher mode)
  (:documentation "Returns two functions that perform encryption and
decryption, respectively, with CIPHER in MODE.  The lambda list of each
function is (IN OUT IN-START IN-END OUT-START HANDLE-FINAL-BLOCK).
HANDLE-FINAL-BLOCK is as in ENCRYPT and DECRYPT; the remaining parameters
should be self-explanatory.  Each function, when called, returns two values:
the number of octets processed from IN and the number of octets processed
from OUT.  Note that for some cipher modes, IN and OUT may be different."))

(defgeneric valid-mode-for-cipher-p (cipher mode))

(defgeneric verify-key (cipher key)
  (:documentation "Return T if KEY is a valid encryption key for CIPHER."))

(defgeneric schedule-key (cipher key)
  (:documentation "Schedule KEY for CIPHER, filling CIPHER with any
round keys, etc. needed for encryption and decryption."))

(defgeneric key-lengths (cipher)
  (:documentation "Return a list of possible lengths of a key for
CIPHER.  CIPHER may either be a cipher name as accepted by
MAKE-CIPHER or a cipher object as returned by MAKE-CIPHER.  NIL
is returned if CIPHER does not name a known cipher or is not a
cipher object."))

(defgeneric block-length (cipher)
  (:documentation "Return the number of bytes in an encryption or
decryption block for CIPHER.  CIPHER may either be a cipher name
as accepted by MAKE-CIPHER or a cipher object as returned by
MAKE-CIPHER.  NIL is returned if CIPHER does not name a known
cipher or is not a cipher object."))
