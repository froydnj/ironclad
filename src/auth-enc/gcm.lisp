;; a working--if slow--GCM implementation

(defun xor-blocks (x y)
  "Return X XOR Y, where X and Y are 16-byte (128-bit) blocks"
  ;;(declare (type (vector (unsigned-byte 8) 16) x y))
  (map '(vector (unsigned-byte 8))
       (lambda (xx yy)
         (logxor xx yy))
       x y))

(defun gcm-hash (subkey x)
  ;;(declare (type (vector (unsigned-byte 8)) subkey x))
  ;;(format t "~&subkey: ~a~&x: ~a~&" subkey x)
  (loop for i from 0 below (/ (length x) 16)
     for xx = (crypto:octets-to-integer (subseq x (* i 16) (min (length x) (+ (* i 16) 16))))
     for y = (gcm-block-mult xx
                             (crypto:octets-to-integer subkey))
     then (gcm-block-mult (logxor y xx)
                          (crypto:octets-to-integer subkey))
     ;;do (format t "i: ~a~&xx: ~a~&y: ~a~&" i xx y)
     finally (return y)))

(defun gcm-ctr (key icb plaintext)
  (apply
   #'concatenate
   '(vector (unsigned-byte 8))
   (loop for i from 0 below (ceiling (length plaintext) 16)
      for cb = icb then (gcm-inc 32 cb)
      with ecb = (ironclad:make-cipher :aes :key key :mode :ecb)
      for x = (subseq plaintext (* i 16)
                      (min (* (1+ i) 16)
                           (length plaintext)))
      collect (let ((block (copy-seq cb)))
                (ironclad:encrypt-in-place ecb block)
                (xor-blocks x block)))))

(defun gcm-block-mult (x y)
  (declare (type integer x y))
  (loop for i from 127 downto 0 ;; reversed because logbitp's index is
                                ;; the reverse of the GCM spec's
     for z = (if (logbitp i x) y 0)
     then (if (logbitp i x)
              (logxor z v)
              z)
     for v = (if (logbitp 0 y)
                 (logxor (ash y -1) r)
                 (ash y -1))
     then (if (logbitp 0 v)
                        (logxor (ash v -1) r)
                        (ash v -1))
     with r = (ash #b11100001 120)
     finally (return z)))

(defun ghb (h a c)
  (let* ((u (- (* 16 (ceiling (length c) 16)) (length c)))
         (v (- (* 16 (ceiling (length a) 16)) (length a)))
         (hash 
          (gcm-hash h (concatenate '(vector (unsigned-byte 8))
                                   a
                                   (make-array v :initial-element 0)
                                   c
                                   (make-array u :initial-element 0)
                                   (crypto:integer-to-octets (* 8 (length a))
                                                             :n-bits 64)
                                   (crypto:integer-to-octets (* 8 (length c))
                                                             :n-bits 64)))))
    (ironclad:integer-to-octets hash :n-bits 128)))

(defun gcm-inc (num-bits octets)
  "Increment the NUM-BITS least significant bits of OCTETS.  NUM-BITS
must be a multiple of 8 and greater than 0."
  (let* ((index (- (length octets) (/ num-bits 8)))
         (lsb (subseq octets index))
         (num (crypto:octets-to-integer lsb)))
    (concatenate '(vector (unsigned-byte 8))
                 (subseq octets 0 index)
                 (crypto:integer-to-octets (logand (1+ num)
                                                   (1- (ash 1 num-bits)))
                                           :n-bits num-bits))))
    
(defconstant +gcm-plaintext-length-max+
  (floor (- (expt 2 39) 256) 8))

(defconstant +gcm-additional-authenthicated-data-length-max+
  (floor (1- (expt 2 64)) 8))

(defconstant +gcm-initialization-vector-length-max+
  (floor (1- (expt 2 64)) 8))

(defun gcm-encrypt (key iv plaintext additional-authenticated-data)
  (assert (and
           (<= (length plaintext) +gcm-plaintext-length-max+)
           (<= (length additional-authenticated-data)
               +gcm-additional-authenthicated-data-length-max+)
           (<= 1 (length iv) +gcm-initialization-vector-length-max+)))
  (let* ((cypher (crypto:make-cipher :aes :key key :mode :ecb))
         (hash-block (coerce #(0 0 0 0
                               0 0 0 0
                               0 0 0 0
                               0 0 0 0)
                             '(vector (unsigned-byte 8))))
         j0
         cyphertext
         s)
    (crypto:encrypt-in-place cypher hash-block)
    (setf j0 (if (= (length iv) 12)
                 (concatenate '(vector (unsigned-byte 8))
                              iv
                              (make-array 3 :initial-element 0)
                              '(1))
                  (ghb hash-block #() iv)))
    (setf cyphertext (gcm-ctr key (gcm-inc 32 j0) plaintext)
          s (ghb hash-block additional-authenticated-data cyphertext))
    (list cyphertext (gcm-ctr key j0 s))))

(defun gcm-decrypt (key iv cyphertext additional-authenticated-data tag)
  ;; FIXME: check bitlengths of IV, CYPHERTEXT,
  ;; ADDITIONAL-AUTHENTiCATED-DATA and TAG
  (let ((cypher (crypto:make-cipher :aes :key key :mode :ecb))
         (hash-block (coerce #(0 0 0 0
                               0 0 0 0
                               0 0 0 0
                               0 0 0 0)
                             '(vector (unsigned-byte 8))))
         j0
         plaintext
         s)
    (crypto:encrypt-in-place cypher hash-block)
    (setf j0 (if (= (length iv) 12)
                 (concatenate '(vector (unsigned-byte 8))
                              iv
                              (make-array 3 :initial-element 0)
                              '(1))
                  (ghb hash-block #() iv)))
    (setf plaintext (gcm-ctr key (gcm-inc 32 j0) cyphertext)
          s (ghb hash-block additional-authenticated-data cyphertext))
    (if (equalp tag (gcm-ctr key j0 s))
        plaintext
        'fail)))

(defvar +gcm-test-vectors+
  '((:case 1
      :key #(0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0)
      :initialization-vector  #(0 0 0 0 0 0 0 0 0 0 0 0)
      :plaintext #()
      :additional-authenticated-data #()
      :cyphertext #()
      :tag #(88 226 252 206 250 126 48 97 54 127 29 87 164 231 69 90))
    (:case 2
      :key #(0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0)
      :initialization-vector  #(0 0 0 0 0 0 0 0 0 0 0 0)
      :plaintext #(0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0)
      :additional-authenticated-data #()
      :cyphertext #(3 136 218 206 96 182 163 146 243 40 194 185 113 178 254 120)
      :tag #(171 110 71 212 44 236 19 189 245 58 103 178 18 87 189 223))
    (:case 3
      :key #(254 255 233 146 134 101 115 28 109 106 143 148 103 48 131 8)
      :initialization-vector #(202 254 186 190 250 206 219 173 222 202 248 136)
      :plaintext #(217 49 50 37 248 132 6 229 165 89 9 197 175 245 38 154 134 167 169 83 21 52 247 218 46 76 48 61 138 49 138 114 28 60 12 149 149 104 9 83 47 207 14 36 73 166 181 37 177 106 237 245 170 13 230 87 186 99 123 57 26 175 210 85)
      :additional-authenticated-data #()
      :cyphertext #(66 131 30 194 33 119 116 36 75 114 33 183 132 208 212 156 227 170 33 47 44 2 164 224 53 193 126 35 41 172 161 46 33 213 20 178 84 102 147 28 125 143 106 90 172 132 170 5 27 163 11 57 106 10 172 151 61 88 224 145 71 63 89 133)
      :tag #(77 92 42 243 39 205 100 166 44 243 90 189 43 166 250 180))
    (:case 4
      :key #(254 255 233 146 134 101 115 28 109 106 143 148 103 48 131 8)
      :initialization-vector #(202 254 186 190 250 206 219 173 222 202 248 136)
      :plaintext #(217 49 50 37 248 132 6 229 165 89 9 197 175 245 38 154 134 167 169 83 21 52 247 218 46 76 48 61 138 49 138 114 28 60 12 149 149 104 9 83 47 207 14 36 73 166 181 37 177 106 237 245 170 13 230 87 186 99 123 57)
      :additional-authenticated-data #(254 237 250 206 222 173 190 239 254 237 250 206 222 173 190 239 171 173 218
  210)
      :cyphertext #(66 131 30 194 33 119 116 36 75 114 33 183 132 208 212 156 227 170 33 47 44 2 164 224 53 193 126 35 41 172 161 46 33 213 20 178 84 102 147 28 125 143 106 90 172 132 170 5 27 163 11 57 106 10 172 151 61 88 224 145)
      :tag #(91 201 79 188 50 33 165 219 148 250 233 90 231 18 26 71))
    (:case 5
      :key #(254 255 233 146 134 101 115 28 109 106 143 148 103 48 131 8)
      :initialization-vector #(202 254 186 190 250 206 219 173)
      :plaintext #(217 49 50 37 248 132 6 229 165 89 9 197 175 245 38 154 134 167 169 83 21 52 247 218 46 76 48 61 138 49 138 114 28 60 12 149 149 104 9 83 47 207 14 36 73 166 181 37 177 106 237 245 170 13 230 87 186 99 123 57)
      :additional-authenticated-data #(254 237 250 206 222 173 190 239 254 237 250 206 222 173 190 239 171 173 218 210)
      :cyphertext #(97 53 59 76 40 6 147 74 119 127 245 31 162 42 71 85 105 155 42 113 79 205 198 248 55 102 229 249 123 108 116 35 115 128 105 0 228 159 36 178 43 9 117 68 212 137 107 66 73 137 181 225 235 172 15 7 194 63 69 152)
      :tag #(54 18 210 231 158 59 7 133 86 27 225 74 172 162 252 203))
    (:case 6
      :key #(254 255 233 146 134 101 115 28 109 106 143 148 103 48 131 8)
      :initialization-vector #(147 19 34 93 248 132 6 229 85 144 156 90 255 82 105 170 106 122 149 56 83 79 125 161 228 195 3 210 163 24 167 40 195 192 201 81 86 128 149 57 252 240 226 66 154 107 82 84 22 174 219 245 160 222 106 87 166 55 179 155)
      :plaintext #(217 49 50 37 248 132 6 229 165 89 9 197 175 245 38 154 134 167 169 83 21 52 247 218 46 76 48 61 138 49 138 114 28 60 12 149 149 104 9 83 47 207 14 36 73 166 181 37 177 106 237 245 170 13 230 87 186 99 123 57)
      :additional-authenticated-data #(254 237 250 206 222 173 190 239 254 237 250 206 222 173 190 239 171 173 218 210)
      :cyphertext #(140 226 73 152 98 86 21 182 3 160 51 172 161 63 184 148 190 145 18 165 195 162 17 168 186 38 42 60 202 126 44 167 1 228 169 164 251 164 60 144 204 220 178 129 212 140 124 111 214 40 117 210 172 164 23 3 76 52 174 229)
      :tag #(97 156 197 174 255 254 11 250 70 42 244 60 22 153 208 80))
    (:case 7
      :key #(0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0)
      :initialization-vector #(0 0 0 0 0 0 0 0 0 0 0 0)
      :plaintext #()
      :additional-authenticated-data #()
      :cyphertext #()
      :tag #(205 51 178 138 199 115 247 75 160 14 209 243 18 87 36 53))
    (:case 8
      :key #(0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0)
      :initialization-vector #(0 0 0 0 0 0 0 0 0 0 0 0)
      :plaintext #(0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0)
      :additional-authenticated-data #()
      :cyphertext #(152 231 36 124 7 240 254 65 28 38 126 67 132 176 246 0)
      :tag #(47 245 141 128 3 57 39 171 142 244 212 88 117 20 240 251))
    (:case 9
      :key #(254 255 233 146 134 101 115 28 109 106 143 148 103 48 131 8 254 255 233 146 134 101 115 28)
      :initialization-vector #(202 254 186 190 250 206 219 173 222 202 248 136)
      :plaintext #(217 49 50 37 248 132 6 229 165 89 9 197 175 245 38 154 134 167 169 83 21 52 247 218 46 76 48 61 138 49 138 114 28 60 12 149 149 104 9 83 47 207 14 36 73 166 181 37 177 106 237 245 170 13 230 87 186 99 123 57 26 175 210 85)
      :additional-authenticated-data #()
      :cyphertext #(57 128 202 11 60 0 232 65 235 6 250 196 135 42 39 87 133 158 28 234 166 239 217 132 98 133 147 180 12 161 225 156 125 119 61 0 193 68 197 37 172 97 157 24 200 74 63 71 24 226 68 139 47 227 36 217 204 218 39 16 172 173 226 86)
      :tag #(153 36 167 200 88 115 54 191 177 24 2 77 184 103 74 20))
    (:case 10
      :key #(254 255 233 146 134 101 115 28 109 106 143 148 103 48 131 8 254 255 233 146 134 101 115 28)
      :initialization-vector #(202 254 186 190 250 206 219 173 222 202 248 136)
      :plaintext #(217 49 50 37 248 132 6 229 165 89 9 197 175 245 38 154 134 167 169 83 21 52 247 218 46 76 48 61 138 49 138 114 28 60 12 149 149 104 9 83 47 207 14 36 73 166 181 37 177 106 237 245 170 13 230 87 186 99 123 57)
      :additional-authenticated-data #(254 237 250 206 222 173 190 239 254 237 250 206 222 173 190 239 171 173 218 210)
      :cyphertext #(57 128 202 11 60 0 232 65 235 6 250 196 135 42 39 87 133 158 28 234 166 239 217 132 98 133 147 180 12 161 225 156 125 119 61 0 193 68 197 37 172 97 157 24 200 74 63 71 24 226 68 139 47 227 36 217 204 218 39 16)
      :tag #(37 25 73 142 128 241 71 143 55 186 85 189 109 39 97 140))
    (:case 11
      :key #(254 255 233 146 134 101 115 28 109 106 143 148 103 48 131 8 254 255 233 146 134 101 115 28)
      :initialization-vector #(202 254 186 190 250 206 219 173)
      :plaintext #(217 49 50 37 248 132 6 229 165 89 9 197 175 245 38 154 134 167 169 83 21 52 247 218 46 76 48 61 138 49 138 114 28 60 12 149 149 104 9 83 47 207 14 36 73 166 181 37 177 106 237 245 170 13 230 87 186 99 123 57)
      :additional-authenticated-data #(254 237 250 206 222 173 190 239 254 237 250 206 222 173 190 239 171 173 218 210)
      :cyphertext #(15 16 245 153 174 20 161 84 237 36 179 110 37 50 77 184 197 102 99 46 242 187 179 79 131 71 40 15 196 80 112 87 253 220 41 223 154 71 31 117 198 101 65 212 212 218 209 201 233 58 25 165 142 139 71 63 160 240 98 247)
      :tag #(101 220 197 127 207 98 58 36 9 79 204 164 13 53 51 248))
    (:case 12
      :key #(254 255 233 146 134 101 115 28 109 106 143 148 103 48 131 8 254 255 233 146 134 101 115 28)
      :initialization-vector #(147 19 34 93 248 132 6 229 85 144 156 90 255 82 105 170 106 122 149 56 83 79 125 161 228 195 3 210 163 24 167 40 195 192 201 81 86 128 149 57 252 240 226 66 154 107 82 84 22 174 219 245 160 222 106 87 166 55 179 155)
      :plaintext #(217 49 50 37 248 132 6 229 165 89 9 197 175 245 38 154 134 167 169 83 21 52 247 218 46 76 48 61 138 49 138 114 28 60 12 149 149 104 9 83 47 207 14 36 73 166 181 37 177 106 237 245 170 13 230 87 186 99 123 57)
      :additional-authenticated-data #(254 237 250 206 222 173 190 239 254 237 250 206 222 173 190 239 171 173 218 210)
      :cyphertext #(210 126 136 104 28 227 36 60 72 48 22 90 143 220 249 255 29 233 161 216 230 180 71 239 110 247 183 152 40 102 110 69 129 231 144 18 175 52 221 217 226 240 55 88 155 41 45 179 230 124 3 103 69 250 34 231 233 183 55 59)
      :tag #(220 245 102 255 41 28 37 187 184 86 143 195 211 118 166 217))
    (:case 13
      :key #(0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0)
      :initialization-vector #(0 0 0 0 0 0 0 0 0 0 0 0)
      :plaintext #()
      :additional-authenticated-data #()
      :cyphertext #()
      :tag #(83 15 138 251 199 69 54 185 169 99 180 241 196 203 115 139))
    (:case 14
      :key #(0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0)
      :initialization-vector #(0 0 0 0 0 0 0 0 0 0 0 0)
      :plaintext #(0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0)
      :additional-authenticated-data #()
      :cyphertext #(206 167 64 61 77 96 107 110 7 78 197 211 186 243 157 24)
      :tag #(208 209 200 167 153 153 107 240 38 91 152 181 212 138 185 25))
    (:case 15
      :key #(254 255 233 146 134 101 115 28 109 106 143 148 103 48 131 8 254 255 233 146 134 101 115 28 109 106 143 148 103 48 131 8)
      :initialization-vector #(202 254 186 190 250 206 219 173 222 202 248 136)
      :plaintext #(217 49 50 37 248 132 6 229 165 89 9 197 175 245 38 154 134 167 169 83 21 52 247 218 46 76 48 61 138 49 138 114 28 60 12 149 149 104 9 83 47 207 14 36 73 166 181 37 177 106 237 245 170 13 230 87 186 99 123 57 26 175 210 85)
      :additional-authenticated-data #()
      :cyphertext #(82 45 193 240 153 86 125 7 244 127 55 163 42 132 66 125 100 58 140 220 191 229 192 201 117 152 162 189 37 85 209 170 140 176 142 72 89 13 187 61 167 176 139 16 86 130 136 56 197 246 30 99 147 186 122 10 188 201 246 98 137 128 21 173)
      :tag #(176 148 218 197 217 52 113 189 236 26 80 34 112 227 204 108))
    (:case 16
      :key #(254 255 233 146 134 101 115 28 109 106 143 148 103 48 131 8 254 255 233 146 134 101 115 28 109 106 143 148 103 48 131 8)
      :initialization-vector #(202 254 186 190 250 206 219 173 222 202 248 136)
      :plaintext #(217 49 50 37 248 132 6 229 165 89 9 197 175 245 38 154 134 167 169 83 21 52 247 218 46 76 48 61 138 49 138 114 28 60 12 149 149 104 9 83 47 207 14 36 73 166 181 37 177 106 237 245 170 13 230 87 186 99 123 57)
      :additional-authenticated-data #(254 237 250 206 222 173 190 239 254 237 250 206 222 173 190 239 171 173 218 210)
      :cyphertext #(82 45 193 240 153 86 125 7 244 127 55 163 42 132 66 125 100 58 140 220 191 229 192 201 117 152 162 189 37 85 209 170 140 176 142 72 89 13 187 61 167 176 139 16 86 130 136 56 197 246 30 99 147 186 122 10 188 201 246 98)
      :tag #(118 252 110 206 15 78 23 104 205 223 136 83 187 45 85 27))
    (:case 17
      :key #(254 255 233 146 134 101 115 28 109 106 143 148 103 48 131 8 254 255 233 146 134 101 115 28 109 106 143 148 103 48 131 8)
      :initialization-vector #(202 254 186 190 250 206 219 173)
      :plaintext #(217 49 50 37 248 132 6 229 165 89 9 197 175 245 38 154 134 167 169 83 21 52 247 218 46 76 48 61 138 49 138 114 28 60 12 149 149 104 9 83 47 207 14 36 73 166 181 37 177 106 237 245 170 13 230 87 186 99 123 57)
      :additional-authenticated-data #(254 237 250 206 222 173 190 239 254 237 250 206 222 173 190 239 171 173 218 210)
      :cyphertext #(195 118 45 241 202 120 125 50 174 71 193 59 241 152 68 203 175 26 225 77 11 151 106 250 197 47 247 215 155 186 157 224 254 181 130 211 57 52 164 240 149 76 194 54 59 199 63 120 98 172 67 14 100 171 228 153 244 124 155 31)
      :tag #(58 51 125 191 70 167 146 196 94 69 73 19 254 46 168 242))
    (:case 18
      :key #(254 255 233 146 134 101 115 28 109 106 143 148 103 48 131 8 254 255 233 146 134 101 115 28 109 106 143 148 103 48 131 8)
      :initialization-vector #(147 19 34 93 248 132 6 229 85 144 156 90 255 82 105 170 106 122 149 56 83 79 125 161 228 195 3 210 163 24 167 40 195 192 201 81 86 128 149 57 252 240 226 66 154 107 82 84 22 174 219 245 160 222 106 87 166 55 179 155)
      :plaintext #(217 49 50 37 248 132 6 229 165 89 9 197 175 245 38 154 134 167 169 83 21 52 247 218 46 76 48 61 138 49 138 114 28 60 12 149 149 104 9 83 47 207 14 36 73 166 181 37 177 106 237 245 170 13 230 87 186 99 123 57)
      :additional-authenticated-data #(254 237 250 206 222 173 190 239 254 237 250 206 222 173 190 239 171 173 218 210)
      :cyphertext #(90 141 239 47 12 158 83 241 247 93 120 83 101 158 42 32 238 178 178 42 175 222 100 25 160 88 171 79 111 116 107 244 15 192 195 183 128 242 68 69 45 163 235 241 197 216 44 222 162 65 137 151 32 14 248 46 68 174 126 63)
      :tag #(164 74 130 102 238 28 142 176 200 181 212 207 90 233 241 154))))

(defclass gcm-state ()
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

(defun make-gcm-cipher (name &key key initialization-vector)
  (make-instance 'gcm-state
                 :key key
                 :initialization-vector initialization-vector
                 :cipher name))

(defun encrypt (cipher plaintext ciphertext
                &key
                (plaintext-start 0)
                (plaintext-end nil)
                (ciphertext-start 0))
  (unless plaintext-end
    (setf plaintext-end (length plaintext)))
  (destructuring-bind (actual-ciphertext tag)
      (gcm-encrypt (key cipher)
                   (initialization-vector cipher)
                   (subseq plaintext plaintext-start plaintext-end)
                   (authenticated-data cipher))
    (setf (subseq ciphertext
                  ciphertext-start
                  (+ ciphertext-start (- plaintext-end plaintext-start)))
          actual-ciphertext
          (tag cipher)
          tag)))

(define-condition gcm-authentication-failed (error) ())

(defun decrypt (cipher ciphertext plaintext
                &key
                (ciphertext-start 0)
                (ciphertext-end nil)
                (plaintext-start 0))
  (unless (tag cipher)
    (error "All GCM ciphers must have a tag in order to decrypt"))
  (unless ciphertext-end
    (setf ciphertext-end (length ciphertext)))
  (let ((result
         (gcm-decrypt (key cipher)
                      (initialization-vector cipher)
                      (subseq ciphertext ciphertext-start ciphertext-end)
                      (authenticated-data cipher)
                      (tag cipher))))
    (when (eq result 'fail)
      (error 'gcm-authentication-failed))
    (setf (subseq plaintext plaintext-start (+ plaintext-start
                                               (- ciphertext-end
                                                  ciphertext-start)))
          result)))

(defun gcm-run-tests ()
  (loop for case in +gcm-test-vectors+
     with *print-base* = 16
     do (destructuring-bind (&key case key initialization-vector
                                  plaintext additional-authenticated-data
                                  cyphertext
                                  tag)
            case
          (let ((cypher (make-gcm-cipher :aes
                                         :key (coerce key '(vector (unsigned-byte 8)))
                                         :initialization-vector (coerce initialization-vector  '(vector (unsigned-byte 8)))))
                (plaintext (coerce plaintext '(vector (unsigned-byte 8))))
                (cyphertext (coerce cyphertext '(vector (unsigned-byte 8))))
                (tag (coerce tag '(vector (unsigned-byte 8))))
                (actual-cyphertext (make-array (length plaintext)
                                               :element-type '(unsigned-byte 8)))
                (actual-plaintext (make-array (length plaintext)
                                              :element-type '(unsigned-byte 8))))
            (setf (authenticated-data cypher)
                  (coerce additional-authenticated-data
                          '(vector (unsigned-byte 8))))
            (format t "Case ~d..." case)
            (encrypt cypher plaintext actual-cyphertext)
            (unless (equalp cyphertext actual-cyphertext)
              (error "cyphertext is incorrect"))
            (unless (equalp tag (tag cypher))
              (error "tag is incorrect: ~a~&  ~a" (tag cypher) tag))
            (decrypt cypher actual-cyphertext actual-plaintext)
            (unless (equalp plaintext
                            actual-plaintext)
              (error "decryption failed ~a ~a" actual-plaintext plaintext))
            ;; test a flipped bit
            (when (plusp (length cyphertext))
              (let ((octet-index (crypto:strong-random (length cyphertext)))
                    (bit-index (crypto:strong-random 8)))
                (setf (aref cyphertext octet-index)
                      (logandc1 (aref cyphertext octet-index)
                                (ash 1 bit-index)))
                (handler-case
                    (decrypt cypher cyphertext actual-plaintext)
                  (:no-error (value)
                    (declare (ignorable value))
                    (error "tag authenticated mangled cyphertext: ~a~&  ~a"
                           actual-cyphertext cyphertext)))))
            (format t "passed~&")))))

(in-package :crypto)

(defun gcm-encrypt (key iv plaintext additional-authenticated-data)
  (assert (and
           (<= (length plaintext) +gcm-plaintext-length-max+)
           (<= (length additional-authenticated-data)
               +gcm-additional-authenthicated-data-length-max+)
           (<= 1 (length iv) +gcm-initialization-vector-length-max+)))
  (let* ((cypher (crypto:make-cipher :aes :key key :mode :ecb))
         (hash-block (coerce #(0 0 0 0
                               0 0 0 0
                               0 0 0 0
                               0 0 0 0)
                             '(vector (unsigned-byte 8))))
         j0
         cyphertext
         s)
    (crypto:encrypt-in-place cypher hash-block)
    (setf j0 (if (= (length iv) 12)
                 (concatenate '(vector (unsigned-byte 8))
                              iv
                              (make-array 3 :initial-element 0)
                              '(1))
                  (ghb hash-block #() iv)))
    (setf cyphertext (gcm-ctr key (gcm-inc 32 j0) plaintext)
          s (ghb hash-block additional-authenticated-data cyphertext))
    (list cyphertext (gcm-ctr key j0 s))))

(defun gcm-decrypt (key iv cyphertext additional-authenticated-data tag)
  ;; FIXME: check bitlengths of IV, CYPHERTEXT,
  ;; ADDITIONAL-AUTHENTiCATED-DATA and TAG
  (let ((cypher (crypto:make-cipher :aes :key key :mode :ecb))
         (hash-block (coerce #(0 0 0 0
                               0 0 0 0
                               0 0 0 0
                               0 0 0 0)
                             '(vector (unsigned-byte 8))))
         j0
         plaintext
         s)
    (crypto:encrypt-in-place cypher hash-block)
    (setf j0 (if (= (length iv) 12)
                 (concatenate '(vector (unsigned-byte 8))
                              iv
                              (make-array 3 :initial-element 0)
                              '(1))
                  (ghb hash-block #() iv)))
    (setf plaintext (gcm-ctr key (gcm-inc 32 j0) cyphertext)
          s (ghb hash-block additional-authenticated-data cyphertext))
    (if (equalp tag (gcm-ctr key j0 s))
        plaintext
        'fail)))

(defclass gcm (authenticated-mode) ())

(defmode gcm
  (:encrypt-function gcm-encrypt)
  (:decrypt-function gcm-decrypt))
