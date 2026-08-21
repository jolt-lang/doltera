(ns doltera.wire
  "MySQL wire byte primitives: little-endian ints, length-encoded ints and
  strings, packet payload assembly. Bytes are jolt byte arrays; values 0-255
  are stored raw (aset wraps to signed) and masked on read.")

;; -- basic byte arrays -------------------------------------------------------

(defn signed [v]
  (if (> v 127) (- v 256) v))

(defn ba
  "byte array from byte values (0-255 or signed)."
  [& vs]
  (byte-array (mapv signed vs)))

(defn concat-ba [& arrs]
  (let [total (reduce + (map count arrs))
        out (byte-array total)]
    (loop [off 0, arrs arrs]
      (if (seq arrs)
        (let [a (first arrs)]
          (dotimes [i (count a)] (aset out (+ off i) (aget a i)))
          (recur (+ off (count a)) (rest arrs)))
        out))))

(defn sub-ba [src start n]
  (let [out (byte-array n)]
    (dotimes [i n] (aset out i (aget src (+ start i))))
    out))

(defn hex [b]
  (apply str (map #(format "%02x" (bit-and % 0xff)) (seq b))))

;; -- little-endian readers (unsigned, from offset) ----------------------------

(defn u8 [b off] (bit-and (aget b off) 0xff))
(defn u16 [b off] (bit-or (u8 b off) (bit-shift-left (u8 b (inc off)) 8)))
(defn u24 [b off] (bit-or (u16 b off) (bit-shift-left (u8 b (+ off 2)) 16)))
(defn u32 [b off] (bit-or (u24 b off) (bit-shift-left (u8 b (+ off 3)) 24)))
(defn u64 [b off] (bit-or (u32 b off) (bit-shift-left (u32 b (+ off 4)) 32)))

(defn i8 [b off] (let [v (u8 b off)] (if (> v 127) (- v 256) v)))
(defn i16 [b off] (let [v (u16 b off)] (if (> v 32767) (- v 65536) v)))
(defn i32 [b off] (let [v (u32 b off)] (if (> v 2147483647) (- v 4294967296) v)))
(defn i64 [b off] (u64 b off)) ; bit-shift wraps, giving the signed value

;; -- little-endian writers (as byte arrays) -----------------------------------

(defn w8 [v] (ba (bit-and v 0xff)))
(defn w16 [v] (ba (bit-and v 0xff) (bit-and (bit-shift-right v 8) 0xff)))
(defn w24 [v] (ba (bit-and v 0xff) (bit-and (bit-shift-right v 8) 0xff)
                  (bit-and (bit-shift-right v 16) 0xff)))
(defn w32 [v] (ba (bit-and v 0xff) (bit-and (bit-shift-right v 8) 0xff)
                  (bit-and (bit-shift-right v 16) 0xff)
                  (bit-and (bit-shift-right v 24) 0xff)))
(defn w64 [v] (concat-ba (w32 (bit-and v 0xffffffff)) (w32 (bit-shift-right v 32))))

(defn w-prefix!
  "Write an n-byte little-endian v at offset in place; returns the new offset."
  [b off v n]
  (dotimes [i n] (aset b (+ off i) (bit-and (bit-shift-right v (* 8 i)) 0xff)))
  (+ off n))

;; -- length-encoded (lenenc) ints and strings --------------------------------

(defn lenenc-int-len [v]
  (cond (< v 0xfb) 1 (< v 0x10000) 3 (< v 0x1000000) 4 :else 9))

(defn lenenc-int [v]
  (cond
    (< v 0xfb) (ba v)
    (< v 0x10000) (concat-ba (ba 0xfc) (w16 v))
    (< v 0x1000000) (concat-ba (ba 0xfd) (w24 v))
    :else (concat-ba (ba 0xfe) (w64 v))))

(defn lenenc-bytes [bs]
  (concat-ba (lenenc-int (count bs)) bs))

(defn nul-string [bs]
  (concat-ba bs (ba 0)))

(defn read-lenenc-int [b off]
  (let [x (u8 b off)]
    (cond
      (< x 0xfb) [(long x) (inc off)]
      (= x 0xfc) [(u16 b (inc off)) (+ off 3)]
      (= x 0xfd) [(u24 b (inc off)) (+ off 4)]
      (= x 0xfe) [(u64 b (inc off)) (+ off 9)]
      :else (throw (ex-info (str "invalid lenenc marker " x) {:marker x})))))

(defn read-lenenc-bytes [b off]
  (let [[n off'] (read-lenenc-int b off)]
    [(sub-ba b off' n) (+ off' n)]))

(defn read-nul-bytes [b off]
  (loop [i off]
    (if (or (>= i (count b)) (zero? (u8 b i)))
      [(sub-ba b off (- i off)) (min (inc i) (count b))]
      (recur (inc i)))))

(defn utf8->str [bs]
  (String. bs))
