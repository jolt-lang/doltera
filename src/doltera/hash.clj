(ns doltera.hash
  "Pure-jolt SHA-1 (FIPS 180-1 / RFC 3174), needed for MySQL
  mysql_native_password auth. 32-bit words live in Clojure longs masked to
  0xffffffff; every shift operates on a masked value so the arithmetic right
  shift never sign-extends."
  (:require [doltera.wire :as w]))

(def ^:private m32 0xffffffff)

(defn- rol [x n]
  (bit-and (bit-or (bit-shift-left (bit-and x m32) n)
                   (bit-shift-right x (- 32 n)))
           m32))

(defn- w+ [& xs]
  (bit-and (reduce + xs) m32))

(defn- pad-message [bytes]
  (let [len (count bytes)
        bitlen (* 8 len)
        total (+ 8 (loop [l (inc len)]
                    (if (zero? (bit-and (- l 56) 63)) l (recur (inc l)))))
        out (byte-array total)]
    (dotimes [i len] (aset out i (aget bytes i)))
    (aset out len 0x80)
    (dotimes [i 8]
      (aset out (- total 1 i) (bit-and (bit-shift-right bitlen (* 8 i)) 0xff)))
    out))

(defn- sha1-block [h block]
  (let [w (loop [i 0, w (vec (repeat 80 0))]
            (if (< i 16)
              (recur (inc i)
                     (assoc w i
                            (bit-or (bit-shift-left (bit-and (aget block (* i 4)) 0xff) 24)
                                    (bit-shift-left (bit-and (aget block (inc (* i 4))) 0xff) 16)
                                    (bit-shift-left (bit-and (aget block (+ 2 (* i 4))) 0xff) 8)
                                    (bit-and (aget block (+ 3 (* i 4))) 0xff))))
              (if (< i 80)
                (recur (inc i)
                       (assoc w i (rol (bit-xor (w (- i 3)) (w (- i 8)) (w (- i 14)) (w (- i 16))) 1)))
                w)))
        [a0 b0 c0 d0 e0] h
        [a b c d e] (loop [i 0, [a b c d e] [a0 b0 c0 d0 e0]]
                      (if (< i 80)
                        (let [f (cond (< i 20) (bit-or (bit-and b c) (bit-and (bit-not b) d))
                                      (< i 40) (bit-xor b c d)
                                      (< i 60) (bit-or (bit-or (bit-and b c) (bit-and b d))
                                                       (bit-and c d))
                                      :else (bit-xor b c d))
                              k (cond (< i 20) 0x5a827999
                                      (< i 40) 0x6ed9eba1
                                      (< i 60) 0x8f1bbcdc
                                      :else 0xca62c1d6)
                              t (w+ (rol a 5) f e k (w i))]
                          (recur (inc i) [t a (rol b 30) c d]))
                        [a b c d e]))]
    [(w+ a0 a) (w+ b0 b) (w+ c0 c) (w+ d0 d) (w+ e0 e)]))

(defn sha1-bytes
  "SHA-1 digest of a byte array, as a 20-byte array."
  [bytes]
  (let [padded (pad-message bytes)
        nblocks (quot (count padded) 64)
        final (loop [i 0, h [0x67452301 0xefcdab89 0x98badcfe 0x10325476 0xc3d2e1f0]]
                (if (< i nblocks)
                  (recur (inc i) (sha1-block h (w/sub-ba padded (* i 64) 64)))
                  h))]
    (byte-array (mapcat (fn [word]
                          [(bit-and (bit-shift-right word 24) 0xff)
                           (bit-and (bit-shift-right word 16) 0xff)
                           (bit-and (bit-shift-right word 8) 0xff)
                           (bit-and word 0xff)])
                        final))))

(defn sha1-hex [bytes]
  (w/hex (sha1-bytes bytes)))
