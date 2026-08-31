(ns doltera.protocol
  "MySQL wire protocol client (text + binary result sets) for dolt sql-server.
  One connection, sequential commands, no pipelining — which is also what lets
  each connection keep a cache of its prepared statements. Auth is
  mysql_native_password (SHA-1 scramble), which dolt's default users use."
  (:require [jolt.socket]
            [jolt.ffi :as ffi]
            [clojure.string :as str]
            [doltera.hash :as hash]
            [doltera.wire :as w]))

;; -- connection ---------------------------------------------------------------

(defn open-conn [host port]
  (let [s (Socket. host port)]
    {:socket s
     :in (.getInputStream s)
     :out (.getOutputStream s)
     :seq (atom 0)
     :stmts (atom {:tick 0 :entries {}})}))

(defn close-conn [conn]
  (.close (:socket conn)))

;; -- packet framing ------------------------------------------------------------

(defn- read-exact! [conn n]
  (let [is (:in conn)
        buf (byte-array n)
        got (loop [off 0]
              (if (>= off n) off
                  (let [r (.read is buf off (- n off))]
                    (if (neg? r) off (recur (+ off r))))))]
    (when (< got n)
      (throw (ex-info (str "connection closed mid-packet (" got "/" n " bytes)")
                      {:type :mysql/closed})))
    buf))

(defn- read-physical [conn]
  (let [hdr (read-exact! conn 4)]
    {:seq (w/u8 hdr 3)
     :len (w/u24 hdr 0)
     :payload (read-exact! conn (w/u24 hdr 0))}))

(defn read-packet [conn]
  (loop [parts [] n 0]
    (let [p (read-physical conn)]
      (if (= (:len p) 0xffffff)
        (recur (conj parts (:payload p)) (+ n 0xffffff))
        {:seq (:seq p)
         :payload (if (seq parts)
                    (apply w/concat-ba (conj parts (:payload p)))
                    (:payload p))}))))

(defn write-packet [conn payload]
  (let [n (count payload)]
    (loop [off 0]
      (let [chunk (min (- n off) 0xffffff)
            hdr (byte-array 4)
            s (let [s @(:seq conn)] (swap! (:seq conn) inc) s)]
        (w/w-prefix! hdr 0 chunk 3)
        (aset hdr 3 s)
        (.write (:out conn) hdr 0 4)
        (when (pos? chunk) (.write (:out conn) payload off chunk))
        ;; a payload that is an exact multiple of the maximum packet size is
        ;; terminated by an empty packet, or the server keeps waiting
        (when (= chunk 0xffffff) (recur (+ off chunk)))))))

(defn send-command [conn cmd payload]
  (reset! (:seq conn) 0)
  (write-packet conn (w/concat-ba (w/ba cmd) payload)))

;; -- OK / ERR / EOF -------------------------------------------------------------

(defn parse-ok [payload]
  (let [[affected off] (w/read-lenenc-int payload 1)
        [insert off] (w/read-lenenc-int payload off)]
    {:affected affected
     :insert-id insert
     :status (w/u16 payload off)
     :warnings (w/u16 payload (+ off 2))}))

(defn parse-err! [payload]
  (let [code (w/u16 payload 1)
        has-state? (= 0x23 (w/u8 payload 3))
        sqlstate (when has-state? (String. payload 4 5))
        msg-off (if has-state? 9 3)
        msg (String. payload msg-off (- (count payload) msg-off))]
    (throw (ex-info (str "SQL error " code (when sqlstate (str " [" sqlstate "]")) ": " msg)
                    {:type :mysql/error :code code :sqlstate sqlstate :message msg}))))

(defn eof? [p]
  (and (= 0xfe (w/u8 (:payload p) 0)) (< (count (:payload p)) 9)))

;; -- handshake ------------------------------------------------------------------

(defn parse-handshake
  "Initial Handshake Packet (protocol version 10). Offsets are relative to the
  end of the NUL-terminated server version string, where the connection id
  starts: +4 auth-plugin-data part 1 (8 bytes), +12 filler, +13 capability
  flags low, +15 charset, +16 status, +18 capability flags high, +20
  auth-plugin-data length, +21 reserved (10 bytes), +31 auth-plugin-data
  part 2, then the NUL-terminated plugin name."
  [payload]
  (let [[ver-bytes ver-end] (w/read-nul-bytes payload 1)
        caps (bit-or (w/u16 payload (+ ver-end 13))
                     (bit-shift-left (w/u16 payload (+ ver-end 18)) 16))
        auth-len (w/u8 payload (+ ver-end 20))
        auth2-len (max 13 (- auth-len 8))
        auth2-start (+ ver-end 31)
        auth1 (w/sub-ba payload (+ ver-end 4) 8)
        auth2 (w/sub-ba payload auth2-start (min auth2-len (- (count payload) auth2-start)))
        nonce (let [n (w/concat-ba auth1 auth2)]
                (if (and (pos? (count n)) (zero? (w/u8 n (dec (count n)))))
                  (w/sub-ba n 0 (dec (count n)))
                  n))
        plugin-start (+ auth2-start auth2-len)]
    {:protocol (w/u8 payload 0)
     :version (String. ver-bytes)
     :conn-id (w/u32 payload ver-end)
     :caps caps
     :charset (w/u8 payload (+ ver-end 15))
     :nonce nonce
     :auth-plugin (when (< plugin-start (count payload))
                    (String. (first (w/read-nul-bytes payload plugin-start))))}))

(defn- client-caps [db?]
  (bit-or 0x1          ; LONG_PASSWORD
          0x4          ; LONG_FLAG
          0x200        ; PROTOCOL_41
          0x2000       ; TRANSACTIONS
          0x8000       ; SECURE_CONNECTION
          0x80000      ; PLUGIN_AUTH
          (if db? 0x8 0))) ; CONNECT_WITH_DB

(defn- mysql-native-scramble [password nonce]
  (if (empty? password)
    (byte-array 0)
    (let [stage1 (hash/sha1-bytes password)
          stage2 (hash/sha1-bytes stage1)
          stage3 (hash/sha1-bytes (w/concat-ba nonce stage2))]
      (byte-array (mapv (fn [a b] (bit-xor a b)) stage1 stage3)))))

(defn auth-switch-plugin
  "Plugin name out of an Auth Switch Request (0xfe) packet."
  [payload]
  (String. (first (w/read-nul-bytes payload 1))))

(defn- unsupported-auth! [plugin]
  (throw (ex-info (str "server wants " plugin " auth; doltera supports only "
                       "mysql_native_password. Create the user with "
                       "IDENTIFIED WITH mysql_native_password.")
                  {:type :mysql/auth :plugin plugin})))

(defn handshake! [conn user password db]
  (let [hs (parse-handshake (:payload (read-packet conn)))
        plugin (or (:auth-plugin hs) "mysql_native_password")]
    (when-not (= "mysql_native_password" plugin)
      (unsupported-auth! plugin))
    (let [caps (bit-and (client-caps (some? db)) (:caps hs))
          auth (mysql-native-scramble (.getBytes password "UTF-8") (:nonce hs))
          parts [(w/w32 caps)
                 (w/w32 0x40000000)
                 (w/ba 45) ; utf8mb4_general_ci; results are decoded as UTF-8
                 (byte-array 23)
                 (.getBytes user "UTF-8")
                 (w/ba 0)
                 (w/ba (count auth))
                 auth
                 (when db (w/concat-ba (.getBytes db "UTF-8") (w/ba 0)))
                 (.getBytes "mysql_native_password" "UTF-8")
                 (w/ba 0)]]
      (reset! (:seq conn) 1)
      (write-packet conn (apply w/concat-ba (remove nil? parts)))
      (let [b (:payload (read-packet conn))
            f (w/u8 b 0)]
        (cond
          (zero? f) (assoc conn :caps caps :server (:version hs) :db db)
          (= f 0xff) (parse-err! b)
          ;; Auth Switch Request: the user is registered with another plugin
          (= f 0xfe) (unsupported-auth! (auth-switch-plugin b))
          :else (throw (ex-info "unexpected auth response"
                                {:type :mysql/auth :first f})))))))

(declare clear-stmt-cache!) ; defined with the statement cache, below

(defn select-db!
  "Switch the working database/repo with `use`. Connecting with :db selects one
  through the handshake; this is for switching afterwards."
  [conn db]
  (let [escaped (clojure.string/replace db "`" "``")
        _ (send-command conn 0x03 (.getBytes (str "use `" escaped "`") "UTF-8"))
        b (:payload (read-packet conn))
        f (w/u8 b 0)]
    (if (= f 0xff)
      (parse-err! b)
      (do
        ;; the cache is keyed by SQL text, which no longer picks out the same
        ;; statement once the database underneath it changes
        (clear-stmt-cache! conn)
        (assoc conn :db db)))))

;; -- columns and rows ------------------------------------------------------------

(defn parse-column [payload]
  (let [[_ off] (w/read-lenenc-bytes payload 0)   ; catalog
        [_ off] (w/read-lenenc-bytes payload off) ; schema
        [_ off] (w/read-lenenc-bytes payload off) ; table
        [_ off] (w/read-lenenc-bytes payload off) ; org-table
        [name off] (w/read-lenenc-bytes payload off)
        [_ off] (w/read-lenenc-bytes payload off) ; org-name
        charset (w/u16 payload (+ off 1))
        len (w/u32 payload (+ off 3))
        type (w/u8 payload (+ off 7))
        flags (w/u16 payload (+ off 8))
        decimals (w/u8 payload (+ off 10))]
    {:name (w/utf8->str name)
     :type type
     :charset charset
     :length len
     :flags flags
     :decimals decimals}))

(defn- row-map [cols vals]
  (zipmap (map #(keyword (:name %)) cols) vals))

(defn parse-text-row [payload cols]
  (loop [off 0, i 0, row []]
    (if (= i (count cols))
      (row-map cols row)
      (let [b (w/u8 payload off)]
        (if (= b 0xfb)
          (recur (inc off) (inc i) (conj row nil))
          (let [[bs off'] (w/read-lenenc-bytes payload off)]
            (recur off' (inc i) (conj row (w/utf8->str bs)))))))))

;; -- binary values (prepared statements) -----------------------------------------

(defn- bytes->double [b off]
  (let [p (ffi/alloc 8)]
    (try
      (dotimes [i 8] (ffi/write p :uint8 (w/u8 b (+ off i)) i))
      (ffi/read p :double 0)
      (finally (ffi/free p)))))

(defn- bytes->float [b off]
  (let [p (ffi/alloc 4)]
    (try
      (dotimes [i 4] (ffi/write p :uint8 (w/u8 b (+ off i)) i))
      (ffi/read p :float 0)
      (finally (ffi/free p)))))

(defn- bytes-of-double [v]
  (let [p (ffi/alloc 8)]
    (try
      (ffi/write p :double v 0)
      (byte-array (mapv #(ffi/read p :uint8 %) (range 8)))
      (finally (ffi/free p)))))

(def ^:private unsigned-flag 0x20)
(def ^:private binary-charset 63)
(def ^:private two-64 18446744073709551616)

;; VARCHAR, TINY/MEDIUM/LONG/BLOB, VAR_STRING, STRING and GEOMETRY. Carrying the
;; binary charset makes them BINARY/VARBINARY/BLOB rather than text.
(def ^:private string-types #{15 249 250 251 252 253 254 255})

(defn- unsigned? [col]
  (pos? (bit-and (:flags col) unsigned-flag)))

(defn- frac
  "Fractional-seconds suffix. A column with a declared precision always shows it;
  otherwise microseconds only appear when there are some."
  [micros decimals]
  (cond
    (pos? decimals) (str "." (subs (format "%06d" micros) 0 (min 6 decimals)))
    (pos? micros) (str "." (format "%06d" micros))
    :else ""))

(defn- decode-datetime [b off decimals]
  (let [len (w/u8 b off)]
    (if (zero? len)
      [nil (inc off)]
      (let [off' (inc off)
            year (w/u16 b off')
            date (format "%04d-%02d-%02d" year (w/u8 b (+ off' 2)) (w/u8 b (+ off' 3)))]
        (if (= len 4)
          [date (+ off' 4)]
          (let [clock (format "%s %02d:%02d:%02d" date
                              (w/u8 b (+ off' 4)) (w/u8 b (+ off' 5)) (w/u8 b (+ off' 6)))]
            (if (= len 7)
              [(str clock (frac 0 decimals)) (+ off' 7)]
              [(str clock (frac (w/u32 b (+ off' 7)) decimals)) (+ off' 11)])))))))

(defn- decode-time [b off decimals]
  (let [len (w/u8 b off)]
    (if (zero? len)
      [nil (inc off)]
      (let [off' (inc off)
            neg (w/u8 b off')
            days (w/u32 b (+ off' 1))
            clock (format "%s%02d:%02d:%02d" (if (pos? neg) "-" "")
                          (+ (* days 24) (w/u8 b (+ off' 5)))
                          (w/u8 b (+ off' 6)) (w/u8 b (+ off' 7)))]
        (if (= len 8)
          [(str clock (frac 0 decimals)) (+ off' 8)]
          [(str clock (frac (w/u32 b (+ off' 8)) decimals)) (+ off' 12)])))))

(defn- decode-bit
  "BIT arrives as a length-encoded big-endian byte string."
  [b off]
  (let [[bs off'] (w/read-lenenc-bytes b off)]
    [(reduce (fn [acc i] (+ (* acc 256) (w/u8 bs i))) 0 (range (count bs))) off']))

(defn- decode-binary-value [b off col]
  (let [type (:type col)
        uns (unsigned? col)]
    (case type
      1  [(if uns (w/u8 b off) (w/i8 b off)) (inc off)]     ; TINY
      2  [(if uns (w/u16 b off) (w/i16 b off)) (+ off 2)]   ; SHORT
      3  [(if uns (w/u32 b off) (w/i32 b off)) (+ off 4)]   ; LONG
      4  [(bytes->float b off) (+ off 4)]                   ; FLOAT
      5  [(bytes->double b off) (+ off 8)]                  ; DOUBLE
      6  [nil off]                                          ; NULL
      8  [(let [v (w/i64 b off)]                            ; LONGLONG
            (if (and uns (neg? v)) (+ v two-64) v))
          (+ off 8)]
      9  [(if uns (w/u32 b off) (w/i32 b off)) (+ off 4)]   ; INT24
      13 [(w/u16 b off) (+ off 2)]                          ; YEAR
      16 (decode-bit b off)                                 ; BIT
      7  (decode-datetime b off (:decimals col))            ; TIMESTAMP
      10 (decode-datetime b off (:decimals col))            ; DATE
      11 (decode-time b off (:decimals col))                ; TIME
      12 (decode-datetime b off (:decimals col))            ; DATETIME
      ;; Everything left is length-encoded bytes: BINARY/VARBINARY/BLOB keep
      ;; their bytes, and the rest — string literals, JSON, decimals, enums —
      ;; decode as text.
      (let [[bs off'] (w/read-lenenc-bytes b off)]
        [(if (and (= binary-charset (:charset col)) (contains? string-types type))
           bs
           (w/utf8->str bs))
         off']))))

(defn parse-binary-row [payload cols]
  (let [n (count cols)
        blen (quot (+ n 7 2) 8)
        [vals _] (loop [i 0, off (+ 1 blen), vals []]
                   (if (= i n)
                     [vals off]
                     (if (bit-test (w/u8 payload (+ 1 (quot (+ i 2) 8))) (mod (+ i 2) 8))
                       (recur (inc i) off (conj vals nil))
                       (let [[v off'] (decode-binary-value payload off (nth cols i))]
                         (recur (inc i) off' (conj vals v))))))]
    (row-map cols vals)))

;; -- result sets -------------------------------------------------------------------

(defn read-result [conn binary?]
  (let [p (read-packet conn)
        b (:payload p)
        f (w/u8 b 0)]
    (cond
      (zero? f) (parse-ok b)
      (= f 0xff) (parse-err! b)
      (= f 0xfb) (throw (ex-info "LOCAL INFILE unsupported" {:type :mysql/local-infile}))
      :else (let [[ncol _] (w/read-lenenc-int b 0)
                  cols (loop [i 0, cs []]
                         (if (< i ncol)
                           (let [cp (read-packet conn)]
                             (recur (inc i) (conj cs (parse-column (:payload cp)))))
                           cs))]
              (when (pos? ncol) (read-packet conn)) ; column EOF
              (let [rows (loop [rs []]
                           (let [rp (read-packet conn)]
                             (if (eof? rp)
                               rs
                               (recur (conj rs (if binary?
                                                 (parse-binary-row (:payload rp) cols)
                                                 (parse-text-row (:payload rp) cols)))))))]
                {:columns cols :rows rows})))))

;; -- commands -----------------------------------------------------------------------

(defn query-text [conn sql]
  (send-command conn 0x03 (.getBytes sql "UTF-8"))
  (read-result conn false))

;; -- prepared statements -------------------------------------------------------------

(defn prepare-stmt [conn sql]
  (send-command conn 0x16 (.getBytes sql "UTF-8"))
  (let [b (:payload (read-packet conn))]
    (if (= 0xff (w/u8 b 0))
      (parse-err! b)
      (let [stmt-id (w/u32 b 1)
            ncols (w/u16 b 5)
            nparams (w/u16 b 7)
            params (when (pos? nparams)
                     (let [ps (loop [i 0, ps []]
                                (if (< i nparams)
                                  (let [pp (read-packet conn)]
                                    (recur (inc i) (conj ps (parse-column (:payload pp)))))
                                  ps))]
                       (read-packet conn) ; params EOF
                       ps))
            cols (when (pos? ncols)
                   (let [cs (loop [i 0, cs []]
                              (if (< i ncols)
                                (let [cp (read-packet conn)]
                                  (recur (inc i) (conj cs (parse-column (:payload cp)))))
                                cs))]
                     (read-packet conn) ; column EOF
                     cs))]
        {:stmt-id stmt-id :columns cols :params params}))))


(defn- param-type-value [v]
  (cond
    (nil? v) [(w/w16 0x06) (byte-array 0)]                       ; NULL
    (instance? Boolean v) [(w/w16 0x01) (w/ba (if v 1 0))]       ; TINY
    (integer? v) [(w/w16 0x08) (w/w64 v)]                        ; LONGLONG
    (float? v) [(w/w16 0x05) (bytes-of-double v)]                 ; DOUBLE
    (bytes? v) [(w/w16 0xfc) (w/lenenc-bytes v)]                  ; BLOB
    :else [(w/w16 0x0f) (w/lenenc-bytes (.getBytes (str v) "UTF-8"))])) ; VARCHAR

(defn execute-stmt [conn {:keys [stmt-id]} params]
  (let [n (count params)
        bitmap (byte-array (quot (+ n 7) 8))
        tyvals (mapv param-type-value params)]
    (dotimes [i n]
      (when (nil? (nth params i))
        (aset bitmap (quot i 8) (bit-or (aget bitmap (quot i 8)) (bit-shift-left 1 (mod i 8))))))
    (send-command conn 0x17
                  (apply w/concat-ba
                         [(w/w32 stmt-id) (w/ba 0) (w/w32 1) bitmap (w/ba 1)
                          (apply w/concat-ba (map first tyvals))
                          (apply w/concat-ba (map second tyvals))]))
    (read-result conn true)))

(defn close-stmt [conn stmt-id]
  (send-command conn 0x19 (w/w32 stmt-id)))


;; -- prepared statement cache ----------------------------------------------------

(def ^:private max-cached-stmts
  "Prepared statements kept open per connection. The server has its own ceiling
  (max_prepared_stmt_count, 16382 on dolt); this one bounds a caller that builds
  a fresh SQL string for every query."
  64)

(def ^:private unknown-stmt-errors
  "What a server answers with when asked to execute a handle it doesn't have:
  2014 from dolt, 1243 (ER_UNKNOWN_STMT_HANDLER) from MySQL."
  #{1243 2014})

(def ^:private evict-batch
  "How many statements to drop when the cache overflows. Evicting a batch means
  ranking the entries once every evict-batch inserts instead of hunting for a
  single victim on each one, which matters for a caller whose SQL is never the
  same twice and so always misses."
  16)

(defn- lru-sqls [entries]
  (map key (take evict-batch (sort-by #(:used (val %)) entries))))

(defn- cache-hit!
  "The statement already prepared for sql, marked as just used."
  [conn sql]
  (let [{:keys [tick entries]} @(:stmts conn)]
    (when-let [e (get entries sql)]
      (reset! (:stmts conn)
              {:tick (inc tick) :entries (assoc entries sql (assoc e :used (inc tick)))})
      (:stmt e))))

(defn- cache-put!
  "Remember stmt for sql, closing the least recently used statements if that
  puts the cache over its bound."
  [conn sql stmt]
  (let [{:keys [tick entries]} @(:stmts conn)
        t (inc tick)
        entries (assoc entries sql {:stmt stmt :used t})
        evict (when (> (count entries) max-cached-stmts) (lru-sqls entries))]
    (reset! (:stmts conn) {:tick t :entries (apply dissoc entries evict)})
    (doseq [victim evict]
      (close-stmt conn (:stmt-id (:stmt (get entries victim)))))))

(defn- cache-forget! [conn sql]
  (swap! (:stmts conn) update :entries dissoc sql))

(defn clear-stmt-cache!
  "Close every statement cached on this connection and empty the cache."
  [conn]
  (let [entries (:entries @(:stmts conn))]
    (reset! (:stmts conn) {:tick 0 :entries {}})
    (doseq [e (vals entries)]
      (try (close-stmt conn (:stmt-id (:stmt e))) (catch Throwable _ nil)))))

(defn cached-stmt
  "Prepare sql on this connection, or hand back the statement already prepared
  for it. Dolt resolves a prepared statement against the current schema on every
  execute, so a cached one survives DDL against the tables it reads."
  [conn sql]
  (or (cache-hit! conn sql)
      (let [stmt (prepare-stmt conn sql)]
        (cache-put! conn sql stmt)
        stmt)))

(defn query-prepared
  "Run sql with params over the binary protocol, reusing the statement already
  prepared for it on this connection. Preparing is about as expensive as
  executing, so reuse roughly halves the cost of a repeated query."
  [conn sql params]
  (try
    (execute-stmt conn (cached-stmt conn sql) params)
    (catch Exception e
      ;; the server no longer has the handle — closed behind our back, or
      ;; dropped on its side. Prepare it again and run once more.
      (if (contains? unknown-stmt-errors (:code (ex-data e)))
        (do (cache-forget! conn sql)
            (execute-stmt conn (cached-stmt conn sql) params))
        (throw e)))))
