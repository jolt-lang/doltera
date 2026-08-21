(ns doltera.test
  "Self-contained test suite: spawns a dolt sql-server on a free port against a
  fresh temp repo, runs the client against it, kills the server. Set
  DOLTERA_TEST_PORT (and DOLTERA_TEST_DATA_DIR) to point at an already-running
  server instead, and DOLTERA_TEST_DB at the database to use on it. The
  wire-level checks need no server at all."
  (:require [clojure.string :as str]
            [doltera.core :as dolt]
            [doltera.protocol :as proto]
            [doltera.wire :as w]
            [jolt.process :as p]))

(def failures (atom 0))

(defn check [label expected actual]
  (if (= expected actual)
    (println "  ok  " label)
    (do (swap! failures inc)
        (println "  FAIL" label "— expected" (pr-str expected) "got" (pr-str actual)))))

(defn free-port []
  (let [ss (ServerSocket. 0)
        port (.getLocalPort ss)]
    (.close ss)
    port))

(defn server-up? [host port]
  (try
    (let [c (dolt/connect {:host host :port port})]
      (dolt/close c)
      true)
    (catch Exception _ false)))

;; -- wire-level checks (no server) --------------------------------------------

(defn unhex [s]
  (let [digit #(str/index-of "0123456789abcdef" (str %))]
    (byte-array (map (fn [i]
                       (w/signed (+ (* 16 (digit (nth s (* 2 i))))
                                    (digit (nth s (inc (* 2 i)))))))
                     (range (quot (count s) 2))))))

(def sample-handshake
  "A real Initial Handshake Packet from dolt 2.3.1 (server version 8.0.33)."
  (str "0a382e302e333300020000002c64504f12447d53008fa22100003b0115000000"
       "0000000000000067784b3a3f2d13433d036e40006d7973716c5f6e6174697665"
       "5f70617373776f726400"))

(defn framed [payload]
  (let [out (ByteArrayOutputStream.)]
    (proto/write-packet {:out out :seq (atom 0)} payload)
    (.toByteArray out)))

(defn err-message [payload]
  (try (proto/parse-err! payload) :no-throw
       (catch Exception e (:message (ex-data e)))))

(defn run-wire-checks []
  (println "  --- handshake packet")
  (let [hs (proto/parse-handshake (unhex sample-handshake))]
    (check "server version" "8.0.33" (:version hs))
    (check "connection id" 2 (:conn-id hs))
    (check "capability flags" 0x013ba28f (:caps hs))
    (check "server charset" 33 (:charset hs))
    (check "auth plugin name" "mysql_native_password" (:auth-plugin hs))
    (check "20-byte nonce" "2c64504f12447d5367784b3a3f2d13433d036e40" (w/hex (:nonce hs))))

  (check "auth switch request names the plugin" "caching_sha2_password"
         (proto/auth-switch-plugin (w/concat-ba (w/ba 0xfe)
                                                (.getBytes "caching_sha2_password" "UTF-8")
                                                (w/ba 0) (byte-array 21))))

  (println "  --- error packets")
  (check "error message with sqlstate" "no such table"
         (err-message (w/concat-ba (w/ba 0xff) (w/w16 1146) (w/ba 0x23)
                                   (.getBytes "42S02" "UTF-8")
                                   (.getBytes "no such table" "UTF-8"))))
  (check "error message without sqlstate" "no such table"
         (err-message (w/concat-ba (w/ba 0xff) (w/w16 1146)
                                   (.getBytes "no such table" "UTF-8"))))

  (println "  --- packet framing")
  (check "short packet header" "03000000010203" (w/hex (framed (w/ba 1 2 3))))
  (check "empty packet" "00000000" (w/hex (framed (byte-array 0))))
  (let [out (framed (byte-array 0xffffff))]
    (check "payload of exactly 0xffffff is terminated by an empty packet"
           (+ 4 0xffffff 4) (count out))
    (check "terminating packet is empty and carries the next sequence id"
           "00000001" (w/hex (w/sub-ba out (- (count out) 4) 4)))))

;; -- server checks -------------------------------------------------------------

(defn run-checks [conn opts]
  (println "  --- connection")
  (check "server version string present" true (pos? (count (:server conn))))
  (check "CONNECT_WITH_DB negotiated" true (pos? (bit-and (:caps conn) 0x8)))
  (check "PLUGIN_AUTH negotiated" true (pos? (bit-and (:caps conn) 0x80000)))
  (check "TRANSACTIONS negotiated" true (pos? (bit-and (:caps conn) 0x2000)))
  (check "handshake selected the database" (:db opts)
         (:db (dolt/fetch-one conn "select database() as db")))

  (println "  --- basics")
  (check "select literal number" [{:x 1}] (dolt/query conn "select 1 as x"))
  (check "select literal string" [{:x "ada"}] (dolt/query conn "select 'ada' as x"))
  (check "execute! ddl" 0 (dolt/execute! conn "create table person (id int primary key, name varchar(100), zip int)"))

  (println "  --- dml + typed results")
  (check "execute! insert" 2 (dolt/execute! conn "insert into person values (1, 'ada', 94546), (2, 'grace', 94546)"))
  (check "query rows typed"
         [{:id 1 :name "ada" :zip 94546} {:id 2 :name "grace" :zip 94546}]
         (dolt/query conn "select * from person order by id"))
  (check "count aggregate" [{:n 2}] (dolt/query conn "select count(*) as n from person"))
  (check "decimal value (string)" [{:x "1.5"}] (dolt/query conn "select 1.5 as x"))
  (check "null value" [{:x nil}] (dolt/query conn "select null as x"))
  (check "blob column round-trip" [1 2 3]
         (do (dolt/execute! conn "create table blobs (id int primary key, body blob)")
             (dolt/execute! conn ["insert into blobs values (1, ?)" (byte-array [1 2 3])])
             (let [b (first (dolt/query conn "select body from blobs"))]
               (vec (:body b)))))
  (check "utf8mb4 round-trip" "héllo 😀 世界"
         (do (dolt/execute! conn "create table utf (id int primary key, s varchar(50))")
             (dolt/execute! conn ["insert into utf values (1, ?)" "héllo 😀 世界"])
             (:s (dolt/fetch-one conn "select s from utf"))))

  (println "  --- integer types")
  (dolt/execute! conn "create table ints (id int primary key, ti tinyint, si smallint, i int, bi bigint)")
  (dolt/execute! conn "insert into ints values (1, -128, -32768, -2147483648, -9223372036854775808)")
  (check "signed integers at their minimum"
         {:id 1 :ti -128 :si -32768 :i -2147483648 :bi -9223372036854775808}
         (dolt/fetch-one conn "select * from ints"))
  (dolt/execute! conn (str "create table uints (id int primary key, ti tinyint unsigned,"
                           " si smallint unsigned, i int unsigned, bi bigint unsigned)"))
  (dolt/execute! conn "insert into uints values (1, 255, 65535, 4294967295, 18446744073709551615)")
  (check "unsigned integers at their maximum"
         {:id 1 :ti 255 :si 65535 :i 4294967295 :bi 18446744073709551615}
         (dolt/fetch-one conn "select * from uints"))
  (check "unsigned parameter echo" [{:x 255}] (dolt/query conn ["select ? as x" 255]))

  (println "  --- binary and bit types")
  (dolt/execute! conn "create table bins (id int primary key, b binary(4), vb varbinary(10))")
  (dolt/execute! conn ["insert into bins values (1, ?, ?)"
                       (byte-array [0 1 2 -1]) (byte-array [-1 -2 0 1])])
  (check "binary(4) stays bytes" "000102ff" (w/hex (:b (dolt/fetch-one conn "select b from bins"))))
  (check "varbinary stays bytes" "fffe0001" (w/hex (:vb (dolt/fetch-one conn "select vb from bins"))))
  (dolt/execute! conn "create table bits (id int primary key, f1 bit(1), f8 bit(8), f64 bit(64))")
  (dolt/execute! conn "insert into bits values (1, 1, 200, 18446744073709551615)")
  (check "bit columns decode as integers" {:f1 1 :f8 200 :f64 18446744073709551615}
         (dolt/fetch-one conn "select f1, f8, f64 from bits"))

  (println "  --- date and time")
  (dolt/execute! conn "create table stamps (id int primary key, d date, dt datetime, ts timestamp, t time, y year)")
  (dolt/execute! conn (str "insert into stamps values (1, '2024-01-02', '2024-01-02 03:04:05',"
                           " '2024-01-02 03:04:05', '10:20:30', 2024)"))
  (check "date/time values"
         {:d "2024-01-02" :dt "2024-01-02 03:04:05" :ts "2024-01-02 03:04:05"
          :t "10:20:30" :y 2024}
         (dolt/fetch-one conn "select d, dt, ts, t, y from stamps"))
  (check "negative time" "-10:20:30"
         (do (dolt/execute! conn "update stamps set t = '-10:20:30' where id = 1")
             (:t (dolt/fetch-one conn "select t from stamps"))))
  (dolt/execute! conn "create table subsecond (id int primary key, a datetime(6))")
  (dolt/execute! conn "insert into subsecond values (1, '2024-01-02 03:04:05.123456')")
  (check "fractional seconds" "2024-01-02 03:04:05.123456"
         (:a (dolt/fetch-one conn "select a from subsecond")))
  (dolt/execute! conn "create table geo (id int primary key, p point)")
  (dolt/execute! conn "insert into geo values (1, point(1, 2))")
  (check "spatial column stays bytes" true
         (bytes? (:p (dolt/fetch-one conn "select p from geo"))))

  (println "  --- parameters")
  (check "int param" [{:id 1 :name "ada" :zip 94546}]
         (dolt/query conn ["select * from person where id = ?" 1]))
  (check "string param" [{:id 1 :name "ada" :zip 94546}]
         (dolt/query conn ["select * from person where name = ?" "ada"]))
  (check "double param" [{:x 2.5}] (dolt/query conn ["select ? as x" 2.5]))
  (check "nil param is SQL NULL" [{:x nil}] (dolt/query conn ["select ? as x" nil]))
  (check "null param in where" [] (dolt/query conn ["select * from person where id = ?" nil]))
  (check "fetch-one" {:id 2 :name "grace" :zip 94546}
         (dolt/fetch-one conn "select * from person where id = 2"))
  (check "sql error throws" :caught
         (try (dolt/query conn "select * from missing_table") (catch Exception _ :caught)))

  (println "  --- auth")
  (dolt/execute! conn "drop user if exists 'doltera_pw'@'%'")
  (dolt/execute! conn "create user 'doltera_pw'@'%' identified by 'sw0rdfish'")
  (dolt/execute! conn "grant all on *.* to 'doltera_pw'@'%'")
  (check "password auth connects" [{:x 1}]
         (let [c (dolt/connect (assoc opts :user "doltera_pw" :password "sw0rdfish"))]
           (try (dolt/query c "select 1 as x") (finally (dolt/close c)))))
  (check "wrong password is rejected" :rejected
         (try (dolt/close (dolt/connect (assoc opts :user "doltera_pw" :password "nope")))
              :accepted
              (catch Exception _ :rejected)))
  (check "unknown database is rejected at connect" :rejected
         (try (dolt/close (dolt/connect (assoc opts :db "no_such_database")))
              :accepted
              (catch Exception _ :rejected)))
  (dolt/execute! conn "drop user if exists 'doltera_pw'@'%'")

  (println "  --- transactions")
  (dolt/transaction conn (fn [] (dolt/execute! conn "insert into person values (3, 'alan', 10001)")))
  (check "transaction commits" 3 (count (dolt/query conn "select * from person")))
  (check "transaction rolls back" :threw
         (try (dolt/transaction conn (fn []
                                       (dolt/execute! conn "insert into person values (4, 'boom', 2)")
                                       (throw (ex-info "no" {}))))
              (catch Throwable _ :threw)))
  (check "rollback discarded the insert" 3 (count (dolt/query conn "select * from person")))

  (println "  --- dolt version control procedures")
  (let [r (first (dolt/dolt-commit conn "add person table"))]
    (check "dolt_commit returns a result row" true (map? r)))
  (check "dolt_log has the commit" true (pos? (count (dolt/dolt-log conn))))
  (check "dolt_branch via query" 1 (count (dolt/query conn ["call dolt_branch('feat')"])))
  (dolt/dolt-checkout conn "feat")
  (check "dolt_status after checkout" [] (dolt/dolt-status conn)))

(defn wait-for-server [port]
  (loop [waits 0]
    (when (and (< waits 60) (not (server-up? "127.0.0.1" port)))
      (Thread/sleep 200)
      (recur (inc waits))))
  (when-not (server-up? "127.0.0.1" port)
    (throw (ex-info "no dolt sql-server answering" {:port port}))))

(defn run-against [opts]
  (println "connecting to port" (:port opts) "with db" (:db opts))
  (let [conn (dolt/connect opts)]
    (try
      (run-checks conn opts)
      (finally (dolt/close conn)))))

(defn -main [& _]
  (println "  --- wire protocol (no server)")
  (run-wire-checks)
  (let [env-port (System/getenv "DOLTERA_TEST_PORT")
        env-dir (System/getenv "DOLTERA_TEST_DATA_DIR")
        own-server? (and (nil? env-port) (nil? env-dir))
        port (if env-port (read-string env-port) (free-port))
        dir (or env-dir (str "/tmp/doltera-test-" (System/nanoTime)))
        dbname (or (System/getenv "DOLTERA_TEST_DB") (last (str/split dir #"/")))
        opts {:host "127.0.0.1" :port port :db dbname}]
    (if own-server?
      (do
        (println "setting up repo at" dir "on port" port)
        (p/check (p/sh ["mkdir" "-p" dir]))
        (p/check (p/sh ["dolt" "config" "--global" "--add" "user.name" "doltera"]))
        (p/check (p/sh ["dolt" "config" "--global" "--add" "user.email" "doltera@test"]))
        (p/check (p/sh ["dolt" "init"] {:dir dir}))
        (let [server (p/process ["dolt" "sql-server" "--host" "127.0.0.1" "--port" (str port)
                                 "--data-dir" dir "--loglevel" "error"]
                                {:out :inherit :err :inherit})]
          (try
            (wait-for-server port)
            (run-against opts)
            (finally (p/destroy-tree server)))))
      (do
        (wait-for-server port)
        (run-against opts)))
    (if (pos? @failures)
      (throw (ex-info "test failures" {:n @failures}))
      (println "all checks passed"))))
