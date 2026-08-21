(ns doltera.core
  "Public API: a MySQL-protocol client for dolt sql-server.

  Queries are strings or sqlvecs (a vector whose first element is SQL and the
  rest are `?` parameters). Prepared statements are used for everything, so
  values come back typed: integers as longs, floats as doubles, NULL as nil,
  strings as strings, blobs as byte arrays. DECIMAL and date/time values come
  back as strings.

  Dolt's version-control procedures (dolt_commit, dolt_branch, dolt_log, ...)
  are reachable through `query` with `call dolt_commit(...)`, and a few common
  ones are wrapped below."
  (:require [doltera.protocol :as proto]))

(defn connect
  "Open a connection to a dolt sql-server. Options:
  :host (default 127.0.0.1), :port (default 3306), :user (default \"root\"),
  :password (default \"\"), :db (optional database/repo name)."
  [{:keys [host port user password db]
    :or {host "127.0.0.1" port 3306 user "root" password ""}}]
  (proto/handshake! (proto/open-conn host port) user password db))

(defn close [conn]
  (proto/close-conn conn))

(defn- run [conn sql]
  (let [[s & params] (if (vector? sql) sql [sql])]
    (proto/query-prepared conn s params)))

(defn query
  "Run a query; returns a vector of row maps (empty for statements without a
  result set). SQL is a string or [sql & params]."
  [conn sql]
  (let [r (run conn sql)]
    (if (:rows r) (:rows r) [])))

(defn execute!
  "Run a statement; returns the number of affected rows."
  [conn sql]
  (let [r (run conn sql)]
    (:affected r 0)))

(defn fetch
  "Alias for query."
  [conn sql]
  (query conn sql))

(defn fetch-one
  "First row of a query, or nil."
  [conn sql]
  (first (query conn sql)))

(defn transaction
  "Run f inside START TRANSACTION ... COMMIT, rolling back on any throw."
  [conn f]
  (execute! conn "start transaction")
  (try
    (let [v (f)]
      (execute! conn "commit")
      v)
    (catch Throwable t
      (try (execute! conn "rollback") (catch Throwable _ nil))
      (throw t))))

(defn- dolt-call [conn proc args]
  (let [marks (apply str (interpose ", " (repeat (count args) "?")))]
    (query conn (into [(str "call " proc "(" marks ")")] args))))

(defn dolt-commit [conn msg]
  (dolt-call conn "dolt_commit" ["-A" "-m" msg]))

(defn dolt-branch [conn name]
  (dolt-call conn "dolt_branch" [name]))

(defn dolt-checkout [conn name]
  (dolt-call conn "dolt_checkout" [name]))

(defn dolt-status [conn]
  (query conn "select * from dolt_status"))

(defn dolt-log [conn]
  (query conn "select * from dolt_log"))
