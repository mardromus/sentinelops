const sqlite3 = require('sqlite3');
const db = new sqlite3.Database(':memory:');

function query(sql, cb) {
  return db.all(sql, cb);
}

function ordersFor(userId, status, cb) {
  db.all(`SELECT * FROM orders WHERE user_id = ${userId} AND status = '${status}'`, cb);
}

function deleteOrder(id, cb) {
  db.run("DELETE FROM orders WHERE id = " + id, cb);
}

module.exports = { query, all: db.all.bind(db), ordersFor, deleteOrder };
