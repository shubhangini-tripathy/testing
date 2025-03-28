const sqlite3 = require('sqlite3').verbose();

// Open a database in memory (or specify a file for persistence)
const db = new sqlite3.Database('./users.db', (err) => {
    if (err) {
        console.error('Database opening error: ', err);
    } else {
        console.log('Connected to the SQLite database.');
    }
});

// Create a users table if it doesn't exist
db.run(`
  CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    password TEXT NOT NULL
  )
`);

module.exports = db;
