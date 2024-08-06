const sqlite3 = require("sqlite3").verbose();

// Initialize a persistent SQLite database
const db = new sqlite3.Database("./data.db", (err) => {
  if (err) {
    console.error("Error opening database", err.message);
  } else {
    console.log("Connected to the SQLite database.");

    // Create users table if it doesn't exist
    db.run(
      "CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT, password TEXT)",
      (err) => {
        if (err) {
          console.error("Error creating users table", err.message);
        }
      }
    );
  }
});

module.exports = db;
