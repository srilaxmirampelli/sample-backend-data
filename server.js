const express = require("express");
const cors = require("cors");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const dotenv = require("dotenv");
const db = require("./database"); // Import the database module

const app = express();

dotenv.config();
app.use(express.json());
app.use(cors());

// Register route
app.post("/register", (req, res) => {
  const { username, password } = req.body;
  console.log(username, password);

  // Hash password
  const hashedPassword = bcrypt.hashSync(password, 8);

  // Insert user into database
  db.run(
    "INSERT INTO users (username, password) VALUES (?, ?)",
    [username, hashedPassword],
    function (err) {
      if (err) {
        return res.status(500).send("Error registering user");
      }
      res.status(201).json({ message: "User registered" });
    }
  );
});

// Login route
app.post("/login", (req, res) => {
  const { username, password } = req.body;

  // Find user in the database
  db.get("SELECT * FROM users WHERE username = ?", [username], (err, user) => {
    if (err) {
      return res.status(500).send("Error retrieving user");
    }
    if (!user) {
      return res.status(404).send("User not found");
    }

    // Compare password
    const passwordIsValid = bcrypt.compareSync(password, user.password);
    if (!passwordIsValid) {
      return res.status(401).send("Invalid password");
    }

    // Create a token
    const token = jwt.sign({ id: user.id }, process.env.JWT_SECRET, {
      expiresIn: 86400, // 24 hours
    });

    res.status(200).send({ auth: true, token: token });
  });
});

// Starting the server
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Server is running on port ${PORT}`);
});
