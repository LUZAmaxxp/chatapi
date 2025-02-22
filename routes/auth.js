import express from "express";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";
import pool from "../db.js";

const router = express.Router();

// Sign Up
router.post("/signup", async (req, res) => {
  const { username, email, password } = req.body;

  try {
    const hashedPassword = await bcrypt.hash(password, 10);
    const newUser = await pool.query(
      "INSERT INTO users (username, email, password) VALUES ($1, $2, $3) RETURNING id, username",
      [username, email, hashedPassword]
    );

    res.status(201).json({ message: "User created successfully" });
  } catch (err) {
    res.status(400).json({ error: "Signup failed" });
  }
});

// Login
router.post("/login", async (req, res) => {
  const { email, password } = req.body;

  try {
    const user = await pool.query("SELECT * FROM users WHERE email = $1", [
      email,
    ]);

    if (!user.rows.length)
      return res.status(400).json({ error: "User not found" });

    const isMatch = await bcrypt.compare(password, user.rows[0].password);
    if (!isMatch) return res.status(400).json({ error: "Invalid credentials" });

    const token = jwt.sign(
      { userId: user.rows[0].id },
      process.env.JWT_SECRET,
      { expiresIn: "24h" }
    );

    res.json({
      token,
      userId: user.rows[0].id,
      username: user.rows[0].username,
    });
  } catch (err) {
    res.status(500).json({ error: "Login failed" });
  }
});
router.get("/search", async (req, res) => {
  const { username } = req.query;

  try {
    const users = await pool.query(
      "SELECT id, username FROM users WHERE username ILIKE $1",
      [`%${username}%`]
    );

    res.json(users.rows);
  } catch (err) {
    res.status(500).json({ error: "Search failed" });
  }
});
router.post("/add-friend", async (req, res) => {
  const { userId, friendId } = req.body;

  try {
    await pool.query(
      "INSERT INTO friends (user_id, friend_id) VALUES ($1, $2), ($2, $1) ON CONFLICT DO NOTHING",
      [userId, friendId]
    );

    res.json({ message: "Friend added" });
  } catch (err) {
    res.status(500).json({ error: "Friend request failed" });
  }
});
router.get("/friends/:userId", async (req, res) => {
  const { userId } = req.params;

  try {
    const friends = await pool.query(
      "SELECT users.id, users.username FROM friends JOIN users ON friends.friend_id = users.id WHERE friends.user_id = $1",
      [userId]
    );

    res.json(friends.rows);
  } catch (err) {
    res.status(500).json({ error: "Failed to get friends list" });
  }
});

export default router;
