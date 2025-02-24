import express from "express";
import { Server } from "socket.io";
import mongoose from "mongoose";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";
import cors from "cors";
import dotenv from "dotenv";
import http from "http";

dotenv.config();

const app = express();
const server = http.createServer(app);
const io = new Server(server, {
  cors: {
    origin: process.env.FRONTEND_URI,
    methods: ["GET", "POST"],
  },
});

app.use(express.json());
app.use(
  cors({
    origin: process.env.FRONTEND_URI,
    methods: ["GET", "POST", "PUT", "DELETE"],
    credentials: true,
  })
);

// ✅ Connect to MongoDB
mongoose
  .connect(
    "mongodb+srv://allouchayman21:KU39Qaq9Bo8cnRgT@cluster0.uyowciu.mongodb.net/users?retryWrites=true&w=majority&appName=Cluster0"
  )
  .then(() => console.log("✅ MongoDB Connected"))
  .catch((err) => console.error("❌ MongoDB Connection Error:", err));

const UserSchema = new mongoose.Schema(
  {
    username: { type: String, unique: true },
    email: { type: String, unique: true },
    password: String,
    profilePic: String,
    friends: [{ type: mongoose.Schema.Types.ObjectId, ref: "User" }],
    friendRequests: [{ type: mongoose.Schema.Types.ObjectId, ref: "User" }],
  },
  { timestamps: true }
);

const MessageSchema = new mongoose.Schema({
  sender: { type: mongoose.Schema.Types.ObjectId, ref: "User" },
  receiver: { type: mongoose.Schema.Types.ObjectId, ref: "User" },
  text: String,
  timestamp: { type: Date, default: Date.now },
});

const User = mongoose.model("User", UserSchema);
const Message = mongoose.model("Message", MessageSchema);

// ✅ Signup Route
app.post("/signup", async (req, res) => {
  try {
    const { username, password, email } = req.body;
    if (!username || !password || !email) {
      return res.status(400).json({ error: "All fields are required" });
    }

    const existingUser = await User.findOne({ $or: [{ username }, { email }] });
    if (existingUser) {
      return res.status(400).json({ error: "Username or email already taken" });
    }

    const hashedPassword = await bcrypt.hash(password, 10);
    const newUser = new User({ username, email, password: hashedPassword });

    await newUser.save();

    // ✅ Return token upon signup
    const token = jwt.sign({ userId: newUser._id }, process.env.JWT_SECRET);
    res.status(201).json({ token, userId: newUser._id });
  } catch (error) {
    console.error("❌ Signup Error:", error);
    res.status(500).json({ error: "Internal server error" });
  }
});

// ✅ Login Route
app.post("/login", async (req, res) => {
  try {
    const { email, password } = req.body;
    const user = await User.findOne({ email });

    if (!user) return res.status(400).json({ error: "User not found" });

    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) return res.status(400).json({ error: "Invalid credentials" });

    const token = jwt.sign({ userId: user._id }, process.env.JWT_SECRET);
    res.json({ token, userId: user._id });
  } catch (error) {
    console.error("❌ Login error:", error);
    res.status(500).json({ error: "Internal server error" });
  }
});

// ✅ Search for Users
app.get("/search", async (req, res) => {
  const { username } = req.query;
  if (!username) return res.status(400).json({ error: "Username is required" });

  const users = await User.find({ username: new RegExp(username, "i") });
  res.json(users);
});

// ✅ Send Friend Request
app.post("/send-request", async (req, res) => {
  const { senderId, receiverId } = req.body;
  try {
    const receiver = await User.findById(receiverId);
    if (!receiver) return res.status(404).json({ error: "User not found" });

    if (
      receiver.friendRequests.includes(senderId) ||
      receiver.friends.includes(senderId)
    ) {
      return res
        .status(400)
        .json({ error: "Friend request already sent or already friends" });
    }

    await User.findByIdAndUpdate(receiverId, {
      $push: { friendRequests: senderId },
    });

    res.json({ message: "Friend request sent successfully" });
  } catch (error) {
    console.error("❌ Friend Request Error:", error);
    res.status(500).json({ error: "Internal server error" });
  }
});

// ✅ Accept Friend Request
app.post("/accept-request", async (req, res) => {
  const { userId, friendId } = req.body;
  try {
    await User.findByIdAndUpdate(userId, {
      $push: { friends: friendId },
      $pull: { friendRequests: friendId },
    });

    await User.findByIdAndUpdate(friendId, { $push: { friends: userId } });

    res.json({ message: "Friend request accepted" });
  } catch (error) {
    console.error("❌ Accept Request Error:", error);
    res.status(500).json({ error: "Internal server error" });
  }
});

// ✅ Get Friend Requests (Fixed Method: GET instead of POST)
app.get("/friend-requests/:userId", async (req, res) => {
  try {
    const user = await User.findById(req.params.userId).populate(
      "friendRequests"
    );
    res.json(user.friendRequests);
  } catch (error) {
    console.error("❌ Fetch Friend Requests Error:", error);
    res.status(500).json({ error: "Internal server error" });
  }
});

// ✅ WebSocket Chat System
io.on("connection", (socket) => {
  try {
    const token = socket.handshake.auth.token;
    if (!token) return socket.disconnect();

    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    socket.userId = decoded.userId;
    console.log("✅ User connected:", decoded.userId);

    socket.on("privateMessage", async ({ sender, receiver, text }) => {
      const message = new Message({ sender, receiver, text });
      await message.save();
      io.to(receiver).emit("newMessage", { sender, text });
    });

    socket.on("disconnect", () => console.log("❌ User disconnected"));
  } catch (error) {
    console.error("❌ WebSocket Error:", error);
    socket.disconnect();
  }
});

// ✅ Start Server
const PORT = process.env.PORT || 3500;
server.listen(PORT, () => console.log(`🚀 Server running on port ${PORT}...`));
