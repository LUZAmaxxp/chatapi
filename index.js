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
    origin: process.env.FRONTEND_URI, // Allow only your frontend domain
    methods: ["GET", "POST", "PUT", "DELETE"],
    credentials: true, // Enable cookies if needed
  })
);

mongoose
  .connect(
    "mongodb+srv://allouchayman21:KU39Qaq9Bo8cnRgT@cluster0.uyowciu.mongodb.net/users?retryWrites=true&w=majority&appName=Cluster0"
  )
  .then(() => console.log("MongoDB Connected"))
  .catch((err) => console.log(err));
const UserSchema = new mongoose.Schema(
  {
    username: String,
    email: String,
    password: String,
    profilePic: String,
    friends: [{ type: mongoose.Schema.Types.ObjectId, ref: "User" }],
    friendRequests: [{ type: mongoose.Schema.Types.ObjectId, ref: "User" }],
  },
  { timestamps: true }
);
UserSchema.index({ email: 1 }, { unique: true });
UserSchema.index({ username: 1 }, { unique: true });

const MessageSchema = new mongoose.Schema({
  sender: { type: mongoose.Schema.Types.ObjectId, ref: "User" },
  receiver: { type: mongoose.Schema.Types.ObjectId, ref: "User" },
  text: String,
  timestamp: { type: Date, default: Date.now },
});

const User = mongoose.model("User", UserSchema);
const Message = mongoose.model("Message", MessageSchema);

// Signup Route
app.post("/signup", async (req, res) => {
  res.setHeader(
    "Access-Control-Allow-Origin",
    "https://chat-io-orpin.vercel.app"
  );
  res.setHeader("Access-Control-Allow-Methods", "POST, GET, OPTIONS");
  res.setHeader("Access-Control-Allow-Headers", "Content-Type, Authorization");
  try {
    console.log("📥 Signup request received:", req.body);

    const { username, password, email } = req.body;
    if (!username || !password || !email) {
      console.log("⚠️ Missing fields:", req.body);
      return res.status(400).json({ error: "All fields are required" });
    }

    const existingUser = await User.findOne({ username });
    if (existingUser) {
      console.log("⚠️ Username already taken:", username);
      return res.status(400).json({ error: "Username already taken" });
    }

    const hashedPassword = await bcrypt.hash(password, 10);
    const newUser = new User({ username, email, password: hashedPassword });

    await newUser.save();

    console.log("✅ User created:", username);
    res.status(201).json({ message: "User created successfully" });
  } catch (error) {
    console.error("❌ Signup Error:", error);
    res.status(500).json({ error: "Internal server error" });
  }
});

// Login Route
app.post("/login", async (req, res) => {
  try {
    const { email, password } = req.body;
    const user = await User.findOne({ email });
    if (!user) return res.status(400).json({ message: "User not found" });
    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch)
      return res.status(400).json({ message: "Invalid credentials" });
    const token = jwt.sign({ userId: user._id }, process.env.JWT_SECRET);
    res.json({ token, userId: user._id });
  } catch (error) {
    console.error("Login error:", error);
    res.status(500).json({ error: "Internal server error" });
  }
});

// Search for Users
app.get("/search", async (req, res) => {
  const { query } = req.query;
  const users = await User.find({ username: new RegExp(query, "i") });
  res.json(users);
});

// Send Friend Request
app.post("/send-request", async (req, res) => {
  const { senderId, receiverId } = req.body;

  try {
    const receiver = await User.findById(receiverId);
    if (!receiver) {
      return res.status(404).json({ error: "Receiver user not found" });
    }

    // Check if request already exists
    if (receiver.friendRequests.includes(senderId)) {
      console.log("Friend request already sent to:", receiver.username);
      return res.status(400).json({ error: "Friend request already sent" });
    }

    await User.findByIdAndUpdate(receiverId, {
      $push: { friendRequests: senderId },
    });

    res.json({ message: "Friend request sent successfully" });
  } catch (error) {
    console.error("Error sending friend request:", error);
    res.status(500).json({ error: "Internal server error" });
  }
});

// Accept Friend Request
app.post("/accept-request", async (req, res) => {
  const { userId, friendId } = req.body;
  await User.findByIdAndUpdate(userId, {
    $push: { friends: friendId },
    $pull: { friendRequests: friendId },
  });
  await User.findByIdAndUpdate(friendId, { $push: { friends: userId } });
  res.json({ message: "Friend request accepted" });
});

// Get User Friends List
app.get("/friend-requests/:userId", async (req, res) => {
  try {
    const user = await User.findById(req.params.userId).populate(
      "friendRequests",
      "username profilePic"
    );
    res.json(user.friendRequests);
  } catch (error) {
    console.error("Error fetching friend requests:", error);
    res.status(500).json({ error: "Internal server error" });
  }
});

// Private Chat with WebSockets
io.on("connection", (socket) => {
  const token = socket.handshake.auth.token;
  if (!token) {
    socket.disconnect();
    return;
  }
  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    socket.userId = decoded.userId;
    console.log("User connected:", decoded.userId);
  } catch (error) {
    socket.disconnect();
    console.error("Invalid token:", error);
  }

  socket.on("privateMessage", async ({ senderId, receiverId, text }) => {
    const message = new Message({
      sender: senderId,
      receiver: receiverId,
      text,
    });
    await message.save();
    io.to(receiverId).emit("newMessage", { senderId, text });
  });

  socket.on("disconnect", () => {
    console.log("User disconnected: " + socket.id);
  });
});

server.listen(process.env.PORT || 3500, () => {
  console.log("Server is running...");
});
