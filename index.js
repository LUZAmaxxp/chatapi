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
app.use(cors());

mongoose
  .connect(
    "mongodb+srv://allouchayman21:KU39Qaq9Bo8cnRgT@cluster0.uyowciu.mongodb.net/users?retryWrites=true&w=majority&appName=Cluster0",
    {
      useNewUrlParser: true,
      useUnifiedTopology: true,
    }
  )
  .then(() => console.log("MongoDB Connected"))
  .catch((err) => console.log(err));

const UserSchema = new mongoose.Schema({
  username: String,
  email: String,
  password: String,
  profilePic: String,
  friends: [{ type: mongoose.Schema.Types.ObjectId, ref: "User" }],
  friendRequests: [{ type: mongoose.Schema.Types.ObjectId, ref: "User" }],
});

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
  const { username, email, password } = req.body;
  const hashedPassword = await bcrypt.hash(password, 10);
  const user = new User({ username, email, password: hashedPassword });
  await user.save();
  res.status(201).json({ message: "User created successfully" });
  console.log("User created successfully");
});

// Login Route
app.post("/login", async (req, res) => {
  const { email, password } = req.body;
  const user = await User.findOne({ email });
  if (!user) return res.status(400).json({ message: "User not found" });
  const isMatch = await bcrypt.compare(password, user.password);
  if (!isMatch) return res.status(400).json({ message: "Invalid credentials" });
  const token = jwt.sign({ userId: user._id }, process.env.JWT_SECRET);
  res.json({ token, userId: user._id });
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
  await User.findByIdAndUpdate(receiverId, {
    $push: { friendRequests: senderId },
  });
  res.json({ message: "Friend request sent" });
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
app.get("/friends/:userId", async (req, res) => {
  const user = await User.findById(req.params.userId).populate(
    "friends",
    "username profilePic"
  );
  res.json(user.friends);
});

// Private Chat with WebSockets
io.on("connection", (socket) => {
  console.log("User connected: " + socket.id);

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
