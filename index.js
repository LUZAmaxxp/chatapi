import express from "express";
import { Server } from "socket.io";
import mongoose from "mongoose";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";
import cors from "cors";
import dotenv from "dotenv";
import http from "http";
import rateLimit from "express-rate-limit";
import helmet from "helmet";
import mongoSanitize from "express-mongo-sanitize";

dotenv.config();

// Required environment variables validation
if (
  !process.env.JWT_SECRET ||
  !process.env.MONGODB_URI ||
  !process.env.FRONTEND_URI
) {
  throw new Error("Missing required environment variables");
}

const app = express();
const server = http.createServer(app);

// Security middleware
app.use(helmet());
app.use(mongoSanitize());
app.use(express.json({ limit: "10kb" }));

// Rate limiting
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 100,
});
app.use("/api/", limiter);

// CORS configuration
const corsOptions = {
  origin: process.env.FRONTEND_URI,
  methods: ["GET", "POST", "PUT", "DELETE"],
  credentials: true,
  maxAge: 86400,
};
app.use(cors(corsOptions));

// Socket.IO setup
const io = new Server(server, {
  cors: corsOptions,
  pingTimeout: 60000,
});

// MongoDB connection
mongoose
  .connect(
    "mongodb+srv://allouchayman21:KU39Qaq9Bo8cnRgT@cluster0.uyowciu.mongodb.net/users?retryWrites=true&w=majority&appName=Cluster0"
  )
  .then(() => console.log("✅ MongoDB Connected"))
  .catch((err) => console.error("❌ MongoDB Connection Error:", err));

// Schemas
const UserSchema = new mongoose.Schema(
  {
    username: {
      type: String,
      required: true,
      unique: true,
      trim: true,
      minlength: 3,
      maxlength: 30,
    },
    email: {
      type: String,
      required: true,
      unique: true,
      lowercase: true,
      trim: true,
    },
    password: {
      type: String,
      required: true,
      minlength: 8,
    },
    profilePic: {
      type: String,
      default: "default.png",
    },
    friends: [
      {
        type: mongoose.Schema.Types.ObjectId,
        ref: "User",
      },
    ],
    friendRequests: [
      {
        type: mongoose.Schema.Types.ObjectId,
        ref: "User",
      },
    ],
    lastActive: {
      type: Date,
      default: Date.now,
    },
  },
  { timestamps: true }
);

const MessageSchema = new mongoose.Schema({
  sender: {
    type: mongoose.Schema.Types.ObjectId,
    ref: "User",
    required: true,
  },
  receiver: {
    type: mongoose.Schema.Types.ObjectId,
    ref: "User",
    required: true,
  },
  text: {
    type: String,
    required: true,
    trim: true,
    maxlength: 2000,
  },
  timestamp: {
    type: Date,
    default: Date.now,
  },
});

const User = mongoose.model("User", UserSchema);
const Message = mongoose.model("Message", MessageSchema);

// Authentication middleware
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers["authorization"];
  const token = authHeader && authHeader.split(" ")[1];

  if (!token) {
    return res.status(401).json({ error: "Access denied" });
  }

  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    req.user = decoded;
    next();
  } catch (error) {
    res.status(403).json({ error: "Invalid token" });
  }
};

// Routes
app.post("/api/signup", async (req, res) => {
  try {
    const { username, email, password } = req.body;

    if (!username || !password || !email) {
      return res.status(400).json({ error: "All fields are required" });
    }

    const existingUser = await User.findOne({
      $or: [{ username }, { email: email.toLowerCase() }],
    });

    if (existingUser) {
      return res.status(400).json({ error: "Username or email already taken" });
    }

    const hashedPassword = await bcrypt.hash(password, 12);
    const user = new User({
      username,
      email: email.toLowerCase(),
      password: hashedPassword,
    });

    await user.save();

    const token = jwt.sign({ userId: user._id }, process.env.JWT_SECRET, {
      expiresIn: "24h",
    });

    res.status(201).json({
      token,
      userId: user._id,
      username: user.username,
    });
  } catch (error) {
    console.error("❌ Signup Error:", error);
    res.status(500).json({ error: "Server error" });
  }
});

app.post("/api/login", async (req, res) => {
  try {
    const { email, password } = req.body;
    const user = await User.findOne({ email: email.toLowerCase() });

    if (!user || !(await bcrypt.compare(password, user.password))) {
      return res.status(400).json({ error: "Invalid credentials" });
    }

    const token = jwt.sign({ userId: user._id }, process.env.JWT_SECRET, {
      expiresIn: "24h",
    });

    res.json({
      token,
      userId: user._id,
      username: user.username,
    });
  } catch (error) {
    console.error("❌ Login Error:", error);
    res.status(500).json({ error: "Server error" });
  }
});

app.get("/api/search", authenticateToken, async (req, res) => {
  try {
    const { username } = req.query;
    if (!username) {
      return res.status(400).json({ error: "Username required" });
    }

    const users = await User.find({
      username: new RegExp(username, "i"),
      _id: { $ne: req.user.userId },
    })
      .select("-password -friendRequests")
      .limit(10);

    res.json(users);
  } catch (error) {
    res.status(500).json({ error: "Server error" });
  }
});

app.post("/api/send-request", authenticateToken, async (req, res) => {
  try {
    const { receiverId } = req.body;
    const senderId = req.user.userId;

    const receiver = await User.findById(receiverId);
    if (!receiver) {
      return res.status(404).json({ error: "User not found" });
    }

    if (
      receiver.friendRequests.includes(senderId) ||
      receiver.friends.includes(senderId)
    ) {
      return res
        .status(400)
        .json({ error: "Request already sent or already friends" });
    }

    await User.findByIdAndUpdate(receiverId, {
      $addToSet: { friendRequests: senderId },
    });

    res.json({ message: "Friend request sent" });
  } catch (error) {
    res.status(500).json({ error: "Server error" });
  }
});

app.get("/api/friend-requests/:userId", authenticateToken, async (req, res) => {
  try {
    const user = await User.findById(req.params.userId).populate(
      "friendRequests",
      "username profilePic"
    );

    if (!user) {
      return res.status(404).json({ error: "User not found" });
    }

    res.json(user.friendRequests);
  } catch (error) {
    res.status(500).json({ error: "Server error" });
  }
});

app.post("/api/accept-request", authenticateToken, async (req, res) => {
  try {
    const { userId, friendId } = req.body;

    await User.findByIdAndUpdate(userId, {
      $pull: { friendRequests: friendId },
      $addToSet: { friends: friendId },
    });

    await User.findByIdAndUpdate(friendId, {
      $addToSet: { friends: userId },
    });

    res.json({ message: "Friend request accepted" });
  } catch (error) {
    res.status(500).json({ error: "Server error" });
  }
});

// Socket.IO authentication middleware
io.use((socket, next) => {
  try {
    const token = socket.handshake.auth.token;
    if (!token) {
      return next(new Error("Authentication error"));
    }

    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    socket.userId = decoded.userId;
    next();
  } catch (error) {
    next(new Error("Authentication error"));
  }
});

// Socket.IO connection handling
io.on("connection", (socket) => {
  console.log("✅ User connected:", socket.userId);
  socket.join(socket.userId);

  socket.on("friendRequest", async ({ receiverId }) => {
    io.to(receiverId).emit("newFriendRequest", {
      senderId: socket.userId,
    });
  });

  socket.on("friendRequestAccepted", async ({ senderId }) => {
    io.to(senderId).emit("friendRequestAccepted", {
      accepterId: socket.userId,
    });
  });

  socket.on("privateMessage", async (data) => {
    try {
      const message = new Message({
        sender: socket.userId,
        receiver: data.receiver,
        text: data.text,
      });
      await message.save();

      io.to(data.receiver).to(socket.userId).emit("newMessage", {
        messageId: message._id,
        sender: socket.userId,
        text: message.text,
        timestamp: message.timestamp,
      });
    } catch (error) {
      socket.emit("messageError", { error: "Failed to send message" });
    }
  });

  socket.on("disconnect", () => {
    console.log("❌ User disconnected:", socket.userId);
  });
});

const PORT = process.env.PORT || 3500;
server.listen(PORT, () => console.log(`🚀 Server running on port ${PORT}`));
