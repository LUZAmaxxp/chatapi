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

// Validate environment variables
if (!process.env.JWT_SECRET || !process.env.FRONTEND_URI) {
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

// CORS setup
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

// Map to store active user connections
const userSocketMap = new Map();

// MongoDB Connection
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

const MessageSchema = new mongoose.Schema(
  {
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
  },
  { timestamps: true }
);

const User = mongoose.model("User", UserSchema);
const Message = mongoose.model("Message", MessageSchema);

// Auth Middleware
const auth = async (req, res, next) => {
  try {
    const token = req.header("Authorization").replace("Bearer ", "");
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    req.user = decoded;
    next();
  } catch (error) {
    res.status(401).json({ error: "Authentication required" });
  }
};

// Routes
app.post("/api/signup", async (req, res) => {
  try {
    const { username, email, password } = req.body;

    const existingUser = await User.findOne({
      $or: [{ email }, { username }],
    });

    if (existingUser) {
      return res.status(400).json({ error: "Username or email already taken" });
    }

    const hashedPassword = await bcrypt.hash(password, 12);
    const user = new User({
      username,
      email,
      password: hashedPassword,
    });

    await user.save();

    const token = jwt.sign({ userId: user._id }, process.env.JWT_SECRET);
    res.status(201).json({ token, userId: user._id });
  } catch (error) {
    res.status(500).json({ error: "Server error" });
  }
});

app.post("/api/login", async (req, res) => {
  try {
    const { email, password } = req.body;
    const user = await User.findOne({ email });

    if (!user) {
      return res.status(400).json({ error: "Invalid credentials" });
    }

    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      return res.status(400).json({ error: "Invalid credentials" });
    }

    const token = jwt.sign({ userId: user._id }, process.env.JWT_SECRET);
    res.json({ token, userId: user._id });
  } catch (error) {
    res.status(500).json({ error: "Server error" });
  }
});

app.get("/api/search", auth, async (req, res) => {
  try {
    const { username } = req.query;
    const users = await User.find({
      username: new RegExp(username, "i"),
      _id: { $ne: req.user.userId },
    }).select("-password");
    res.json(users);
  } catch (error) {
    res.status(500).json({ error: "Server error" });
  }
});

app.post("/api/send-request", auth, async (req, res) => {
  try {
    const { receiverId } = req.body;
    const sender = await User.findById(req.user.userId).select("username");
    const receiver = await User.findById(receiverId);

    if (!receiver) {
      return res.status(404).json({ error: "User not found" });
    }

    if (receiver.friendRequests.includes(req.user.userId)) {
      return res.status(400).json({ error: "Request already sent" });
    }

    // Check if they're already friends
    if (receiver.friends.includes(req.user.userId)) {
      return res.status(400).json({ error: "Already friends" });
    }

    receiver.friendRequests.push(req.user.userId);
    await receiver.save();

    // Emit event to receiver if they're online
    // Emit both event names for compatibility during transition
    if (userSocketMap.has(receiverId)) {
      io.to(receiverId).emit("newFriendRequest", {
        senderId: req.user.userId,
        senderUsername: sender.username,
      });

      io.to(receiverId).emit("friendRequest", {
        senderId: req.user.userId,
        senderUsername: sender.username,
      });

      console.log(
        `Friend request emitted to ${receiverId} from ${req.user.userId}`
      );
    } else {
      console.log(`Receiver ${receiverId} is not currently online`);
    }

    res.json({ message: "Friend request sent" });
  } catch (error) {
    console.error("Send request error:", error);
    res.status(500).json({ error: "Server error" });
  }
});

app.post("/api/accept-request", auth, async (req, res) => {
  try {
    const { friendId } = req.body;

    const user = await User.findById(req.user.userId).select(
      "username friendRequests friends"
    );
    const friend = await User.findById(friendId).select("username friends");

    if (!user || !friend) {
      return res.status(404).json({ error: "User not found" });
    }

    // Check if request exists
    if (!user.friendRequests.includes(friendId)) {
      return res
        .status(400)
        .json({ error: "No friend request from this user" });
    }

    // Remove from requests and add to friends
    user.friendRequests = user.friendRequests.filter(
      (id) => id.toString() !== friendId
    );
    user.friends.push(friendId);
    friend.friends.push(req.user.userId);

    await Promise.all([user.save(), friend.save()]);

    // Emit event to the sender of the request
    if (userSocketMap.has(friendId)) {
      io.to(friendId).emit("friendRequestAccepted", {
        accepterId: req.user.userId,
        accepterUsername: user.username,
      });
      console.log(
        `Friend request acceptance emitted to ${friendId} from ${req.user.userId}`
      );
    } else {
      console.log(
        `Friend ${friendId} is not currently online to receive acceptance`
      );
    }

    res.json({ message: "Friend request accepted" });
  } catch (error) {
    console.error("Accept request error:", error);
    res.status(500).json({ error: "Server error" });
  }
});

app.get("/api/friend-requests/:userId", auth, async (req, res) => {
  try {
    if (req.params.userId !== req.user.userId) {
      return res.status(403).json({ error: "Unauthorized" });
    }

    const user = await User.findById(req.params.userId).populate(
      "friendRequests",
      "username email profilePic"
    );

    if (!user) {
      return res.status(404).json({ error: "User not found" });
    }

    res.json(user.friendRequests);
  } catch (error) {
    console.error("Get friend requests error:", error);
    res.status(500).json({ error: "Server error" });
  }
});

app.get("/api/friends/:userId", auth, async (req, res) => {
  try {
    if (req.params.userId !== req.user.userId) {
      return res.status(403).json({ error: "Unauthorized" });
    }

    const user = await User.findById(req.params.userId).populate(
      "friends",
      "username email profilePic lastActive"
    );

    if (!user) {
      return res.status(404).json({ error: "User not found" });
    }

    res.json(user.friends);
  } catch (error) {
    console.error("Get friends error:", error);
    res.status(500).json({ error: "Server error" });
  }
});

app.get("/api/messages/:friendId", auth, async (req, res) => {
  try {
    const messages = await Message.find({
      $or: [
        { sender: req.user.userId, receiver: req.params.friendId },
        { sender: req.params.friendId, receiver: req.user.userId },
      ],
    }).sort({ createdAt: 1 });
    res.json(messages);
  } catch (error) {
    console.error("Get messages error:", error);
    res.status(500).json({ error: "Server error" });
  }
});

// Socket.IO handling
io.use((socket, next) => {
  try {
    const token = socket.handshake.auth.token;
    if (!token) {
      return next(new Error("Authentication token missing"));
    }

    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    socket.userId = decoded.userId;
    next();
  } catch (error) {
    console.error("Socket authentication error:", error);
    next(new Error("Authentication failed"));
  }
});

io.on("connection", (socket) => {
  const userId = socket.userId;
  console.log("User connected:", userId);

  // Store the socket id mapped to the user id
  if (!userSocketMap.has(userId)) {
    userSocketMap.set(userId, new Set());
  }
  userSocketMap.get(userId).add(socket.id);

  // Join a room with the user's ID
  socket.join(userId);

  // Update user's last active status
  User.findByIdAndUpdate(userId, { lastActive: new Date() }).catch((err) => {
    console.error("Error updating last active status:", err);
  });

  // Handle the register event from the frontend
  socket.on("register", ({ userId }) => {
    if (userId && userId === socket.userId) {
      console.log(`User ${userId} registered their socket connection`);

      // Make sure they're in their own room
      socket.join(userId);

      // Update the socket map
      if (!userSocketMap.has(userId)) {
        userSocketMap.set(userId, new Set());
      }
      userSocketMap.get(userId).add(socket.id);
    }
  });

  socket.on("friendRequest", async (data) => {
    try {
      const { receiverId, senderId } = data;

      // Verify sender ID matches socket user ID
      if (senderId && senderId !== userId) {
        console.error(
          `User ID mismatch in friendRequest: ${senderId} vs ${userId}`
        );
        return;
      }

      const sender = await User.findById(userId).select("username");

      if (!sender) {
        console.error("Sender not found:", userId);
        return;
      }

      console.log(`Emitting friendRequest from ${userId} to ${receiverId}`);

      // Emit both event names for compatibility
      io.to(receiverId).emit("newFriendRequest", {
        senderId: userId,
        senderUsername: sender.username,
      });

      io.to(receiverId).emit("friendRequest", {
        senderId: userId,
        senderUsername: sender.username,
      });
    } catch (error) {
      console.error("Error in friendRequest event:", error);
    }
  });

  socket.on("friendRequestAccepted", async (data) => {
    try {
      const { senderId, receiverId } = data;

      // Verify receiver ID matches socket user ID
      if (receiverId && receiverId !== userId) {
        console.error(
          `User ID mismatch in friendRequestAccepted: ${receiverId} vs ${userId}`
        );
        return;
      }

      const accepter = await User.findById(userId).select("username");

      if (!accepter) {
        console.error("Accepter not found:", userId);
        return;
      }

      console.log(
        `Emitting friendRequestAccepted from ${userId} to ${senderId}`
      );
      io.to(senderId).emit("friendRequestAccepted", {
        accepterId: userId,
        accepterUsername: accepter.username,
      });
    } catch (error) {
      console.error("Error in friendRequestAccepted event:", error);
    }
  });

  socket.on("privateMessage", async (data) => {
    try {
      const message = new Message({
        sender: userId,
        receiver: data.receiver,
        text: data.text,
      });
      await message.save();

      const messageData = {
        messageId: message._id,
        sender: userId,
        receiver: data.receiver,
        text: message.text,
        createdAt: message.createdAt,
      };

      console.log(`Sending message from ${userId} to ${data.receiver}`);
      // Send to both sender and receiver rooms
      io.to(data.receiver).to(userId).emit("newMessage", messageData);
    } catch (error) {
      console.error("Message error:", error);
      socket.emit("messageError", { error: "Failed to send message" });
    }
  });

  socket.on("disconnect", () => {
    console.log("User disconnected:", userId);

    // Remove this socket from the user's set of active connections
    if (userSocketMap.has(userId)) {
      const userSockets = userSocketMap.get(userId);
      userSockets.delete(socket.id);

      // If no more active connections for this user, remove from map
      if (userSockets.size === 0) {
        userSocketMap.delete(userId);
      }
    }

    // Update last active status on disconnect
    User.findByIdAndUpdate(userId, { lastActive: new Date() }).catch((err) => {
      console.error("Error updating last active status on disconnect:", err);
    });
  });
});

const PORT = process.env.PORT || 3500;
server.listen(PORT, () => console.log(`Server running on port ${PORT}`));
