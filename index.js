require("dotenv").config();
const express = require("express");
const http = require("http");
const { Server } = require("socket.io");
const cors = require("cors");
const mongoose = require("mongoose");
const Y = require("yjs");
const jwt = require("jsonwebtoken");
const bcrypt = require("bcrypt");
const User = require("./models/User");

const app = express();
const server = http.createServer(app);

// --- 1. MIDDLEWARE ---
app.use(express.json());

const allowedOrigins = [
  "http://localhost:3000",
  "https://collaborative-editor-client-two.vercel.app",
  "https://collaborative-editor-client-1mmcbutsk-ekram2004s-projects.vercel.app",
];

app.use(
  cors({
    origin: (origin, callback) => {
      if (!origin || allowedOrigins.includes(origin)) callback(null, true);
      else callback(new Error("Not allowed by CORS"));
    },
    credentials: true,
  })
);

const SECRET_KEY = process.env.SECRET_KEY || "your_super_secret_key";

const verifyToken = (req, res, next) => {
  const token = req.headers["authorization"]?.split(" ")[1];
  if (!token) return res.status(403).json({ message: "Token required" });

  jwt.verify(token, SECRET_KEY, (err, decoded) => {
    if (err) return res.status(401).json({ message: "Invalid token" });
    req.userId = decoded.userId;
    next();
  });
};

// --- 2. AUTH ROUTES ---
app.post("/auth/register", async (req, res) => {
  try {
    const { username, password } = req.body;
    if (!username || !password) throw new Error("Missing fields");
    const user = new User({ username, password });
    await user.save();
    res.status(201).json({ message: "User registered" });
  } catch (err) {
    res.status(400).json({ message: err.message });
  }
});

app.post("/auth/login", async (req, res) => {
  try {
    const { username, password } = req.body;
    const user = await User.findOne({ username });
    if (user && (await bcrypt.compare(password, user.password))) {
      const token = jwt.sign({ userId: user._id }, SECRET_KEY, {
        expiresIn: "24h",
      });
      res.json({ token, username });
    } else {
      res.status(401).json({ message: "Invalid credentials" });
    }
  } catch (err) {
    res.status(500).json({ message: "Server error" });
  }
});

// --- 3. DOCUMENT LOGIC ---
const Document = mongoose.model(
  "Document",
  new mongoose.Schema(
    {
      _id: String,
      data: Buffer,
      owner: {
        type: mongoose.Schema.Types.ObjectId,
        ref: "User",
        required: true,
      },
      title: { type: String, default: "Untitled Document" },
      language: { type: String, default: "javascript" },
    },
    { timestamps: true }
  )
);

app.get("/documents", verifyToken, async (req, res) => {
  const docs = await Document.find({ owner: req.userId }).sort({
    updatedAt: -1,
  });
  res.json(docs);
});

app.get("/documents/:id/meta", verifyToken, async (req, res) => {
  const doc = await Document.findOne({ _id: req.params.id, owner: req.userId });
  if (!doc) return res.status(404).json({ message: "Not found" });
  res.json(doc);
});

app.post("/documents/:id/meta", verifyToken, async (req, res) => {
  const { title, language } = req.body;
  const doc = await Document.findOneAndUpdate(
    { _id: req.params.id },
    { title, language, owner: req.userId },
    { upsert: true, new: true }
  );
  res.json(doc);
});

app.delete("/documents/:id", verifyToken, async (req, res) => {
  await Document.deleteOne({ _id: req.params.id, owner: req.userId });
  res.json({ message: "Deleted" });
});

// --- 4. SOCKET.IO ---
const io = new Server(server, { cors: { origin: allowedOrigins } });
const activeDocs = {};

io.on("connection", (socket) => {
  socket.on("join-document", async (documentId) => {
    socket.join(documentId);
    if (!activeDocs[documentId]) {
      const doc = await Document.findById(documentId);
      const ydoc = new Y.Doc();
      if (doc?.data) Y.applyUpdate(ydoc, doc.data);
      activeDocs[documentId] = ydoc;
    }
    socket.emit("load-document", Y.encodeStateAsUpdate(activeDocs[documentId]));
  });

  socket.on("send-changes", ({ documentId, delta }) => {
    const ydoc = activeDocs[documentId];
    if (ydoc) {
      Y.applyUpdate(ydoc, new Uint8Array(delta));
      socket.to(documentId).emit("receive-changes", delta);
      // Debounced save
      clearTimeout(ydoc.saveTimer);
      ydoc.saveTimer = setTimeout(async () => {
        await Document.findByIdAndUpdate(documentId, {
          data: Buffer.from(Y.encodeStateAsUpdate(ydoc)),
        });
      }, 2000);
    }
  });
});

const PORT = process.env.PORT || 3001;
mongoose.connect(process.env.DATABASE_URL).then(() => {
  server.listen(PORT, () => console.log(`🚀 Server on ${PORT}`));
});
