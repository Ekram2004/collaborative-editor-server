if (process.env.NODE_ENV !== "production") {
  require("dotenv").config();
}
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
app.use(express.json());
app.use(
  cors({
    origin: "https://collaborative-editor-client-two.vercel.app/", // Your Vercel URL
    methods: ["GET", "POST"],
  })
);

const SECRET_KEY = "your_super_secret_key";

// --- MIDDLEWARE: VERIFY TOKEN ---
const verifyToken = (req, res, next) => {
  // Check for "Authorization: Bearer <token>"
  const authHeader = req.headers["authorization"];
  const token = authHeader && authHeader.split(" ")[1];

  if (!token) return res.status(403).json({ message: "Token required" });

  jwt.verify(token, SECRET_KEY, (err, decoded) => {
    if (err)
      return res.status(401).json({ message: "Invalid or expired token" });
    req.userId = decoded.userId;
    next();
  });
};

// --- AUTH ROUTES ---
app.post("/auth/register", async (req, res) => {
  try {
    const { username, password } = req.body;
    const user = new User({ username, password });
    await user.save();
    res.status(201).json({ message: "User registered" });
  } catch (err) {
    res.status(400).json({ message: "Registration failed: " + err.message });
  }
});

app.post("/auth/login", async (req, res) => {
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
});

// --- DOCUMENT SCHEMA & MODEL ---
const DocumentSchema = new mongoose.Schema(
  {
    _id: String,
    data: Buffer,
    owner: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "User",
      required: true,
    }, // Link to User
    title: { type: String, default: "Untitled Document" },
    language: { type: String, default: "javascript" }, // Fixed: was Date
  },
  { timestamps: true }
);

const Document = mongoose.model("Document", DocumentSchema);

// --- DOCUMENT REST ROUTES ---

// 1. Get ALL documents for the logged-in user (DASHBOARD)
app.get("/documents", verifyToken, async (req, res) => {
  try {
    const docs = await Document.find({ owner: req.userId })
      .select("title language updatedAt") // Only return what the dashboard needs
      .sort({ updatedAt: -1 });
    res.json(docs);
  } catch (err) {
    res.status(500).send(err.message);
  }
});

// 2. Get metadata for a specific document
app.get("/documents/:id/meta", verifyToken, async (req, res) => {
  const doc = await Document.findOne({ _id: req.params.id, owner: req.userId });
  if (!doc)
    return res
      .status(404)
      .json({ error: "Document not found or access denied" });

  res.json({
    title: doc.title,
    language: doc.language,
    updatedAt: doc.updatedAt,
  });
});

// 3. Update metadata (or create new document entry)
app.post("/documents/:id/meta", verifyToken, async (req, res) => {
  const { title, language } = req.body;
  try {
    await Document.findByIdAndUpdate(
      req.params.id,
      {
        ...(title && { title }),
        ...(language && { language }),
        owner: req.userId, // Ensure the owner is set on creation
      },
      { upsert: true, new: true }
    );
    res.sendStatus(200);
  } catch (err) {
    res.status(500).send(err.message);
  }
});
// DELETE a document
app.delete("/documents/:id", verifyToken, async (req, res) => {
  try {
    const result = await Document.findOneAndDelete({
      _id: req.params.id,
      owner: req.userId,
    });

    if (!result) {
      return res
        .status(404)
        .json({ message: "Document not found or unauthorized" });
    }

    res.json({ message: "Document deleted successfully" });
  } catch (err) {
    res.status(500).send(err.message);
  }
});

// --- SOCKET.IO LOGIC ---
const server = http.createServer(app);
const io = new Server(server, {
  cors: {
    origin: "https://collaborative-editor-client-two.vercel.app/",
    methods: ["GET", "POST"],
  },
});

const saveTimers = {};
const activeDocs = {};

io.on("connection", (socket) => {
  socket.on("join-document", async (documentId) => {
    socket.join(documentId);

    let docData;
    if (activeDocs[documentId]) {
      docData = Y.encodeStateAsUpdate(activeDocs[documentId]);
    } else {
      const existingDoc = await Document.findById(documentId);
      if (existingDoc) {
        docData = existingDoc.data;
        const ydoc = new Y.Doc();
        Y.applyUpdate(ydoc, existingDoc.data);
        activeDocs[documentId] = ydoc;
      }
    }
    if (docData) socket.emit("load-document", docData);
  });

  socket.on("send-changes", ({ documentId, delta }) => {
    socket.to(documentId).emit("receive-changes", delta);

    if (!activeDocs[documentId]) activeDocs[documentId] = new Y.Doc();
    Y.applyUpdate(activeDocs[documentId], new Uint8Array(delta));

    if (saveTimers[documentId]) clearTimeout(saveTimers[documentId]);

    saveTimers[documentId] = setTimeout(async () => {
      try {
        const fullState = Y.encodeStateAsUpdate(activeDocs[documentId]);
        // Note: Socket saves don't have access to req.userId easily,
        // so we assume the doc was already created with an owner via the REST API
        await Document.findByIdAndUpdate(documentId, {
          data: Buffer.from(fullState),
        });
      } catch (e) {
        console.error("Save error:", e);
      }
    }, 2000);
  });

  socket.on("cursor-movement", ({ documentId, awarenessUpdate }) => {
    socket.to(documentId).emit("cursor-update", awarenessUpdate);
  });
});

mongoose
  .connect(process.env.MONGO_URI)
  .then(() =>
    server.listen(3001, () => console.log("🚀 Server & DB Ready on port 3001"))
  );
