require("dotenv").config();
const express = require("express");
const multer = require("multer");
const cloudinary = require("cloudinary").v2;
const cors = require("cors");
const rateLimit = require("express-rate-limit");
const helmet = require("helmet");
const session = require("express-session");

const app = express();

app.use(
  cors({
    origin: process.env.FRONTEND_URL,
    credentials: true,
  })
);

app.use(helmet());
app.use(express.json());

app.set("trust proxy", 1);

const limiter = rateLimit({
  windowMs: 1 * 60 * 1000,
  max: 10,
});
app.use(limiter);

app.use(
  session({
    secret: process.env.SESSION_SECRET || "changeme",
    resave: false,
    saveUninitialized: false,
    cookie: {
      httpOnly: true,
      secure: process.env.NODE_ENV === "production", // Only true in production with HTTPS
      sameSite: "none",
      maxAge: 5 * 60 * 1000,
    },
  })
);

// --- Cloudinary Config ---
cloudinary.config({
  cloud_name: process.env.CLOUDINARY_CLOUD_NAME,
  api_key: process.env.CLOUDINARY_API_KEY,
  api_secret: process.env.CLOUDINARY_API_SECRET,
});

// --- Multer Config ---
const storage = multer.memoryStorage();
const fileFilter = (req, file, cb) => {
  if (file.mimetype !== "application/pdf") {
    return cb(new Error("Only PDF files are allowed."));
  }
  cb(null, true);
};
const upload = multer({
  storage,
  fileFilter,
  limits: { fileSize: 5 * 1024 * 1024 },
});

// --- Routes ---
app.get("/", (req, res) => {
  res.send("Secure file upload service is running.");
});

app.get("/ping", (req, res) => {
  res.send("Server is Running");
});

// Step 1: Start session for uploading
app.post("/start-upload-session", (req, res) => {
  req.session.canUpload = true;
  console.log("Session started:", req.session);
  res.json({ message: "Upload session started." });
});

// Step 2: Upload route — checks session, not token
const checkUploadPermission = (req, res, next) => {
  if (!req.session.canUpload) {
    return res.status(403).json({ error: "Unauthorized access" });
  }
  next();
};

app.post("/upload", checkUploadPermission, upload.single("file"), (req, res) => {
  if (!req.file) return res.status(400).send("No file uploaded.");

  cloudinary.uploader
    .upload_stream({ resource_type: "raw" }, (error, result) => {
      if (error) return res.status(500).send(error.message);
      res.json({ url: result.secure_url, public_id: result.public_id });
    })
    .end(req.file.buffer);
});

app.delete("/delete", checkUploadPermission, async (req, res) => {
  const publicId = req.body.public_id;
  if (!publicId) return res.status(400).send("Missing public_id.");

  try {
    const result = await cloudinary.uploader.destroy(publicId, {
      resource_type: "raw",
    });
    res.json(result);
  } catch (err) {
    res.status(500).send(err.message);
  }
});

const PORT = process.env.PORT || 8080;
app.listen(PORT, () => console.log(`🚀 Secure Server running on http://localhost:${PORT}`));
