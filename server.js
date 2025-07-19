require("dotenv").config();
const express = require("express");
const multer = require("multer");
const cloudinary = require("cloudinary").v2;
const fs = require("fs");
const cors = require("cors");
const rateLimit = require("express-rate-limit");

const app = express();
app.use(cors());
app.use(express.json());

// ✅ Rate Limiting
const limiter = rateLimit({
  windowMs: 1 * 60 * 1000, // 1 minute
  max: 10, // limit each IP to 10 requests per minute
});
app.use(limiter);

// ✅ Cloudinary Config
cloudinary.config({
  cloud_name: process.env.CLOUDINARY_CLOUD_NAME,
  api_key: process.env.CLOUDINARY_API_KEY,
  api_secret: process.env.CLOUDINARY_API_SECRET,
});

// ✅ Multer Setup (Restrict to PDF, limit file size)
const storage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, "uploads/"),
  filename: (req, file, cb) => cb(null, Date.now() + "-" + file.originalname),
});

const fileFilter = (req, file, cb) => {
  const allowedTypes = ["application/pdf"];
  if (!allowedTypes.includes(file.mimetype)) {
    return cb(new Error("Only PDF files are allowed."));
  }
  cb(null, true);
};

const upload = multer({
  storage,
  fileFilter,
  limits: { fileSize: 5 * 1024 * 1024 }, // 5MB max
});

// ✅ Simple Token-Based Authentication
const authenticate = (req, res, next) => {
  const authHeader = req.headers.authorization;
  if (!authHeader || authHeader !== `Bearer ${process.env.UPLOAD_TOKEN}`) {
    return res.status(403).send("Unauthorized.");
  }
  next();
};

// ✅ Routes
app.get("/", (req, res) => {
  res.send("Secure file upload service is running.");
});

// ✅ Upload Route (Secured)
app.post("/upload", authenticate, upload.single("file"), async (req, res) => {
  try {
    if (!req.file) return res.status(400).send("No file uploaded.");

    const result = await cloudinary.uploader.upload(req.file.path, {
      resource_type: "raw",
    });

    fs.unlinkSync(req.file.path);
    res.json({ url: result.secure_url, public_id: result.public_id });
  } catch (err) {
    res.status(500).send(err.message);
  }
});

// ✅ Delete Route (Secured)
app.delete("/delete", authenticate, async (req, res) => {
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

app.listen(8080, () =>
  console.log("🚀 Secure Server running on http://localhost:8080")
);
