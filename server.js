require("dotenv").config();
const express = require("express");
const multer = require("multer");
const cloudinary = require("cloudinary").v2;
const cors = require("cors");
const rateLimit = require("express-rate-limit");

const app = express();
app.use(cors());
app.use(express.json());

const limiter = rateLimit({
  windowMs: 1 * 60 * 1000,
  max: 10,
});
app.use(limiter);

cloudinary.config({
  cloud_name: process.env.CLOUDINARY_CLOUD_NAME,
  api_key: process.env.CLOUDINARY_API_KEY,
  api_secret: process.env.CLOUDINARY_API_SECRET,
});

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

const authenticate = (req, res, next) => {
  const authHeader = req.headers.authorization;
  if (!authHeader || authHeader !== `Bearer ${process.env.UPLOAD_TOKEN}`) {
    return res.status(403).send("Unauthorized.");
  }
  next();
};

app.get("/", (req, res) => {
  res.send("Secure file upload service is running.");
});

app.post("/upload", authenticate, upload.single("file"), (req, res) => {
  if (!req.file) return res.status(400).send("No file uploaded.");

  cloudinary.uploader
    .upload_stream({ resource_type: "raw" }, (error, result) => {
      if (error) return res.status(500).send(error.message);
      res.json({ url: result.secure_url, public_id: result.public_id });
    })
    .end(req.file.buffer);
});

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

const PORT = process.env.PORT || 8080;
app.listen(PORT, () => console.log(`🚀 Secure Server running on http://localhost:${PORT}`));
