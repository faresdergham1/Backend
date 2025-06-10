require("dotenv").config(); // Load environment variables from .env file
const express = require("express");
const mongoose = require("mongoose");
const cors = require("cors");
const helmet = require("helmet");
const morgan = require("morgan");
const rateLimit = require("express-rate-limit");
const compression = require("compression");
const swaggerUi = require("swagger-ui-express");
const fs = require("fs");
const path = require("path");
const nodemailer = require("nodemailer");
const axios = require("axios");
const jwt = require("jsonwebtoken");
const Joi = require("joi");
const bcrypt = require("bcryptjs");
const multer = require("multer");

// --- Configuration Constants ---
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET;
const MONGO_URI = process.env.MONGO_URI;
const DEVICE_API_KEYS = (process.env.DEVICE_API_KEYS || "")
  .split(",")
  .map(key => key.trim())
  .filter(key => key !== '');
const MAIL_USER = process.env.MAIL_USER;
const MAIL_PASS = process.env.MAIL_PASS;
const ADMIN_EMAIL = process.env.ADMIN_EMAIL;
const INTERNAL_AI_API_KEY = process.env.INTERNAL_AI_API_KEY;

// --- Input Validation for Essential Environment Variables ---
if (!JWT_SECRET) {
  console.error("CRITICAL ERROR: JWT_SECRET is not defined in .env");
  process.exit(1);
}
if (!MONGO_URI) {
  console.error("CRITICAL ERROR: MONGO_URI is not defined in .env");
  process.exit(1);
}
if (DEVICE_API_KEYS.length === 0) {
  console.warn("WARNING: DEVICE_API_KEYS is not defined or is empty in .env. Device uploads will be denied.");
}

// --- Mongoose Models ---
const userSchema = new mongoose.Schema({
  email: { type: String, required: true, unique: true, lowercase: true, trim: true },
  password: { type: String, required: true, minlength: 8 },
  role: { type: String, enum: ["admin", "user", "viewer"], default: "user" },
  createdAt: { type: Date, default: Date.now },
});
userSchema.pre("save", async function (next) {
  if (this.isModified("password")) {
    this.password = await bcrypt.hash(this.password, 10);
  }
  next();
});
userSchema.methods.comparePassword = function (candidatePassword) {
  return bcrypt.compare(candidatePassword, this.password);
};
const User = mongoose.model("User", userSchema);

const logSchema = new mongoose.Schema({
  type: { type: String, required: true, enum: ["error", "alert", "sensor_data", "image_upload", "user_auth", "system", "device_control"] },
  message: { type: String, required: true },
  timestamp: { type: Date, default: Date.now },
  esp_id: { type: String, required: false },
  details: { type: mongoose.Schema.Types.Mixed }
});
const Logs = mongoose.model("Log", logSchema);

const sensorDataSchema = new mongoose.Schema({
  esp_id: { type: String, required: true, trim: true },
  soil_moisture: { type: Number, min: 0, max: 100 },
  tds: { type: Number, min: 0 },
  temperature: { type: Number },
  humidity: { type: Number, min: 0, max: 100 },
  ldr: { type: Number, min: 0 },
  motor_status: { type: String, enum: ["on", "off"], default: "off" },
  pump_status: { type: String, enum: ["on", "off"], default: "off" },
  sr206_motion: { type: Boolean },
  timestamp: { type: Date, default: Date.now },
}, { timestamps: true });
const SensorData = mongoose.model("SensorData", sensorDataSchema);

const imageDataSchema = new mongoose.Schema({
  filename: { type: String, required: true, unique: true },
  originalName: { type: String },
  mimetype: { type: String },
  size: { type: Number },
  url: { type: String, required: true },
  esp_id: { type: String, required: true },
  timestamp: { type: Date, default: Date.now },
}, { timestamps: true });
const ImageData = mongoose.model("ImageData", imageDataSchema);

const aiResultSchema = new mongoose.Schema({
  image_id: { type: mongoose.Schema.Types.ObjectId, ref: "ImageData", required: true },
  status: { type: String, required: true },
  confidence: { type: Number, required: true, min: 0, max: 1 },
  detectedObjects: { type: [String] },
  timestamp: { type: Date, default: Date.now },
}, { timestamps: true });
const AIResult = mongoose.model("AIResult", aiResultSchema);

// --- Connect to MongoDB ---
mongoose
  .connect(MONGO_URI)
  .then(() => console.log("MongoDB connected successfully."))
  .catch((err) => {
    console.error("MongoDB connection error:", err.message);
    systemLogger("error", "MongoDB connection failed.", null, { error: err.message });
    process.exit(1);
  });

// --- Express App Init ---
const app = express();

// --- Global Middleware ---
app.use(express.json({ limit: "10mb" }));
app.use(express.urlencoded({ extended: true }));
app.use(cors({
  origin: process.env.CORS_ORIGIN || '*',
  methods: ['GET', 'POST', 'PUT', 'DELETE'],
  allowedHeaders: ['Content-Type', 'Authorization', 'x-api-key', 'x-esp-id', 'x-internal-ai-key'],
}));
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      ...helmet.contentSecurityPolicy.getDefaultDirectives(),
      "img-src": ["'self'", "data:", "https://img.icons8.com", "https://.swagger.io", "http://localhost:"],
      "media-src": ["'self'", "https://assets.mixkit.co"],
      "script-src": ["'self'", "'unsafe-inline'", "'unsafe-eval'", "https://cdn.jsdelivr.net"],
      "style-src": ["'self'", "'unsafe-inline'", "https://cdn.jsdelivr.net"],
    },
  },
}));
app.use(compression());
app.use(morgan("combined"));

// Serve static images
const imagesDir = path.join(__dirname, 'uploads', 'images');
if (!fs.existsSync(imagesDir)) {
  try {
    fs.mkdirSync(imagesDir, { recursive: true });
    console.log(Created uploads/images directory at ${imagesDir});
  } catch (mkdirErr) {
    console.error(Failed to create uploads/images directory: ${mkdirErr.message});
    // لو systemLogger مش معرف فوق هنا هيتجاهل السطر ده، لو محتاجه فعلها
  }
}
app.use('/uploads/images', express.static(imagesDir));

// --- Rate Limiting ---
const apiLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 100,
  standardHeaders: true,
  legacyHeaders: false,
  message: {
    status: "fail",
    error: "Too many requests, please try again later."
  },
});
const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 8,
  standardHeaders: true,
  legacyHeaders: false,
  message: {
    status: "fail",
    error: "Too many authentication attempts from this IP, please try again after 15 minutes."
  },
});
const deviceUploadLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 30,
  keyGenerator: (req) => req.headers["x-esp-id"] || req.ip,
  standardHeaders: true,
  legacyHeaders: false,
  message: {
    status: "fail",
    error: "Too many uploads from this device, please slow down."
  },
});

// --- Image Upload Storage Configuration (Multer) ---
const storage = multer.diskStorage({
  destination: (req, file, cb) => { cb(null, imagesDir); },
  filename: (req, file, cb) => {
    const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1E9);
    cb(null, file.fieldname + '-' + uniqueSuffix + path.extname(file.originalname));
  },
});
const upload = multer({
  storage: storage,
  limits: { fileSize: 5 * 1024 * 1024 },
  fileFilter: (req, file, cb) => {
    const allowedTypes = /jpeg|jpg|png|gif/;
    const extname = allowedTypes.test(path.extname(file.originalname).toLowerCase());
    const mimetype = allowedTypes.test(file.mimetype);
    if (mimetype && extname) {
      return cb(null, true);
    } else {
      cb(new Error("Only images (jpeg, jpg, png, gif) are allowed!"));
    }
  },
});

// --- Utility Functions ---
const systemLogger = async (type, message, esp_id = null, details = {}) => {
  try { await Logs.create({ type, message, esp_id, details }); }
  catch (error) { console.error("Failed to write log to DB:", error); }
};
const transporter = nodemailer.createTransport({
  service: "gmail",
  auth: { user: MAIL_USER, pass: MAIL_PASS },
});
const sendAlertEmail = async (subject, text) => {
  if (!ADMIN_EMAIL || !MAIL_USER || !MAIL_PASS) {
    console.warn("Email credentials (MAIL_USER, MAIL_PASS) or ADMIN_EMAIL not configured. Skipping email alert.");
    systemLogger("alert", Email config missing. Alert not sent: ${subject});
    return;
  }
  try {
    await transporter.sendMail({
      from: MAIL_USER,
      to: ADMIN_EMAIL,
      subject: Smart Farming Alert: ${subject},
      text: text,
    });
    systemLogger("alert", Email alert sent: ${subject});
  } catch (error) {
    systemLogger("error", Failed to send email alert: ${subject}, null, { error: error.message });
    console.error("Error sending email:", error);
  }
};

// --- Minimal Route for testing ---
app.get("/", (req, res) => {
  res.send("Server is running and ready!");
});

// --- Swagger UI route (dummy doc to avoid crash if not complete) ---
const swaggerDocument = {
  openapi: "3.0.0",
  info: {
    title: "Smart Agriculture System API",
    version: "1.0.0",
    description: "API documentation for the Smart Agriculture Monitoring and Control System.",
  },
  paths: {}
};
app.use('/api-docs', swaggerUi.serve, swaggerUi.setup(swaggerDocument));

// --- Start server ---
app.listen(PORT, () => {
  console.log(Server running on port ${PORT});
});
