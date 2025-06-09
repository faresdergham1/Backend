
// ====== server.js (Production-grade, Modular, Secure, Documented) ======
require("dotenv").config();
const express      = require("express");
const mongoose     = require("mongoose");
const cors         = require("cors");
const helmet       = require("helmet");
const morgan       = require("morgan");
const rateLimit    = require("express-rate-limit");
const compression  = require("compression");
const swaggerUi    = require("swagger-ui-express");
const fs           = require("fs");
const path         = require("path");
const nodemailer   = require("nodemailer");
const axios        = require("axios");
const jwt          = require("jsonwebtoken");
const Joi          = require("joi");
const bcrypt       = require("bcryptjs");

// ========== Import Routers ==========
const sensorRoutes    = require("./routes/sensors");
const imageRoutes     = require("./routes/images");
const aiRoutes        = require("./routes/ai");
const controlRoutes   = require("./routes/control");
const authMiddleware  = require("./utils/authMiddleware");
const roleMiddleware  = require("./utils/roleMiddleware");
const Logs            = require("./models/Logs");
const SensorData      = require("./models/SensorData");
const ImageData       = require("./models/ImageData");
const User            = require("./models/User");
const AIResult        = require("./models/AIResult");
const swaggerDocument = require("./swagger.json");

// ========== App Init ==========
const app = express();

// ========== Secure Rate Limiting ==========
const limiter = rateLimit({
  windowMs: 60 * 1000,
  max: 60,
  keyGenerator: (req) => req.headers["esp-id"] || req.ip,
  message: { status: "fail", error: "Too many requests. Please slow down." }
});
const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 8,
  message: { status: "fail", error: "Too many auth attempts. Try later." }
});
const uploadLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 20,
  message: { status: "fail", error: "Too many uploads. Please slow down." }
});

// ========== Device API Key Middleware ==========
const validDeviceKeys = (process.env.DEVICE_KEYS || "").split(",");
function deviceApiKeyMiddleware(req, res, next) {
  const apiKey = req.headers["x-api-key"];
  if (!apiKey || !validDeviceKeys.includes(apiKey)) {
    return res.status(401).json({ status: "fail", error: "Invalid device API key" });
  }
  next();
}

// ========== HTTPS (Production Proxy) ==========
if (process.env.NODE_ENV === "production") {
  app.set("trust proxy", 1);
}

// ========== Middleware Setup ==========
app.use(helmet());
app.use(cors({ origin: process.env.ALLOWED_ORIGINS?.split(",") || "*" }));
app.use(limiter);
app.use(compression());
app.use(express.json({ limit: "16mb" }));
app.use(morgan("dev"));
app.use("/uploads", express.static(path.join(__dirname, "uploads")));

// ========== MongoDB Connection ==========
mongoose.connect(process.env.MONGO_URI, { useNewUrlParser: true, useUnifiedTopology: true });
mongoose.connection.on("connected", () => console.log("✅ MongoDB connected"));
mongoose.connection.on("error", (err) => {
  console.error("❌ MongoDB error:", err);
  sendSystemAlert("MongoDB Error: " + err.message);
});

// ========== Alerts (Email/Telegram) ==========
const EMAIL_ENABLED = process.env.EMAIL_ENABLED === "true";
const TELEGRAM_ENABLED = process.env.TELEGRAM_ENABLED === "true";
const transporter = EMAIL_ENABLED ? nodemailer.createTransport({
  host: process.env.SMTP_HOST,
  port: 465,
  secure: true,
  auth: { user: process.env.SMTP_USER, pass: process.env.SMTP_PASS }
}) : null;
async function sendSystemAlert(msg) {
  if (TELEGRAM_ENABLED && process.env.TELEGRAM_TOKEN && process.env.TELEGRAM_CHAT_ID) {
    await axios.get(`https://api.telegram.org/bot${process.env.TELEGRAM_TOKEN}/sendMessage`, {
      params: { chat_id: process.env.TELEGRAM_CHAT_ID, text: `🚨 [ALERT] ${msg}` }
    }).catch(() => {});
  }
  if (EMAIL_ENABLED && transporter) {
    await transporter.sendMail({
      from: process.env.SMTP_USER,
      to: process.env.ADMIN_EMAIL,
      subject: "System Alert",
      text: msg
    }).catch(() => {});
  }
  await Logs.create({ type: "alert", message: msg });
}

// ========== Auth Routes ==========
// ... Rest of the code remains unchanged
