/* ============================================================
   GREENBOOKS BACKEND — Express + MongoDB + Cloudinary
   Save as: server.js
   ============================================================ */
require("dotenv").config();

const express = require("express");
const mongoose = require("mongoose");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const cors = require("cors");
const helmet = require("helmet");
const morgan = require("morgan");
const rateLimit = require("express-rate-limit");
const multer = require("multer");
const crypto = require("crypto");
const cloudinary = require("cloudinary").v2;
const { CloudinaryStorage } = require("multer-storage-cloudinary");

const app = express();
const PORT = process.env.PORT || 5000;
const PLAN_AMOUNT = 500;
const PLAN_DAYS = 30;

if (!process.env.MONGO_URI) console.warn("WARNING: MONGO_URI is not configured.");
if (!process.env.JWT_SECRET) console.warn("WARNING: JWT_SECRET is not configured.");

cloudinary.config({
  cloud_name: process.env.CLOUDINARY_CLOUD_NAME,
  api_key: process.env.CLOUDINARY_API_KEY,
  api_secret: process.env.CLOUDINARY_API_SECRET,
});

const SUBJECTS = [
  "English", "Chichewa", "Mathematics", "Biology", "Agriculture",
  "Chemistry", "Physics", "Geography", "History", "Social Studies",
];

/* -------------------- File storage -------------------- */
// NOTE: resource_type is passed at top-level for CloudinaryStorage v4+
const pdfStorage = new CloudinaryStorage({
  cloudinary,
  params: {
    folder: "greenbooks/pdfs",
    resource_type: "raw",
    allowed_formats: ["pdf"],
  },
});
const coverStorage = new CloudinaryStorage({
  cloudinary,
  params: {
    folder: "greenbooks/covers",
    resource_type: "image",
    allowed_formats: ["jpg", "jpeg", "png", "webp"],
  },
});
const uploadPdf = multer({
  storage: pdfStorage,
  limits: { fileSize: 50 * 1024 * 1024 },
  fileFilter: (req, file, cb) => {
    if (file.mimetype !== "application/pdf") return cb(new Error("Please select a PDF file."));
    cb(null, true);
  },
});
const uploadCover = multer({
  storage: coverStorage,
  limits: { fileSize: 5 * 1024 * 1024 },
  fileFilter: (req, file, cb) => {
    if (!["image/jpeg", "image/png", "image/webp"].includes(file.mimetype)) {
      return cb(new Error("Cover must be JPG, PNG, or WEBP."));
    }
    cb(null, true);
  },
});

/* -------------------- MongoDB models -------------------- */
const userSchema = new mongoose.Schema({
  name: { type: String, required: true, trim: true },
  email: { type: String, required: true, unique: true, lowercase: true, trim: true },
  password: { type: String, required: true, minlength: 6, select: false },
  role: { type: String, enum: ["student", "admin"], default: "student" },
  hasPlan: { type: Boolean, default: false },
  planExpiry: { type: Date, default: null },
  downloads: [{
    book: { type: mongoose.Schema.Types.ObjectId, ref: "Book" },
    at: { type: Date, default: Date.now }
  }],
}, { timestamps: true });

userSchema.pre("save", async function () {
  if (!this.isModified("password")) return;
  this.password = await bcrypt.hash(this.password, 10);
});
userSchema.methods.matchPassword = function (entered) {
  return bcrypt.compare(entered, this.password);
};
userSchema.methods.isPlanActive = function () {
  return Boolean(this.hasPlan && this.planExpiry && this.planExpiry > new Date());
};
const User = mongoose.models.User || mongoose.model("User", userSchema);

const bookSchema = new mongoose.Schema({
  title: { type: String, required: true, trim: true },
  form: { type: Number, required: true, min: 1, max: 4 },
  subject: { type: String, required: true, enum: SUBJECTS },
  pdfUrl: { type: String, required: true },
  cloudinaryId: { type: String, required: true },
  coverUrl: { type: String, default: "" },
  coverCloudinaryId: { type: String, default: "" },
  downloads: { type: Number, default: 0 },
  uploadedBy: { type: mongoose.Schema.Types.ObjectId, ref: "User" },
}, { timestamps: true });
bookSchema.index({ form: 1, subject: 1 });
const Book = mongoose.models.Book || mongoose.model("Book", bookSchema);

const paymentSchema = new mongoose.Schema({
  user: { type: mongoose.Schema.Types.ObjectId, ref: "User", required: true },
  amount: { type: Number, required: true },
  currency: { type: String, default: "MWK" },
  status: { type: String, enum: ["pending", "success", "failed"], default: "pending" },
  provider: { type: String, default: "manual" },
  reference: { type: String, unique: true, sparse: true },
  meta: { type: Object, default: {} },
}, { timestamps: true });
// Auto-delete stale pending payments after 7 days (optional cleanup)
paymentSchema.index({ createdAt: 1 }, { expireAfterSeconds: 60 * 60 * 24 * 7 });
const Payment = mongoose.models.Payment || mongoose.model("Payment", paymentSchema);

/* -------------------- Middleware and helpers -------------------- */
const clientOrigins = (process.env.CLIENT_URL || "")
  .split(",").map(s => s.trim()).filter(Boolean);

app.use(helmet({ crossOriginResourcePolicy: { policy: "cross-origin" } }));
app.use(cors({
  origin(origin, callback) {
    // Allow requests with no origin (Postman, file://, mobile apps)
    if (!origin) return callback(null, true);
    if (clientOrigins.length === 0 || clientOrigins.includes("*")) return callback(null, true);
    if (clientOrigins.includes(origin)) return callback(null, true);
    return callback(new Error("Origin is not allowed by CORS."));
  },
  credentials: true,
}));
app.use(express.json({ limit: "1mb" }));
app.use(express.urlencoded({ extended: true }));
app.use(morgan("tiny"));

app.use("/api", rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 200,
  standardHeaders: "draft-7",
  legacyHeaders: false,
  message: { message: "Too many requests. Please try again later." },
}));

function signToken(id) {
  if (!process.env.JWT_SECRET) throw new Error("JWT_SECRET is not configured on the server.");
  return jwt.sign(
    { id: String(id) },
    process.env.JWT_SECRET,
    { expiresIn: process.env.JWT_EXPIRE || "7d" }
  );
}

function userPayload(user) {
  return {
    _id: user._id,
    name: user.name,
    email: user.email,
    role: user.role,
    hasPlan: user.hasPlan,
    planExpiry: user.planExpiry,
    isPlanActive: user.isPlanActive(),
  };
}

async function protect(req, res, next) {
  const header = req.headers.authorization || "";
  const token = header.startsWith("Bearer ") ? header.slice(7).trim() : "";

  if (!token) {
    return res.status(401).json({
      message: "Please log in; authorization token is missing."
    });
  }

  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    const user = await User.findById(decoded.id).select("-downloads");

    if (!user) return res.status(401).json({ message: "Account not found." });

    req.user = user;
    next();
  } catch (error) {
    return res.status(401).json({
      message: "Token is invalid or expired. Please log in again."
    });
  }
}

function adminOnly(req, res, next) {
  if (req.user?.role === "admin") return next();
  return res.status(403).json({ message: "Admin access required." });
}

function asyncRoute(fn) {
  return (req, res, next) =>
    Promise.resolve(fn(req, res, next)).catch(next);
}

function validObjectId(id) {
  return mongoose.isValidObjectId(id);
}

function signedPdfUrl(cloudinaryId, attachment = false, seconds = 3600) {
  return cloudinary.url(cloudinaryId, {
    resource_type: "raw",
    type: "upload",
    sign_url: true,
    expires_at: Math.floor(Date.now() / 1000) + seconds,
    ...(attachment ? { flags: "attachment" } : {}),
  });
}

/* -------------------- Health -------------------- */
app.get("/", (req, res) => res.json({
  status: "ok",
  service: "GreenBooks API",
  time: new Date().toISOString(),
}));

app.get("/api/health", (req, res) => res.json({
  status: "ok",
  database: mongoose.connection.readyState === 1 ? "connected" : "disconnected",
}));

/* -------------------- Authentication -------------------- */
app.post("/api/auth/register", asyncRoute(async (req, res) => {
  const name = String(req.body.name || "").trim();
  const email = String(req.body.email || "").trim().toLowerCase();
  const password = String(req.body.password || "");

  if (!name || !email || !password) {
    return res.status(400).json({ message: "Name, email and password are required." });
  }
  if (password.length < 6) {
    return res.status(400).json({ message: "Password must be at least 6 characters." });
  }
  if (await User.findOne({ email })) {
    return res.status(409).json({ message: "Email already registered." });
  }

  const user = await User.create({ name, email, password });
  res.status(201).json({ token: signToken(user._id), user: userPayload(user) });
}));

app.post("/api/auth/login", asyncRoute(async (req, res) => {
  const email = String(req.body.email || "").trim().toLowerCase();
  const password = String(req.body.password || "");

  if (!email || !password) {
    return res.status(400).json({ message: "Email and password are required." });
  }

  const user = await User.findOne({ email }).select("+password");

  if (!user || !(await user.matchPassword(password))) {
    return res.status(401).json({ message: "Invalid email or password." });
  }

  if (user.hasPlan && user.planExpiry && user.planExpiry <= new Date()) {
    user.hasPlan = false;
    await user.save();
  }

  res.json({ token: signToken(user._id), user: userPayload(user) });
}));

app.get("/api/auth/me", protect, (req, res) =>
  res.json({ user: userPayload(req.user) })
);

/* -------------------- Books -------------------- */
app.get("/api/books", asyncRoute(async (req, res) => {
  const filter = {};

  if (req.query.form) {
    const form = Number(req.query.form);
    if (![1, 2, 3, 4].includes(form)) {
      return res.status(400).json({ message: "Form must be 1, 2, 3 or 4." });
    }
    filter.form = form;
  }

  if (req.query.subject) {
    if (!SUBJECTS.includes(req.query.subject)) {
      return res.status(400).json({ message: "Unknown subject." });
    }
    filter.subject = req.query.subject;
  }

  if (req.query.q) {
    filter.title = {
      $regex: String(req.query.q).slice(0, 100).replace(/[.*+?^${}()|[\]\\]/g, "\\$&"),
      $options: "i"
    };
  }

  const books = await Book.find(filter)
    .sort({ form: 1, subject: 1, title: 1 })
    .lean();

  res.json(books.map(b => ({
    _id: b._id,
    title: b.title,
    form: b.form,
    subject: b.subject,
    coverUrl: b.coverUrl,
    downloads: b.downloads,
    readUrl: signedPdfUrl(b.cloudinaryId, false, 3600),
  })));
}));

app.get("/api/books/:id/read", asyncRoute(async (req, res) => {
  if (!validObjectId(req.params.id)) {
    return res.status(400).json({ message: "Invalid book ID." });
  }

  const book = await Book.findById(req.params.id);
  if (!book) return res.status(404).json({ message: "Book not found." });

  res.json({
    url: signedPdfUrl(book.cloudinaryId, false, 3600),
    title: book.title
  });
}));

app.get("/api/books/:id/download", protect, asyncRoute(async (req, res) => {
  if (!validObjectId(req.params.id)) {
    return res.status(400).json({ message: "Invalid book ID." });
  }

  // Re-fetch user with full doc (protect excluded downloads for perf)
  const user = await User.findById(req.user._id);

  if (!user.isPlanActive()) {
    return res.status(403).json({
      message: "An active 500 MWK/month plan is required to download.",
      requiresPayment: true
    });
  }

  const book = await Book.findById(req.params.id);
  if (!book) return res.status(404).json({ message: "Book not found." });

  book.downloads += 1;
  await book.save();

  user.downloads.push({ book: book._id });
  await user.save();

  res.json({ url: signedPdfUrl(book.cloudinaryId, true, 600) });
}));

/* -------------------- Admin book uploads -------------------- */
app.post(
  "/api/admin/books",
  protect,
  adminOnly,
  uploadPdf.single("pdf"),
  asyncRoute(async (req, res) => {
    const { title, form, subject } = req.body;

    if (!req.file) {
      return res.status(400).json({ message: "Please select a PDF file." });
    }

    const cleanup = async () => {
      if (req.file?.filename) {
        await cloudinary.uploader.destroy(
          req.file.filename,
          { resource_type: "raw" }
        ).catch(() => {});
      }
    };

    if (!String(title || "").trim() || !form || !subject) {
      await cleanup();
      return res.status(400).json({ message: "Title, form and subject are required." });
    }

    if (![1, 2, 3, 4].includes(Number(form)) || !SUBJECTS.includes(subject)) {
      await cleanup();
      return res.status(400).json({ message: "Choose a valid form and subject." });
    }

    const book = await Book.create({
      title: String(title).trim(),
      form: Number(form),
      subject,
      pdfUrl: req.file.path,
      cloudinaryId: req.file.filename,
      uploadedBy: req.user._id,
    });

    res.status(201).json({
      _id: book._id,
      title: book.title,
      form: book.form,
      subject: book.subject,
      coverUrl: book.coverUrl,
      downloads: book.downloads,
    });
  })
);

app.put(
  "/api/admin/books/:id/cover",
  protect,
  adminOnly,
  uploadCover.single("cover"),
  asyncRoute(async (req, res) => {
    if (!validObjectId(req.params.id)) {
      return res.status(400).json({ message: "Invalid book ID." });
    }
    if (!req.file) {
      return res.status(400).json({ message: "Please select a JPG, PNG or WEBP cover image." });
    }

    const book = await Book.findById(req.params.id);

    if (!book) {
      await cloudinary.uploader.destroy(req.file.filename).catch(() => {});
      return res.status(404).json({ message: "Book not found." });
    }

    if (book.coverCloudinaryId) {
      await cloudinary.uploader.destroy(book.coverCloudinaryId).catch(() => {});
    }

    book.coverUrl = req.file.path;
    book.coverCloudinaryId = req.file.filename;
    await book.save();

    res.json({
      message: "Cover uploaded.",
      _id: book._id,
      coverUrl: book.coverUrl
    });
  })
);

app.delete("/api/admin/books/:id", protect, adminOnly, asyncRoute(async (req, res) => {
  if (!validObjectId(req.params.id)) {
    return res.status(400).json({ message: "Invalid book ID." });
  }

  const book = await Book.findById(req.params.id);
  if (!book) return res.status(404).json({ message: "Book not found." });

  await cloudinary.uploader.destroy(
    book.cloudinaryId,
    { resource_type: "raw" }
  ).catch(() => {});

  if (book.coverCloudinaryId) {
    await cloudinary.uploader.destroy(book.coverCloudinaryId).catch(() => {});
  }

  await book.deleteOne();
  res.json({ message: "Book deleted." });
}));

/* -------------------- Admin: list users & activate plan (manual) -------------------- */
app.get("/api/admin/users", protect, adminOnly, asyncRoute(async (req, res) => {
  const users = await User.find({ role: "student" })
    .select("name email hasPlan planExpiry createdAt")
    .sort({ createdAt: -1 })
    .limit(200)
    .lean();
  res.json(users);
}));

// Manually activate a user's plan (for manual payment confirmation)
app.post("/api/admin/users/:id/activate-plan", protect, adminOnly, asyncRoute(async (req, res) => {
  if (!validObjectId(req.params.id)) {
    return res.status(400).json({ message: "Invalid user ID." });
  }
  const user = await User.findById(req.params.id);
  if (!user) return res.status(404).json({ message: "User not found." });

  const base = user.isPlanActive() ? user.planExpiry : new Date();
  user.hasPlan = true;
  user.planExpiry = new Date(base.getTime() + PLAN_DAYS * 24 * 60 * 60 * 1000);
  await user.save();

  res.json({ message: "Plan activated.", user: userPayload(user) });
}));

/* -------------------- Payments -------------------- */
app.post("/api/payments/create", protect, asyncRoute(async (req, res) => {
  const reference = "GB-" + crypto.randomBytes(8).toString("hex").toUpperCase();

  const payment = await Payment.create({
    user: req.user._id,
    amount: PLAN_AMOUNT,
    currency: "MWK",
    provider: String(req.body.provider || "manual"),
    reference,
    status: "pending",
  });

  res.status(201).json({
    message: "Pending payment record created. Contact admin with your reference to activate your plan.",
    reference: payment.reference,
    amount: payment.amount,
    currency: payment.currency,
    status: payment.status,
  });
}));

app.post("/api/payments/webhook", (req, res) => {
  res.status(501).json({
    message: "Payment provider webhook is not configured. Plans cannot be activated through this endpoint yet."
  });
});

app.get("/api/payments/status/:reference", protect, asyncRoute(async (req, res) => {
  const payment = await Payment.findOne({
    reference: req.params.reference,
    user: req.user._id
  }).select("-meta");

  if (!payment) return res.status(404).json({ message: "Payment not found." });

  res.json({ status: payment.status, payment });
}));

/* -------------------- Admin seed and start -------------------- */
async function seedAdmin() {
  const email = String(process.env.ADMIN_EMAIL || "").trim().toLowerCase();
  const password = process.env.ADMIN_PASSWORD;

  if (!email || !password) {
    console.warn("ADMIN_EMAIL/ADMIN_PASSWORD not set; skipping admin seed.");
    return;
  }

  const exists = await User.findOne({ email });

  if (!exists) {
    await User.create({ name: "Admin", email, password, role: "admin" });
    console.log("Admin account created:", email);
  } else if (exists.role !== "admin") {
    exists.role = "admin";
    await exists.save();
    console.log("Existing account promoted to admin:", email);
  }
}

app.use((req, res) =>
  res.status(404).json({ message: `Route not found: ${req.method} ${req.originalUrl}` })
);

app.use((err, req, res, next) => {
  console.error(err.stack || err);

  if (res.headersSent) return next(err);

  if (err instanceof multer.MulterError) {
    const message = err.code === "LIMIT_FILE_SIZE"
      ? "File is too large. PDF limit is 50 MB and cover limit is 5 MB."
      : err.message;
    return res.status(400).json({ message });
  }

  if (err.message === "Origin is not allowed by CORS.") {
    return res.status(403).json({ message: err.message });
  }

  if (err.name === "ValidationError") {
    return res.status(400).json({ message: err.message });
  }

  if (err.code === 11000) {
    return res.status(409).json({ message: "That email or reference already exists." });
  }

  res.status(err.status || 500).json({ message: err.message || "Server error." });
});

async function start() {
  if (!process.env.MONGO_URI) throw new Error("MONGO_URI is required.");
  if (!process.env.JWT_SECRET) throw new Error("JWT_SECRET is required.");

  await mongoose.connect(process.env.MONGO_URI);
  console.log("MongoDB connected.");

  await seedAdmin();

  app.listen(PORT, () =>
    console.log(`GreenBooks API listening on port ${PORT}`)
  );
}

start().catch(err => {
  console.error("Startup failed:", err.message);
  process.exit(1);
});