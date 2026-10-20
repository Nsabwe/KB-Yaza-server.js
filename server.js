/* ============================================================
   GREENBOOKS BACKEND — Single-file Express + MongoDB + Cloudinary
   Everything: models, middleware, routes, config, server
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

/* ============================================================
   1. CONFIG — Cloudinary
   ============================================================ */
cloudinary.config({
  cloud_name: process.env.CLOUDINARY_CLOUD_NAME,
  api_key: process.env.CLOUDINARY_API_KEY,
  api_secret: process.env.CLOUDINARY_API_SECRET,
});

/* ============================================================
   2. CONFIG — Multer storages
   ============================================================ */
const pdfStorage = new CloudinaryStorage({
  cloudinary,
  params: {
    folder: "greenbooks/pdfs",
    resource_type: "raw",
    allowed_formats: ["pdf"],
    type: "upload",
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

const uploadPdf = multer({ storage: pdfStorage, limits: { fileSize: 50 * 1024 * 1024 } });
const uploadCover = multer({ storage: coverStorage, limits: { fileSize: 5 * 1024 * 1024 } });

/* ============================================================
   3. DB CONNECT
   ============================================================ */
async function connectDB() {
  try {
    await mongoose.connect(process.env.MONGO_URI);
    console.log("✅ MongoDB connected");
  } catch (err) {
    console.error("❌ MongoDB error:", err.message);
    process.exit(1);
  }
}

/* ============================================================
   4. MODELS
   ============================================================ */

/* ---------- User ---------- */
const userSchema = new mongoose.Schema(
  {
    name: { type: String, required: true, trim: true },
    email: { type: String, required: true, unique: true, lowercase: true, trim: true },
    password: { type: String, required: true, minlength: 6, select: false },
    role: { type: String, enum: ["student", "admin"], default: "student" },
    hasPlan: { type: Boolean, default: false },
    planExpiry: { type: Date, default: null },
    downloads: [
      {
        book: { type: mongoose.Schema.Types.ObjectId, ref: "Book" },
        at: { type: Date, default: Date.now },
      },
    ],
  },
  { timestamps: true }
);

userSchema.pre("save", async function (next) {
  if (!this.isModified("password")) return next();
  const salt = await bcrypt.genSalt(10);
  this.password = await bcrypt.hash(this.password, salt);
  next();
});

userSchema.methods.matchPassword = function (entered) {
  return bcrypt.compare(entered, this.password);
};

userSchema.methods.isPlanActive = function () {
  return this.hasPlan && this.planExpiry && this.planExpiry > new Date();
};

const User = mongoose.model("User", userSchema);

/* ---------- Book ---------- */
const SUBJECTS = [
  "English", "Chichewa", "Mathematics", "Biology", "Agriculture",
  "Chemistry", "Physics", "Geography", "History", "Social Studies",
];

const bookSchema = new mongoose.Schema(
  {
    title: { type: String, required: true, trim: true },
    form: { type: Number, required: true, min: 1, max: 4 },
    subject: { type: String, required: true, enum: SUBJECTS },
    pdfUrl: { type: String, required: true },
    cloudinaryId: { type: String, required: true },
    coverUrl: { type: String, default: "" },
    coverCloudinaryId: { type: String, default: "" },
    downloads: { type: Number, default: 0 },
    uploadedBy: { type: mongoose.Schema.Types.ObjectId, ref: "User" },
  },
  { timestamps: true }
);

bookSchema.index({ form: 1, subject: 1 });
bookSchema.index({ title: "text" });

const Book = mongoose.model("Book", bookSchema);

/* ---------- Payment ---------- */
const paymentSchema = new mongoose.Schema(
  {
    user: { type: mongoose.Schema.Types.ObjectId, ref: "User", required: true },
    amount: { type: Number, required: true },
    currency: { type: String, default: "MWK" },
    status: { type: String, enum: ["pending", "success", "failed"], default: "pending" },
    provider: { type: String, default: "manual" },
    reference: { type: String, unique: true, sparse: true },
    meta: { type: Object, default: {} },
  },
  { timestamps: true }
);

const Payment = mongoose.model("Payment", paymentSchema);

/* ============================================================
   5. MIDDLEWARE
   ============================================================ */

/* ---------- JWT helper ---------- */
const signToken = (id) =>
  jwt.sign({ id }, process.env.JWT_SECRET, { expiresIn: process.env.JWT_EXPIRE || "7d" });

/* ---------- Auth protect ---------- */
const protect = async (req, res, next) => {
  let token;
  if (req.headers.authorization?.startsWith("Bearer")) {
    token = req.headers.authorization.split(" ")[1];
  }
  if (!token) return res.status(401).json({ message: "Not authorized" });

  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    req.user = await User.findById(decoded.id);
    if (!req.user) return res.status(401).json({ message: "User not found" });
    next();
  } catch {
    res.status(401).json({ message: "Invalid token" });
  }
};

/* ---------- Admin only ---------- */
const admin = (req, res, next) => {
  if (req.user && req.user.role === "admin") return next();
  res.status(403).json({ message: "Admin access required" });
};

/* ============================================================
   6. ROUTES — AUTH
   ============================================================ */
const authRouter = express.Router();

const userPayload = (u) => ({
  _id: u._id,
  name: u.name,
  email: u.email,
  role: u.role,
  hasPlan: u.hasPlan,
  planExpiry: u.planExpiry,
  isPlanActive: u.isPlanActive(),
});

authRouter.post("/register", async (req, res) => {
  try {
    const { name, email, password } = req.body;
    if (!name || !email || !password)
      return res.status(400).json({ message: "All fields required" });
    if (password.length < 6)
      return res.status(400).json({ message: "Password must be at least 6 characters" });

    const exists = await User.findOne({ email });
    if (exists) return res.status(400).json({ message: "Email already registered" });

    const user = await User.create({ name, email, password });
    res.status(201).json({ token: signToken(user._id), user: userPayload(user) });
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

authRouter.post("/login", async (req, res) => {
  try {
    const { email, password } = req.body;
    const user = await User.findOne({ email }).select("+password");
    if (!user) return res.status(401).json({ message: "Invalid credentials" });

    const match = await user.matchPassword(password);
    if (!match) return res.status(401).json({ message: "Invalid credentials" });

    if (user.hasPlan && user.planExpiry && user.planExpiry < new Date()) {
      user.hasPlan = false;
      await user.save();
    }

    res.json({ token: signToken(user._id), user: userPayload(user) });
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

authRouter.get("/me", protect, (req, res) => {
  res.json({ user: userPayload(req.user) });
});

/* ============================================================
   7. ROUTES — BOOKS
   ============================================================ */
const bookRouter = express.Router();

/* List all books (safe — no raw pdfUrl exposed) */
bookRouter.get("/", async (req, res) => {
  try {
    const { form, subject, q } = req.query;
    const filter = {};
    if (form) filter.form = Number(form);
    if (subject) filter.subject = subject;
    if (q) filter.title = { $regex: q, $options: "i" };

    const books = await Book.find(filter).sort({ form: 1, subject: 1 });

    const safe = books.map((b) => ({
      _id: b._id,
      title: b.title,
      form: b.form,
      subject: b.subject,
      coverUrl: b.coverUrl,
      downloads: b.downloads,
      readUrl: cloudinary.url(b.cloudinaryId, {
        resource_type: "raw",
        type: "upload",
        sign_url: true,
        expires_at: Math.floor(Date.now() / 1000) + 3600,
      }),
    }));

    res.json(safe);
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

/* Read — fresh 1-hour signed URL, inline only */
bookRouter.get("/:id/read", async (req, res) => {
  try {
    const book = await Book.findById(req.params.id);
    if (!book) return res.status(404).json({ message: "Book not found" });

    const readUrl = cloudinary.url(book.cloudinaryId, {
      resource_type: "raw",
      type: "upload",
      sign_url: true,
      expires_at: Math.floor(Date.now() / 1000) + 3600,
    });

    res.json({ url: readUrl, title: book.title });
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

/* Download — requires login + active 500 MK/month plan */
bookRouter.get("/:id/download", protect, async (req, res) => {
  try {
    const user = await User.findById(req.user._id);
    if (!user.isPlanActive()) {
      return res.status(403).json({
        message: "Active 500 MK/month plan required to download",
        requiresPayment: true,
      });
    }

    const book = await Book.findById(req.params.id);
    if (!book) return res.status(404).json({ message: "Book not found" });

    const downloadUrl = cloudinary.url(book.cloudinaryId, {
      resource_type: "raw",
      type: "upload",
      sign_url: true,
      expires_at: Math.floor(Date.now() / 1000) + 600,
      flags: "attachment",
    });

    book.downloads += 1;
    await book.save();
    user.downloads.push({ book: book._id });
    await user.save();

    res.json({ url: downloadUrl });
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

/* ============================================================
   8. ROUTES — PAYMENTS (500 MK / month)
   ============================================================ */
const paymentRouter = express.Router();
const PLAN_AMOUNT = 500;
const PLAN_DAYS = 30;

paymentRouter.post("/create", protect, async (req, res) => {
  try {
    const { provider = "manual" } = req.body;
    const reference = "GB-" + crypto.randomBytes(6).toString("hex").toUpperCase();

    await Payment.create({
      user: req.user._id,
      amount: PLAN_AMOUNT,
      currency: "MWK",
      provider,
      reference,
      status: "pending",
    });

    /* 🔌 INTEGRATION POINT — replace stub with real provider:
       PayChangu / Flutterwave / TNM Mpamba / Airtel Money
       Then respond with { checkoutUrl } from the provider.
    */

    res.json({
      checkoutUrl: `https://sandbox.paychangu.com/pay/${reference}`,
      reference,
      amount: PLAN_AMOUNT,
    });
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

paymentRouter.post("/webhook", async (req, res) => {
  try {
    const { reference, status } = req.body;
    if (!reference) return res.status(400).json({ message: "Missing reference" });

    const payment = await Payment.findOne({ reference });
    if (!payment) return res.status(404).json({ message: "Payment not found" });

    if (status !== "success") {
      payment.status = "failed";
      await payment.save();
      return res.json({ received: true });
    }

    payment.status = "success";
    await payment.save();

    const user = await User.findById(payment.user);
    if (user) {
      const now = new Date();
      const base = user.planExpiry && user.planExpiry > now ? user.planExpiry : now;
      user.hasPlan = true;
      user.planExpiry = new Date(base.getTime() + PLAN_DAYS * 24 * 60 * 60 * 1000);
      await user.save();
    }

    res.json({ received: true });
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

paymentRouter.get("/status/:reference", protect, async (req, res) => {
  try {
    const payment = await Payment.findOne({
      reference: req.params.reference,
      user: req.user._id,
    });
    if (!payment) return res.status(404).json({ message: "Not found" });
    res.json({ status: payment.status, payment });
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

/* ============================================================
   9. ROUTES — ADMIN
   ============================================================ */
const adminRouter = express.Router();

adminRouter.post(
  "/books",
  protect,
  admin,
  uploadPdf.single("pdf"),
  async (req, res) => {
    try {
      const { title, form, subject } = req.body;
      if (!req.file) return res.status(400).json({ message: "PDF file required" });
      if (!title || !form || !subject)
        return res.status(400).json({ message: "title, form and subject required" });

      const book = await Book.create({
        title,
        form: Number(form),
        subject,
        pdfUrl: req.file.path,
        cloudinaryId: req.file.filename,
        uploadedBy: req.user._id,
      });

      res.status(201).json(book);
    } catch (err) {
      res.status(500).json({ message: err.message });
    }
  }
);

adminRouter.put(
  "/books/:id/cover",
  protect,
  admin,
  uploadCover.single("cover"),
  async (req, res) => {
    try {
      const book = await Book.findById(req.params.id);
      if (!book) return res.status(404).json({ message: "Book not found" });
      if (!req.file) return res.status(400).json({ message: "Cover required" });

      if (book.coverCloudinaryId) {
        await cloudinary.uploader.destroy(book.coverCloudinaryId);
      }

      book.coverUrl = req.file.path;
      book.coverCloudinaryId = req.file.filename;
      await book.save();

      res.json(book);
    } catch (err) {
      res.status(500).json({ message: err.message });
    }
  }
);

adminRouter.delete("/books/:id", protect, admin, async (req, res) => {
  try {
    const book = await Book.findById(req.params.id);
    if (!book) return res.status(404).json({ message: "Book not found" });

    await cloudinary.uploader.destroy(book.cloudinaryId, { resource_type: "raw" });
    if (book.coverCloudinaryId)
      await cloudinary.uploader.destroy(book.coverCloudinaryId);

    await book.deleteOne();
    res.json({ message: "Book deleted" });
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

/* ============================================================
   10. EXPRESS APP
   ============================================================ */
const app = express();

app.use(helmet());
app.use(
  cors({
    origin: [process.env.CLIENT_URL || "*", "http://localhost:3000"],
    credentials: true,
  })
);
app.use(express.json({ limit: "10mb" }));
app.use(express.urlencoded({ extended: true }));
app.use(morgan("dev"));

app.use(
  "/api/",
  rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 200,
    message: { message: "Too many requests, try again later" },
  })
);

/* Health */
app.get("/", (req, res) =>
  res.json({ status: "ok", service: "GreenBooks API", time: new Date() })
);

/* Routers */
app.use("/api/auth", authRouter);
app.use("/api/books", bookRouter);
app.use("/api/payments", paymentRouter);
app.use("/api/admin", adminRouter);

/* 404 */
app.use((req, res) => res.status(404).json({ message: "Route not found" }));

/* Error handler */
app.use((err, req, res, next) => {
  console.error(err.stack);
  res.status(err.status || 500).json({ message: err.message || "Server error" });
});

/* ============================================================
   11. SEED ADMIN
   ============================================================ */
async function seedAdmin() {
  try {
    const email = process.env.ADMIN_EMAIL;
    if (!email || !process.env.ADMIN_PASSWORD) return;
    const exists = await User.findOne({ email });
    if (!exists) {
      await User.create({
        name: "Admin",
        email,
        password: process.env.ADMIN_PASSWORD,
        role: "admin",
      });
      console.log("👑 Admin created:", email);
    }
  } catch (e) {
    console.error("Admin seed error:", e.message);
  }
}

/* ============================================================
   12. START
   ============================================================ */
const PORT = process.env.PORT || 5000;

(async () => {
  await connectDB();
  await seedAdmin();
  app.listen(PORT, () => console.log(`🚀 Server running on port ${PORT}`));
})();