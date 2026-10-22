
/* ============================================================
   GREENBOOKS BACKEND
   Express + MongoDB Atlas + Cloudinary
   File: server.js
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

const app = express();
const PORT = process.env.PORT || 5000;
const PLAN_AMOUNT = 500;
const PLAN_DAYS = 30;

cloudinary.config({
  cloud_name: process.env.CLOUDINARY_CLOUD_NAME,
  api_key: process.env.CLOUDINARY_API_KEY,
  api_secret: process.env.CLOUDINARY_API_SECRET
});

const SUBJECTS = [
  "English",
  "Chichewa",
  "Mathematics",
  "Biology",
  "Agriculture",
  "Chemistry",
  "Physics",
  "Geography",
  "History",
  "Social Studies"
];

/* ============================================================
   CLOUDINARY FILE STORAGE
   Custom Multer storage engine; no multer-storage-cloudinary.
   ============================================================ */

function createCloudinaryStorage({
  folder,
  resourceType,
  allowedFormats
}) {
  return {
    _handleFile(req, file, callback) {
      const originalName = String(file.originalname || "upload");

      const extension = originalName.includes(".")
        ? originalName.split(".").pop().toLowerCase()
            .replace(/[^a-z0-9]/g, "")
        : "";

      const publicId =
        `${Date.now()}-${crypto.randomBytes(8).toString("hex")}` +
        (resourceType === "raw" && extension
          ? `.${extension}`
          : "");

      let completed = false;

      function finish(error, result) {
        if (completed) return;
        completed = true;

        if (error) return callback(error);

        callback(null, {
          path: result.secure_url,
          filename: result.public_id,
          size: result.bytes,
          cloudinaryResourceType: resourceType
        });
      }

      try {
        const uploadStream = cloudinary.uploader.upload_stream(
          {
            folder,
            resource_type: resourceType,
            public_id: publicId,
            allowed_formats: allowedFormats
          },
          (error, result) => {
            if (error) return finish(error);

            if (!result) {
              return finish(
                new Error("Cloudinary returned no upload result.")
              );
            }

            finish(null, result);
          }
        );

        file.stream.on("error", error => {
          uploadStream.destroy(error);
          finish(error);
        });

        uploadStream.on("error", error => finish(error));

        file.stream.pipe(uploadStream);
      } catch (error) {
        finish(error);
      }
    },

    _removeFile(req, file, callback) {
      if (!file.filename) return callback(null);

      cloudinary.uploader.destroy(file.filename, {
        resource_type:
          file.cloudinaryResourceType || resourceType
      })
        .then(() => callback(null))
        .catch(callback);
    }
  };
}

const pdfStorage = createCloudinaryStorage({
  folder: "greenbooks/pdfs",
  resourceType: "raw",
  allowedFormats: ["pdf"]
});

const coverStorage = createCloudinaryStorage({
  folder: "greenbooks/covers",
  resourceType: "image",
  allowedFormats: ["jpg", "jpeg", "png", "webp"]
});

const uploadPdf = multer({
  storage: pdfStorage,
  limits: {
    fileSize: 50 * 1024 * 1024
  },
  fileFilter(req, file, callback) {
    if (file.mimetype !== "application/pdf") {
      return callback(new Error("Please select a PDF file."));
    }

    callback(null, true);
  }
});

const uploadCover = multer({
  storage: coverStorage,
  limits: {
    fileSize: 5 * 1024 * 1024
  },
  fileFilter(req, file, callback) {
    if (!["image/jpeg", "image/png", "image/webp"].includes(file.mimetype)) {
      return callback(
        new Error("Cover must be JPG, PNG, or WEBP.")
      );
    }

    callback(null, true);
  }
});

/* ============================================================
   MONGODB MODELS
   ============================================================ */

const userSchema = new mongoose.Schema({
  name: {
    type: String,
    required: true,
    trim: true
  },

  email: {
    type: String,
    required: true,
    unique: true,
    lowercase: true,
    trim: true
  },

  password: {
    type: String,
    required: true,
    minlength: 6,
    select: false
  },

  role: {
    type: String,
    enum: ["student", "admin"],
    default: "student"
  },

  hasPlan: {
    type: Boolean,
    default: false
  },

  planExpiry: {
    type: Date,
    default: null
  },

  downloads: [{
    book: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "Book"
    },
    at: {
      type: Date,
      default: Date.now
    }
  }]
}, {
  timestamps: true
});

userSchema.pre("save", async function () {
  if (!this.isModified("password")) return;
  this.password = await bcrypt.hash(this.password, 10);
});

userSchema.methods.matchPassword = function (enteredPassword) {
  return bcrypt.compare(enteredPassword, this.password);
};

userSchema.methods.isPlanActive = function () {
  return Boolean(
    this.hasPlan &&
    this.planExpiry &&
    this.planExpiry > new Date()
  );
};

const User =
  mongoose.models.User || mongoose.model("User", userSchema);

const bookSchema = new mongoose.Schema({
  title: {
    type: String,
    required: true,
    trim: true
  },

  form: {
    type: Number,
    required: true,
    min: 1,
    max: 4
  },

  subject: {
    type: String,
    required: true,
    enum: SUBJECTS
  },

  pdfUrl: {
    type: String,
    required: true
  },

  cloudinaryId: {
    type: String,
    required: true
  },

  coverUrl: {
    type: String,
    default: ""
  },

  coverCloudinaryId: {
    type: String,
    default: ""
  },

  downloads: {
    type: Number,
    default: 0
  },

  uploadedBy: {
    type: mongoose.Schema.Types.ObjectId,
    ref: "User"
  }
}, {
  timestamps: true
});

bookSchema.index({
  form: 1,
  subject: 1
});

const Book =
  mongoose.models.Book || mongoose.model("Book", bookSchema);

const paymentSchema = new mongoose.Schema({
  user: {
    type: mongoose.Schema.Types.ObjectId,
    ref: "User",
    required: true
  },

  amount: {
    type: Number,
    required: true
  },

  currency: {
    type: String,
    default: "MWK"
  },

  status: {
    type: String,
    enum: ["pending", "success", "failed"],
    default: "pending"
  },

  provider: {
    type: String,
    default: "manual"
  },

  reference: {
    type: String,
    unique: true,
    sparse: true
  },

  meta: {
    type: Object,
    default: {}
  }
}, {
  timestamps: true
});

/*
  This expires ALL payment records after 7 days,
  regardless of their status.
*/
paymentSchema.index(
  { createdAt: 1 },
  { expireAfterSeconds: 60 * 60 * 24 * 7 }
);

const Payment =
  mongoose.models.Payment ||
  mongoose.model("Payment", paymentSchema);

/* ============================================================
   MIDDLEWARE
   ============================================================ */

const clientOrigins = (process.env.CLIENT_URL || "")
  .split(",")
  .map(value => value.trim())
  .filter(Boolean);

app.use(
  helmet({
    crossOriginResourcePolicy: {
      policy: "cross-origin"
    }
  })
);

app.use(cors({
  origin(origin, callback) {
    if (!origin) return callback(null, true);

    if (
      clientOrigins.length === 0 ||
      clientOrigins.includes("*")
    ) {
      return callback(null, true);
    }

    if (clientOrigins.includes(origin)) {
      return callback(null, true);
    }

    return callback(
      new Error("Origin is not allowed by CORS.")
    );
  },
  credentials: true
}));

app.use(express.json({
  limit: "1mb"
}));

app.use(express.urlencoded({
  extended: true
}));

app.use(morgan("tiny"));

app.use("/api", rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 200,
  standardHeaders: "draft-7",
  legacyHeaders: false,
  message: {
    message: "Too many requests. Please try again later."
  }
}));

/* ============================================================
   AUTHENTICATION HELPERS
   ============================================================ */

function signToken(id) {
  if (!process.env.JWT_SECRET) {
    throw new Error("JWT_SECRET is not configured.");
  }

  return jwt.sign(
    { id: String(id) },
    process.env.JWT_SECRET,
    {
      expiresIn: process.env.JWT_EXPIRE || "7d"
    }
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
    isPlanActive: user.isPlanActive()
  };
}

async function protect(req, res, next) {
  const header = req.headers.authorization || "";

  const token = header.startsWith("Bearer ")
    ? header.slice(7).trim()
    : "";

  if (!token) {
    return res.status(401).json({
      message: "Please log in; authorization token is missing."
    });
  }

  try {
    const decoded = jwt.verify(
      token,
      process.env.JWT_SECRET
    );

    const user = await User.findById(decoded.id)
      .select("-downloads");

    if (!user) {
      return res.status(401).json({
        message: "Account not found."
      });
    }

    req.user = user;
    next();
  } catch (error) {
    return res.status(401).json({
      message: "Token is invalid or expired. Please log in again."
    });
  }
}

function adminOnly(req, res, next) {
  if (req.user?.role === "admin") {
    return next();
  }

  return res.status(403).json({
    message: "Admin access required."
  });
}

function asyncRoute(handler) {
  return (req, res, next) =>
    Promise.resolve(handler(req, res, next)).catch(next);
}

function validObjectId(id) {
  return mongoose.isValidObjectId(id);
}

function signedPdfUrl(cloudinaryId, attachment = false) {
  /*
    Generates a signed Cloudinary URL.
    Check your Cloudinary account's access and delivery settings
    to ensure private PDF delivery behaves as intended.
  */
  return cloudinary.url(cloudinaryId, {
    resource_type: "raw",
    type: "upload",
    sign_url: true,
    ...(attachment ? { flags: "attachment" } : {})
  });
}

/* ============================================================
   HEALTH CHECKS
   ============================================================ */

app.get("/", (req, res) => {
  res.json({
    status: "ok",
    service: "GreenBooks API",
    time: new Date().toISOString()
  });
});

app.get("/api/health", (req, res) => {
  res.json({
    status: "ok",
    database:
      mongoose.connection.readyState === 1
        ? "connected"
        : "disconnected"
  });
});

/* ============================================================
   REGISTER
   ============================================================ */

app.post("/api/auth/register", asyncRoute(async (req, res) => {
  const name = String(req.body.name || "").trim();
  const email = String(req.body.email || "").trim().toLowerCase();
  const password = String(req.body.password || "");

  if (!name || !email || !password) {
    return res.status(400).json({
      message: "Name, email and password are required."
    });
  }

  if (password.length < 6) {
    return res.status(400).json({
      message: "Password must be at least 6 characters."
    });
  }

  if (await User.findOne({ email })) {
    return res.status(409).json({
      message: "Email already registered."
    });
  }

  const user = await User.create({
    name,
    email,
    password
  });

  res.status(201).json({
    token: signToken(user._id),
    user: userPayload(user)
  });
}));

/* ============================================================
   LOGIN
   ============================================================ */

app.post("/api/auth/login", asyncRoute(async (req, res) => {
  const email = String(req.body.email || "").trim().toLowerCase();
  const password = String(req.body.password || "");

  if (!email || !password) {
    return res.status(400).json({
      message: "Email and password are required."
    });
  }

  const user = await User.findOne({ email })
    .select("+password");

  if (!user || !(await user.matchPassword(password))) {
    return res.status(401).json({
      message: "Invalid email or password."
    });
  }

  if (
    user.hasPlan &&
    user.planExpiry &&
    user.planExpiry <= new Date()
  ) {
    user.hasPlan = false;
    await user.save();
  }

  res.json({
    token: signToken(user._id),
    user: userPayload(user)
  });
}));

/* ============================================================
   CURRENT USER
   ============================================================ */

app.get("/api/auth/me", protect, (req, res) => {
  res.json({
    user: userPayload(req.user)
  });
});

/* ============================================================
   LIST AND SEARCH BOOKS
   ============================================================ */

app.get("/api/books", asyncRoute(async (req, res) => {
  const filter = {};

  if (req.query.form) {
    const form = Number(req.query.form);

    if (![1, 2, 3, 4].includes(form)) {
      return res.status(400).json({
        message: "Form must be 1, 2, 3 or 4."
      });
    }

    filter.form = form;
  }

  if (req.query.subject) {
    if (!SUBJECTS.includes(req.query.subject)) {
      return res.status(400).json({
        message: "Unknown subject."
      });
    }

    filter.subject = req.query.subject;
  }

  if (req.query.q) {
    filter.title = {
      $regex: String(req.query.q)
        .slice(0, 100)
        .replace(/[.*+?^${}()|[\]\\]/g, "\\$&"),
      $options: "i"
    };
  }

  const books = await Book.find(filter)
    .sort({
      form: 1,
      subject: 1,
      title: 1
    })
    .lean();

  res.json(books.map(book => ({
    _id: book._id,
    title: book.title,
    form: book.form,
    subject: book.subject,
    coverUrl: book.coverUrl,
    downloads: book.downloads,
    readUrl: signedPdfUrl(book.cloudinaryId)
  })));
}));

/* ============================================================
   READ A BOOK
   ============================================================ */

app.get("/api/books/:id/read", asyncRoute(async (req, res) => {
  if (!validObjectId(req.params.id)) {
    return res.status(400).json({
      message: "Invalid book ID."
    });
  }

  const book = await Book.findById(req.params.id);

  if (!book) {
    return res.status(404).json({
      message: "Book not found."
    });
  }

  res.json({
    url: signedPdfUrl(book.cloudinaryId),
    title: book.title
  });
}));

/* ============================================================
   DOWNLOAD BOOK — ACTIVE PLAN REQUIRED
   ============================================================ */

app.get(
  "/api/books/:id/download",
  protect,
  asyncRoute(async (req, res) => {
    if (!validObjectId(req.params.id)) {
      return res.status(400).json({
        message: "Invalid book ID."
      });
    }

    const user = await User.findById(req.user._id);

    if (!user) {
      return res.status(401).json({
        message: "Account not found."
      });
    }

    if (!user.isPlanActive()) {
      return res.status(403).json({
        message: "An active 500 MWK/month plan is required to download.",
        requiresPayment: true
      });
    }

    const book = await Book.findById(req.params.id);

    if (!book) {
      return res.status(404).json({
        message: "Book not found."
      });
    }

    book.downloads += 1;
    await book.save();

    user.downloads.push({
      book: book._id
    });

    await user.save();

    res.json({
      url: signedPdfUrl(book.cloudinaryId, true)
    });
  })
);

/* ============================================================
   ADMIN — UPLOAD A BOOK PDF
   Form fields:
   title, form, subject, pdf
   ============================================================ */

app.post(
  "/api/admin/books",
  protect,
  adminOnly,
  uploadPdf.single("pdf"),
  asyncRoute(async (req, res) => {
    const { title, form, subject } = req.body;

    if (!req.file) {
      return res.status(400).json({
        message: "Please select a PDF file."
      });
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

      return res.status(400).json({
        message: "Title, form and subject are required."
      });
    }

    if (
      ![1, 2, 3, 4].includes(Number(form)) ||
      !SUBJECTS.includes(subject)
    ) {
      await cleanup();

      return res.status(400).json({
        message: "Choose a valid form and subject."
      });
    }

    const book = await Book.create({
      title: String(title).trim(),
      form: Number(form),
      subject,
      pdfUrl: req.file.path,
      cloudinaryId: req.file.filename,
      uploadedBy: req.user._id
    });

    res.status(201).json({
      _id: book._id,
      title: book.title,
      form: book.form,
      subject: book.subject,
      coverUrl: book.coverUrl,
      downloads: book.downloads
    });
  })
);

/* ============================================================
   ADMIN — UPLOAD OR REPLACE BOOK COVER
   ============================================================ */

app.put(
  "/api/admin/books/:id/cover",
  protect,
  adminOnly,
  uploadCover.single("cover"),
  asyncRoute(async (req, res) => {
    if (!validObjectId(req.params.id)) {
      return res.status(400).json({
        message: "Invalid book ID."
      });
    }

    if (!req.file) {
      return res.status(400).json({
        message: "Please select a JPG, PNG or WEBP cover image."
      });
    }

    const book = await Book.findById(req.params.id);

    if (!book) {
      await cloudinary.uploader.destroy(
        req.file.filename,
        { resource_type: "image" }
      ).catch(() => {});

      return res.status(404).json({
        message: "Book not found."
      });
    }

    if (book.coverCloudinaryId) {
      await cloudinary.uploader.destroy(
        book.coverCloudinaryId,
        { resource_type: "image" }
      ).catch(() => {});
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

/* ============================================================
   ADMIN — DELETE BOOK
   ============================================================ */

app.delete(
  "/api/admin/books/:id",
  protect,
  adminOnly,
  asyncRoute(async (req, res) => {
    if (!validObjectId(req.params.id)) {
      return res.status(400).json({
        message: "Invalid book ID."
      });
    }

    const book = await Book.findById(req.params.id);

    if (!book) {
      return res.status(404).json({
        message: "Book not found."
      });
    }

    await cloudinary.uploader.destroy(
      book.cloudinaryId,
      { resource_type: "raw" }
    ).catch(() => {});

    if (book.coverCloudinaryId) {
      await cloudinary.uploader.destroy(
        book.coverCloudinaryId,
        { resource_type: "image" }
      ).catch(() => {});
    }

    await book.deleteOne();

    res.json({
      message: "Book deleted."
    });
  })
);

/* ============================================================
   ADMIN — LIST STUDENTS
   ============================================================ */

app.get(
  "/api/admin/users",
  protect,
  adminOnly,
  asyncRoute(async (req, res) => {
    const users = await User.find({
      role: "student"
    })
      .select("name email hasPlan planExpiry createdAt")
      .sort({ createdAt: -1 })
      .limit(200)
      .lean();

    res.json(users);
  })
);

/* ============================================================
   ADMIN — ACTIVATE STUDENT PLAN
   ============================================================ */

app.post(
  "/api/admin/users/:id/activate-plan",
  protect,
  adminOnly,
  asyncRoute(async (req, res) => {
    if (!validObjectId(req.params.id)) {
      return res.status(400).json({
        message: "Invalid user ID."
      });
    }

    const user = await User.findById(req.params.id);

    if (!user) {
      return res.status(404).json({
        message: "User not found."
      });
    }

    const base = user.isPlanActive()
      ? user.planExpiry
      : new Date();

    user.hasPlan = true;
    user.planExpiry = new Date(
      base.getTime() + PLAN_DAYS * 24 * 60 * 60 * 1000
    );

    await user.save();

    res.json({
      message: "Plan activated.",
      user: userPayload(user)
    });
  })
);

/* ============================================================
   PAYMENTS — CREATE PAYMENT REQUEST RECORD
   This does not collect money automatically.
   ============================================================ */

app.post(
  "/api/payments/create",
  protect,
  asyncRoute(async (req, res) => {
    const reference =
      "GB-" +
      crypto.randomBytes(8).toString("hex").toUpperCase();

    const payment = await Payment.create({
      user: req.user._id,
      amount: PLAN_AMOUNT,
      currency: "MWK",
      provider: String(req.body.provider || "manual"),
      reference,
      status: "pending"
    });

    res.status(201).json({
      message:
        "Pending payment record created. Contact admin with your reference to activate your plan.",
      reference: payment.reference,
      amount: payment.amount,
      currency: payment.currency,
      status: payment.status
    });
  })
);

/* ============================================================
   PAYMENT WEBHOOK PLACEHOLDER
   Connect a real payment provider before using automatic payments.
   ============================================================ */

app.post("/api/payments/webhook", (req, res) => {
  res.status(501).json({
    message:
      "Payment provider webhook is not configured. Plans cannot be activated through this endpoint yet."
  });
});

/* ============================================================
   CHECK PAYMENT STATUS
   ============================================================ */

app.get(
  "/api/payments/status/:reference",
  protect,
  asyncRoute(async (req, res) => {
    const payment = await Payment.findOne({
      reference: req.params.reference,
      user: req.user._id
    }).select("-meta");

    if (!payment) {
      return res.status(404).json({
        message: "Payment not found."
      });
    }

    res.json({
      status: payment.status,
      payment
    });
  })
);

/* ============================================================
   CREATE ADMIN ACCOUNT FROM RENDER ENVIRONMENT VARIABLES
   ============================================================ */

async function seedAdmin() {
  const email = String(
    process.env.ADMIN_EMAIL || ""
  ).trim().toLowerCase();

  const password = process.env.ADMIN_PASSWORD;

  if (!email || !password) {
    console.warn(
      "ADMIN_EMAIL/ADMIN_PASSWORD not set; skipping admin seed."
    );
    return;
  }

  const exists = await User.findOne({ email });

  if (!exists) {
    await User.create({
      name: "Admin",
      email,
      password,
      role: "admin"
    });

    console.log("Admin account created:", email);
  } else if (exists.role !== "admin") {
    exists.role = "admin";
    await exists.save();

    console.log("Existing account promoted to admin:", email);
  }
}

/* ============================================================
   ERROR HANDLING
   ============================================================ */

app.use((req, res) => {
  res.status(404).json({
    message: `Route not found: ${req.method} ${req.originalUrl}`
  });
});

app.use((error, req, res, next) => {
  console.error(error.stack || error);

  if (res.headersSent) {
    return next(error);
  }

  if (error instanceof multer.MulterError) {
    const message = error.code === "LIMIT_FILE_SIZE"
      ? "File is too large. PDF limit is 50 MB and cover limit is 5 MB."
      : error.message;

    return res.status(400).json({ message });
  }

  if (error.message === "Origin is not allowed by CORS.") {
    return res.status(403).json({
      message: error.message
    });
  }

  if (
    error.message === "Please select a PDF file." ||
    error.message === "Cover must be JPG, PNG, or WEBP."
  ) {
    return res.status(400).json({
      message: error.message
    });
  }

  if (error.name === "ValidationError") {
    return res.status(400).json({
      message: error.message
    });
  }

  if (error.code === 11000) {
    return res.status(409).json({
      message: "That email or reference already exists."
    });
  }

  res.status(error.status || 500).json({
    message: error.message || "Server error."
  });
});

/* ============================================================
   START SERVER
   ============================================================ */

async function start() {
  if (!process.env.MONGO_URI) {
    throw new Error("MONGO_URI is required in Render environment variables.");
  }

  if (!process.env.JWT_SECRET) {
    throw new Error("JWT_SECRET is required in Render environment variables.");
  }

  await mongoose.connect(process.env.MONGO_URI);

  console.log("MongoDB connected.");

  await seedAdmin();

  app.listen(PORT, () => {
    console.log(`GreenBooks API listening on port ${PORT}`);
  });
}

start().catch(error => {
  console.error("Startup failed:", error.message);
  process.exit(1);
});
