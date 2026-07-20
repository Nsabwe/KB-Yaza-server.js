// server.js – NjalaMarket Backend
// Added: typing, read receipts, message deletion, video call signaling

const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const multer = require('multer');
const cloudinary = require('cloudinary').v2;
const twilio = require('twilio');
const http = require('http');
const socketIo = require('socket.io');
require('dotenv').config();

const app = express();
const server = http.createServer(app);
const io = socketIo(server, {
  cors: {
    origin: '*',
    methods: ['GET', 'POST'],
  },
});

// ============================================================
//  CONFIGURATION
// ============================================================
const PORT = process.env.PORT || 5000;
const JWT_SECRET = process.env.JWT_SECRET || 'super-secret-key-change-me';
const MONGODB_URI = process.env.MONGODB_URI || 'mongodb://localhost:27017/njalamarket';

cloudinary.config({
  cloud_name: process.env.CLOUDINARY_CLOUD_NAME,
  api_key: process.env.CLOUDINARY_API_KEY,
  api_secret: process.env.CLOUDINARY_API_SECRET,
});

const twilioClient = twilio(
  process.env.TWILIO_ACCOUNT_SID,
  process.env.TWILIO_AUTH_TOKEN
);
const TWILIO_PHONE = process.env.TWILIO_PHONE_NUMBER;

// ============================================================
//  MIDDLEWARE
// ============================================================
app.use(cors());
app.use(express.json({ limit: '50mb' }));
app.use(express.urlencoded({ extended: true, limit: '50mb' }));

const storage = multer.memoryStorage();
const upload = multer({ storage });

// ============================================================
//  DATABASE CONNECTION
// ============================================================
mongoose.connect(MONGODB_URI, {
  useNewUrlParser: true,
  useUnifiedTopology: true,
})
.then(() => console.log('✅ MongoDB connected successfully'))
.catch(err => {
  console.error('❌ MongoDB connection error:', err);
  process.exit(1);
});

const log = (msg) => console.log(`[${new Date().toISOString()}] ${msg}`);

// ============================================================
//  MODELS (with ChatMessage updated)
// ============================================================
const UserSchema = new mongoose.Schema({
  name: { type: String, required: true },
  email: { type: String, required: true, unique: true },
  phone: { type: String, required: true },
  password: { type: String, required: true },
  district: { type: String, default: '' },
  gender: { type: String, default: '' },
  profilePicture: { type: String, default: '' },
  role: { type: String, default: 'user' },
  isOnline: { type: Boolean, default: false },
  lastSeen: { type: Date, default: Date.now },
}, { timestamps: true });

const User = mongoose.model('User', UserSchema);

const ProductSchema = new mongoose.Schema({
  title: { type: String, required: true },
  price: { type: Number, required: true },
  category: { type: String, default: 'Other' },
  condition: { type: String, default: 'Good' },
  location: { type: String, required: true },
  phone: { type: String, required: true },
  image: { type: String, default: '' },
  userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  posterName: { type: String },
  posterImage: { type: String },
  views: { type: Number, default: 0 },
}, { timestamps: true });

const Product = mongoose.model('Product', ProductSchema);

const PropertySchema = new mongoose.Schema({
  title: { type: String, required: true },
  type: { type: String, default: 'House' },
  listingType: { type: String, default: 'For Sale' },
  price: { type: Number, required: true },
  bedrooms: { type: Number, default: 0 },
  location: { type: String, required: true },
  phone: { type: String, required: true },
  image: { type: String, default: '' },
  userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  posterName: { type: String },
  posterImage: { type: String },
  views: { type: Number, default: 0 },
}, { timestamps: true });

const Property = mongoose.model('Property', PropertySchema);

const JobSchema = new mongoose.Schema({
  title: { type: String, required: true },
  company: { type: String, required: true },
  employmentType: { type: String, default: 'Full-time' },
  salary: { type: String, default: 'Negotiable' },
  location: { type: String, required: true },
  phone: { type: String, required: true },
  description: { type: String, default: '' },
  requirements: { type: String, default: '' },
  userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  posterName: { type: String },
  posterImage: { type: String },
  views: { type: Number, default: 0 },
}, { timestamps: true });

const Job = mongoose.model('Job', JobSchema);

// Updated ChatMessage schema with readAt
const ChatMessageSchema = new mongoose.Schema({
  senderId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  receiverId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  message: { type: String, required: true },
  read: { type: Boolean, default: false },
  readAt: { type: Date },
}, { timestamps: true });

const ChatMessage = mongoose.model('ChatMessage', ChatMessageSchema);

const ContactMessageSchema = new mongoose.Schema({
  name: { type: String, required: true },
  email: { type: String, required: true },
  subject: { type: String, required: true },
  message: { type: String, required: true },
  userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
  read: { type: Boolean, default: false },
}, { timestamps: true });

const ContactMessage = mongoose.model('ContactMessage', ContactMessageSchema);

const OwnerMessageSchema = new mongoose.Schema({
  key: { type: String, unique: true },
  value: { type: String, default: 'Welcome to NjalaMarket! Your trusted marketplace.' },
}, { timestamps: true });

const OwnerMessage = mongoose.model('OwnerMessage', OwnerMessageSchema);

const PasswordResetSchema = new mongoose.Schema({
  userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  code: { type: String, required: true },
  phone: { type: String, required: true },
  used: { type: Boolean, default: false },
  expiresAt: { type: Date, required: true },
}, { timestamps: true });

const PasswordReset = mongoose.model('PasswordReset', PasswordResetSchema);

const NotificationSchema = new mongoose.Schema({
  userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  type: { type: String, enum: ['chat', 'contact_reply', 'system', 'listing'], required: true },
  title: { type: String, required: true },
  body: { type: String, required: true },
  data: { type: mongoose.Schema.Types.Mixed, default: {} },
  read: { type: Boolean, default: false },
}, { timestamps: true });

const Notification = mongoose.model('Notification', NotificationSchema);

// ============================================================
//  HELPERS
// ============================================================
const generateToken = (user) => {
  return jwt.sign(
    { id: user._id, email: user.email, role: user.role },
    JWT_SECRET,
    { expiresIn: '7d' }
  );
};

const authMiddleware = async (req, res, next) => {
  try {
    const token = req.headers.authorization?.split(' ')[1];
    if (!token) return res.status(401).json({ error: 'No token provided' });
    const decoded = jwt.verify(token, JWT_SECRET);
    const user = await User.findById(decoded.id).select('-password');
    if (!user) return res.status(401).json({ error: 'User not found' });
    req.user = user;
    next();
  } catch (error) {
    return res.status(401).json({ error: 'Invalid or expired token' });
  }
};

const adminMiddleware = (req, res, next) => {
  if (req.user.role !== 'admin') {
    return res.status(403).json({ error: 'Admin access required' });
  }
  next();
};

const uploadImage = async (buffer) => {
  return new Promise((resolve, reject) => {
    cloudinary.uploader.upload_stream(
      { folder: 'njalamarket', transformation: [{ width: 600, height: 600, crop: 'limit' }] },
      (error, result) => {
        if (error) reject(error);
        else resolve(result.secure_url);
      }
    ).end(buffer);
  });
};

const sendSMS = async (phone, message) => {
  try {
    if (!twilioClient || !TWILIO_PHONE) {
      log(`⚠️ SMS (mock): To ${phone} - ${message}`);
      return { success: true, mock: true };
    }
    const result = await twilioClient.messages.create({
      body: message,
      from: TWILIO_PHONE,
      to: phone,
    });
    log(`📱 SMS sent to ${phone}: ${message}`);
    return { success: true, sid: result.sid };
  } catch (error) {
    log(`❌ SMS error: ${error.message}`);
    return { success: false, error: error.message };
  }
};

const generateResetCode = () => {
  return Math.floor(100000 + Math.random() * 900000).toString();
};

// ============================================================
//  NOTIFICATION HELPER
// ============================================================
const userSocketMap = {};

const createNotification = async (userId, type, title, body, data = {}) => {
  try {
    const notification = new Notification({ userId, type, title, body, data });
    await notification.save();
    const userSockets = userSocketMap[userId] || [];
    userSockets.forEach(socketId => {
      io.to(socketId).emit('notification', notification);
    });
    return notification;
  } catch (error) {
    log(`❌ Notification error: ${error.message}`);
    return null;
  }
};

// ============================================================
//  SOCKET.IO SETUP (enhanced with new features)
// ============================================================
io.use((socket, next) => {
  const token = socket.handshake.auth.token;
  if (!token) return next(new Error('Authentication error: no token'));
  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    socket.userId = decoded.id;
    next();
  } catch (err) {
    next(new Error('Authentication error: invalid token'));
  }
});

io.on('connection', (socket) => {
  const userId = socket.userId;
  log(`🔌 User ${userId} connected`);
  if (!userSocketMap[userId]) userSocketMap[userId] = [];
  userSocketMap[userId].push(socket.id);
  socket.join(`user_${userId}`);

  // ---- Existing events ----
  socket.on('join_chat', (otherUserId) => {
    const room = `chat_${[userId, otherUserId].sort().join('_')}`;
    socket.join(room);
    log(`📨 User ${userId} joined room ${room}`);
  });

  socket.on('send_message', async (data) => {
    try {
      const { receiverId, message } = data;
      const chat = new ChatMessage({ senderId: userId, receiverId, message });
      await chat.save();
      const room = `chat_${[userId, receiverId].sort().join('_')}`;
      // Include `seen` field (same as read)
      const chatObj = chat.toObject();
      chatObj.seen = chat.read;
      io.to(room).emit('new_message', chatObj);
      const sender = await User.findById(userId).select('name');
      await createNotification(
        receiverId,
        'chat',
        `New message from ${sender.name}`,
        message,
        { chatId: chat._id, senderId: userId }
      );
      const unreadCount = await ChatMessage.countDocuments({ receiverId, read: false });
      io.to(`user_${receiverId}`).emit('unread_update', { count: unreadCount });
    } catch (error) {
      log(`❌ Socket send_message error: ${error.message}`);
      socket.emit('error', { message: 'Failed to send message' });
    }
  });

  socket.on('mark_read', async (data) => {
    try {
      const { otherUserId } = data;
      const result = await ChatMessage.updateMany(
        { senderId: otherUserId, receiverId: userId, read: false },
        { read: true, readAt: new Date() }
      );
      // Emit message_read event for each updated message? 
      // We'll just update unread count and rely on frontend to refresh.
      const unreadCount = await ChatMessage.countDocuments({ receiverId: userId, read: false });
      io.to(`user_${userId}`).emit('unread_update', { count: unreadCount });
      // Also notify sender that messages were read (optional)
      io.to(`user_${otherUserId}`).emit('messages_read', { byUserId: userId });
    } catch (error) {
      log(`❌ mark_read error: ${error.message}`);
    }
  });

  // ---- NEW: Typing events ----
  socket.on('typing', ({ receiverId }) => {
    io.to(`user_${receiverId}`).emit('typing', { senderId: userId });
  });

  socket.on('stop_typing', ({ receiverId }) => {
    io.to(`user_${receiverId}`).emit('stop_typing', { senderId: userId });
  });

  // ---- NEW: Read receipt per message ----
  socket.on('message_read', async ({ messageId }) => {
    try {
      const message = await ChatMessage.findById(messageId);
      if (!message) return;
      // Only mark if the current user is the receiver
      if (message.receiverId.toString() !== userId) return;
      message.read = true;
      message.readAt = new Date();
      await message.save();
      // Notify the sender that this message was read
      io.to(`user_${message.senderId}`).emit('message_read', { messageId });
    } catch (error) {
      log(`❌ message_read error: ${error.message}`);
    }
  });

  // ---- NEW: Delete message ----
  socket.on('delete_message', async ({ messageId }) => {
    try {
      const message = await ChatMessage.findById(messageId);
      if (!message) return;
      // Only sender can delete
      if (message.senderId.toString() !== userId) {
        socket.emit('error', { message: 'Not authorized' });
        return;
      }
      await message.deleteOne();
      // Broadcast deletion to the chat room
      const room = `chat_${[message.senderId, message.receiverId].sort().join('_')}`;
      io.to(room).emit('message_deleted', { messageId });
      log(`🗑️ Message ${messageId} deleted by ${userId}`);
    } catch (error) {
      log(`❌ delete_message error: ${error.message}`);
      socket.emit('error', { message: 'Failed to delete message' });
    }
  });

  // ---- NEW: Video call signaling ----
  socket.on('call_user', ({ to, name }) => {
    io.to(`user_${to}`).emit('incoming_call', { from: userId, name });
  });

  socket.on('call_accepted', ({ to }) => {
    io.to(`user_${to}`).emit('call_accepted', { from: userId });
  });

  socket.on('call_declined', ({ to }) => {
    io.to(`user_${to}`).emit('call_declined');
  });

  socket.on('webrtc_offer', ({ to, sdp }) => {
    io.to(`user_${to}`).emit('webrtc_offer', { from: userId, sdp });
  });

  socket.on('webrtc_answer', ({ to, sdp }) => {
    io.to(`user_${to}`).emit('webrtc_answer', { from: userId, sdp });
  });

  socket.on('webrtc_ice', ({ to, candidate }) => {
    io.to(`user_${to}`).emit('webrtc_ice', { from: userId, candidate });
  });

  socket.on('call_ended', ({ to }) => {
    io.to(`user_${to}`).emit('call_ended');
  });

  // ---- Disconnect ----
  socket.on('disconnect', () => {
    log(`🔌 User ${userId} disconnected`);
    if (userSocketMap[userId]) {
      userSocketMap[userId] = userSocketMap[userId].filter(id => id !== socket.id);
      if (userSocketMap[userId].length === 0) delete userSocketMap[userId];
    }
  });
});

// ============================================================
//  AUTH ROUTES (unchanged)
// ============================================================
app.post('/api/auth/register', async (req, res) => {
  try {
    const { name, phone, password, district, gender } = req.body;
    const email = phone + '@njalamarket.com';
    const existingUser = await User.findOne({ email });
    if (existingUser) return res.status(400).json({ error: 'Phone already registered' });
    const hashedPassword = await bcrypt.hash(password, 10);
    const user = new User({
      name,
      email,
      phone,
      password: hashedPassword,
      district: district || '',
      gender: gender || '',
      isOnline: true,
    });
    await user.save();
    log(`✅ New user registered: ${phone} (${name})`);
    const token = generateToken(user);
    const userData = user.toObject();
    delete userData.password;
    res.status(201).json({ success: true, token, user: userData });
  } catch (error) {
    log(`❌ Register error: ${error.message}`);
    res.status(500).json({ error: error.message });
  }
});

app.post('/api/auth/login', async (req, res) => {
  try {
    const { phone, password } = req.body;
    const user = await User.findOne({ phone });
    if (!user) return res.status(400).json({ error: 'Invalid credentials' });
    const valid = await bcrypt.compare(password, user.password);
    if (!valid) return res.status(400).json({ error: 'Invalid credentials' });
    user.isOnline = true;
    user.lastSeen = new Date();
    await user.save();
    const token = generateToken(user);
    const userData = user.toObject();
    delete userData.password;
    log(`✅ User logged in: ${phone}`);
    res.json({ success: true, token, user: userData });
  } catch (error) {
    log(`❌ Login error: ${error.message}`);
    res.status(500).json({ error: error.message });
  }
});

app.post('/api/auth/forgot-password', async (req, res) => {
  try {
    const { phone } = req.body;
    const user = await User.findOne({ phone });
    if (!user) return res.status(404).json({ error: 'No account with this phone' });
    const code = generateResetCode();
    const expiresAt = new Date(Date.now() + 10 * 60 * 1000);
    await PasswordReset.findOneAndUpdate(
      { userId: user._id },
      { code, phone, expiresAt, used: false },
      { upsert: true, new: true }
    );
    const message = `NjalaMarket: Your password reset code is ${code}. It expires in 10 minutes.`;
    const sms = await sendSMS(phone, message);
    if (!sms.success) return res.status(500).json({ error: 'Failed to send SMS' });
    res.json({ success: true, message: 'Code sent', mock: sms.mock || false });
  } catch (error) {
    log(`❌ Forgot password error: ${error.message}`);
    res.status(500).json({ error: error.message });
  }
});

app.post('/api/auth/verify-reset-code', async (req, res) => {
  try {
    const { phone, code } = req.body;
    const reset = await PasswordReset.findOne({ phone, code, used: false, expiresAt: { $gt: new Date() } });
    if (!reset) return res.status(400).json({ error: 'Invalid or expired code' });
    res.json({ success: true, userId: reset.userId });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.post('/api/auth/reset-password', async (req, res) => {
  try {
    const { phone, code, newPassword, keepOldPassword } = req.body;
    const reset = await PasswordReset.findOne({ phone, code, used: false, expiresAt: { $gt: new Date() } });
    if (!reset) return res.status(400).json({ error: 'Invalid or expired code' });
    const user = await User.findById(reset.userId);
    if (!user) return res.status(404).json({ error: 'User not found' });
    if (keepOldPassword) {
      reset.used = true;
      await reset.save();
      return res.json({ success: true, keepOld: true });
    }
    const hashed = await bcrypt.hash(newPassword, 10);
    user.password = hashed;
    await user.save();
    reset.used = true;
    await reset.save();
    log(`✅ Password reset for ${phone}`);
    res.json({ success: true, keepOld: false });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// ============================================================
//  PROFILE UPDATE
// ============================================================
app.put('/api/auth/profile', authMiddleware, upload.single('profilePicture'), async (req, res) => {
  try {
    const { name, phone, district, gender } = req.body;
    const user = await User.findById(req.user._id);
    if (!user) return res.status(404).json({ error: 'User not found' });

    if (name) user.name = name;
    if (phone) user.phone = phone;
    if (district !== undefined) user.district = district;
    if (gender !== undefined) user.gender = gender;

    if (req.file && req.file.buffer && req.file.buffer.length > 0) {
      const url = await uploadImage(req.file.buffer);
      user.profilePicture = url;
      log(`📸 Profile picture updated for ${user.phone}`);
    } else if (req.body.profilePictureData) {
      const base64Data = req.body.profilePictureData.replace(/^data:image\/\w+;base64,/, '');
      const buffer = Buffer.from(base64Data, 'base64');
      const url = await uploadImage(buffer);
      user.profilePicture = url;
      log(`📸 Profile picture (base64) updated for ${user.phone}`);
    }

    await user.save();
    const userData = user.toObject();
    delete userData.password;
    res.json({ success: true, user: userData });
  } catch (error) {
    log(`❌ Profile update error: ${error.message}`);
    res.status(500).json({ error: error.message });
  }
});

// ============================================================
//  USERS
// ============================================================
app.get('/api/users', authMiddleware, async (req, res) => {
  try {
    const users = await User.find({}, '-password -email');
    res.json({ success: true, users });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.get('/api/users/:id', async (req, res) => {
  try {
    const user = await User.findById(req.params.id).select('-password -email -phone');
    if (!user) return res.status(404).json({ error: 'User not found' });
    res.json({ success: true, user });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// ============================================================
//  LISTING ROUTES (unchanged)
// ============================================================
const createListing = async (Model, data, user, file) => {
  let imageUrl = '';
  if (file && file.buffer && file.buffer.length > 0) {
    imageUrl = await uploadImage(file.buffer);
  } else if (data.imageData && data.imageData.startsWith('data:image')) {
    const base64Data = data.imageData.replace(/^data:image\/\w+;base64,/, '');
    const buffer = Buffer.from(base64Data, 'base64');
    imageUrl = await uploadImage(buffer);
  }
  const listing = new Model({
    ...data,
    image: imageUrl,
    userId: user._id,
    posterName: user.name,
    posterImage: user.profilePicture,
  });
  await listing.save();
  return listing;
};

app.post('/api/products', authMiddleware, upload.single('image'), async (req, res) => {
  try {
    const listing = await createListing(Product, req.body, req.user, req.file);
    log(`📦 Product created: ${listing.title} by ${req.user.phone}`);
    res.status(201).json({ success: true, product: listing });
  } catch (error) {
    log(`❌ Product create error: ${error.message}`);
    res.status(500).json({ error: error.message });
  }
});

app.get('/api/products', async (req, res) => {
  try {
    const products = await Product.find().sort({ createdAt: -1 });
    res.json({ success: true, products });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.get('/api/products/:id', async (req, res) => {
  try {
    const product = await Product.findById(req.params.id);
    if (!product) return res.status(404).json({ error: 'Not found' });
    product.views += 1;
    await product.save();
    res.json({ success: true, product });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.put('/api/products/:id', authMiddleware, upload.single('image'), async (req, res) => {
  try {
    const product = await Product.findById(req.params.id);
    if (!product) return res.status(404).json({ error: 'Not found' });
    if (product.userId.toString() !== req.user._id.toString() && req.user.role !== 'admin') {
      return res.status(403).json({ error: 'Unauthorized' });
    }
    const { title, price, category, condition, location, phone } = req.body;
    if (title) product.title = title;
    if (price) product.price = Number(price);
    if (category) product.category = category;
    if (condition) product.condition = condition;
    if (location) product.location = location;
    if (phone) product.phone = phone;

    if (req.file && req.file.buffer && req.file.buffer.length > 0) {
      product.image = await uploadImage(req.file.buffer);
    } else if (req.body.imageData && req.body.imageData.startsWith('data:image')) {
      const base64Data = req.body.imageData.replace(/^data:image\/\w+;base64,/, '');
      const buffer = Buffer.from(base64Data, 'base64');
      product.image = await uploadImage(buffer);
    }

    await product.save();
    log(`📦 Product updated: ${product.title}`);
    res.json({ success: true, product });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.delete('/api/products/:id', authMiddleware, async (req, res) => {
  try {
    const product = await Product.findById(req.params.id);
    if (!product) return res.status(404).json({ error: 'Not found' });
    if (product.userId.toString() !== req.user._id.toString() && req.user.role !== 'admin') {
      return res.status(403).json({ error: 'Unauthorized' });
    }
    await product.deleteOne();
    log(`🗑️ Product deleted: ${product.title}`);
    res.json({ success: true, message: 'Deleted' });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.post('/api/properties', authMiddleware, upload.single('image'), async (req, res) => {
  try {
    const listing = await createListing(Property, req.body, req.user, req.file);
    log(`🏠 Property created: ${listing.title} by ${req.user.phone}`);
    res.status(201).json({ success: true, property: listing });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.get('/api/properties', async (req, res) => {
  try {
    const properties = await Property.find().sort({ createdAt: -1 });
    res.json({ success: true, properties });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.get('/api/properties/:id', async (req, res) => {
  try {
    const property = await Property.findById(req.params.id);
    if (!property) return res.status(404).json({ error: 'Not found' });
    property.views += 1;
    await property.save();
    res.json({ success: true, property });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.put('/api/properties/:id', authMiddleware, upload.single('image'), async (req, res) => {
  try {
    const property = await Property.findById(req.params.id);
    if (!property) return res.status(404).json({ error: 'Not found' });
    if (property.userId.toString() !== req.user._id.toString() && req.user.role !== 'admin') {
      return res.status(403).json({ error: 'Unauthorized' });
    }
    const { title, type, listingType, price, bedrooms, location, phone } = req.body;
    if (title) property.title = title;
    if (type) property.type = type;
    if (listingType) property.listingType = listingType;
    if (price) property.price = Number(price);
    if (bedrooms !== undefined) property.bedrooms = Number(bedrooms);
    if (location) property.location = location;
    if (phone) property.phone = phone;

    if (req.file && req.file.buffer && req.file.buffer.length > 0) {
      property.image = await uploadImage(req.file.buffer);
    } else if (req.body.imageData && req.body.imageData.startsWith('data:image')) {
      const base64Data = req.body.imageData.replace(/^data:image\/\w+;base64,/, '');
      const buffer = Buffer.from(base64Data, 'base64');
      property.image = await uploadImage(buffer);
    }
    await property.save();
    res.json({ success: true, property });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.delete('/api/properties/:id', authMiddleware, async (req, res) => {
  try {
    const property = await Property.findById(req.params.id);
    if (!property) return res.status(404).json({ error: 'Not found' });
    if (property.userId.toString() !== req.user._id.toString() && req.user.role !== 'admin') {
      return res.status(403).json({ error: 'Unauthorized' });
    }
    await property.deleteOne();
    res.json({ success: true, message: 'Deleted' });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.post('/api/jobs', authMiddleware, async (req, res) => {
  try {
    const job = new Job({
      ...req.body,
      userId: req.user._id,
      posterName: req.user.name,
      posterImage: req.user.profilePicture,
    });
    await job.save();
    log(`💼 Job created: ${job.title} by ${req.user.phone}`);
    res.status(201).json({ success: true, job });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.get('/api/jobs', async (req, res) => {
  try {
    const jobs = await Job.find().sort({ createdAt: -1 });
    res.json({ success: true, jobs });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.get('/api/jobs/:id', async (req, res) => {
  try {
    const job = await Job.findById(req.params.id);
    if (!job) return res.status(404).json({ error: 'Not found' });
    job.views += 1;
    await job.save();
    res.json({ success: true, job });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.put('/api/jobs/:id', authMiddleware, async (req, res) => {
  try {
    const job = await Job.findById(req.params.id);
    if (!job) return res.status(404).json({ error: 'Not found' });
    if (job.userId.toString() !== req.user._id.toString() && req.user.role !== 'admin') {
      return res.status(403).json({ error: 'Unauthorized' });
    }
    const { title, company, employmentType, salary, location, phone, description, requirements } = req.body;
    if (title) job.title = title;
    if (company) job.company = company;
    if (employmentType) job.employmentType = employmentType;
    if (salary) job.salary = salary;
    if (location) job.location = location;
    if (phone) job.phone = phone;
    if (description !== undefined) job.description = description;
    if (requirements !== undefined) job.requirements = requirements;
    await job.save();
    res.json({ success: true, job });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.delete('/api/jobs/:id', authMiddleware, async (req, res) => {
  try {
    const job = await Job.findById(req.params.id);
    if (!job) return res.status(404).json({ error: 'Not found' });
    if (job.userId.toString() !== req.user._id.toString() && req.user.role !== 'admin') {
      return res.status(403).json({ error: 'Unauthorized' });
    }
    await job.deleteOne();
    res.json({ success: true, message: 'Deleted' });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// ============================================================
//  DASHBOARD
// ============================================================
app.get('/api/dashboard', authMiddleware, async (req, res) => {
  try {
    const userId = req.user._id;
    const products = await Product.find({ userId });
    const properties = await Property.find({ userId });
    const jobs = await Job.find({ userId });
    res.json({
      success: true,
      stats: {
        products: products.length,
        properties: properties.length,
        jobs: jobs.length,
        total: products.length + properties.length + jobs.length,
      },
      products,
      properties,
      jobs,
    });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// ============================================================
//  CHAT ROUTES (enhanced with delete endpoint)
// ============================================================
app.post('/api/chat/messages', authMiddleware, async (req, res) => {
  try {
    const { receiverId, message } = req.body;
    const chat = new ChatMessage({ senderId: req.user._id, receiverId, message });
    await chat.save();
    const room = `chat_${[req.user._id, receiverId].sort().join('_')}`;
    const chatObj = chat.toObject();
    chatObj.seen = chat.read;
    io.to(room).emit('new_message', chatObj);
    const sender = req.user;
    await createNotification(
      receiverId,
      'chat',
      `New message from ${sender.name}`,
      message,
      { chatId: chat._id, senderId: sender._id }
    );
    res.status(201).json({ success: true, message: chatObj });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.get('/api/chat/messages/:userId', authMiddleware, async (req, res) => {
  try {
    const otherUserId = req.params.userId;
    const userId = req.user._id;
    const messages = await ChatMessage.find({
      $or: [
        { senderId: userId, receiverId: otherUserId },
        { senderId: otherUserId, receiverId: userId },
      ],
    }).sort({ createdAt: 1 });
    // Mark all as read
    await ChatMessage.updateMany(
      { senderId: otherUserId, receiverId: userId, read: false },
      { read: true, readAt: new Date() }
    );
    // Map to include seen field
    const messagesWithSeen = messages.map(msg => {
      const obj = msg.toObject();
      obj.seen = msg.read;
      return obj;
    });
    res.json({ success: true, messages: messagesWithSeen });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.get('/api/chat/unread', authMiddleware, async (req, res) => {
  try {
    const count = await ChatMessage.countDocuments({ receiverId: req.user._id, read: false });
    res.json({ success: true, count });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// NEW: Delete a message via REST (fallback)
app.delete('/api/chat/messages/:id', authMiddleware, async (req, res) => {
  try {
    const message = await ChatMessage.findById(req.params.id);
    if (!message) return res.status(404).json({ error: 'Message not found' });
    if (message.senderId.toString() !== req.user._id.toString()) {
      return res.status(403).json({ error: 'Not authorized to delete this message' });
    }
    await message.deleteOne();
    // Broadcast deletion
    const room = `chat_${[message.senderId, message.receiverId].sort().join('_')}`;
    io.to(room).emit('message_deleted', { messageId: message._id });
    res.json({ success: true, message: 'Deleted' });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// ============================================================
//  CONTACT & SETTINGS (unchanged)
// ============================================================
app.post('/api/contact', authMiddleware, async (req, res) => {
  try {
    const { name, email, subject, message } = req.body;
    const contact = new ContactMessage({ name, email, subject, message, userId: req.user._id });
    await contact.save();
    log(`📧 Contact message from ${email}: ${subject}`);
    const admins = await User.find({ role: 'admin' });
    for (const admin of admins) {
      await createNotification(
        admin._id,
        'contact_reply',
        `New contact message from ${name}`,
        subject,
        { contactId: contact._id }
      );
    }
    res.status(201).json({ success: true, message: 'Sent' });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.get('/api/contact/messages', authMiddleware, adminMiddleware, async (req, res) => {
  try {
    const messages = await ContactMessage.find().sort({ createdAt: -1 });
    res.json({ success: true, messages });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.put('/api/contact/messages/:id/read', authMiddleware, adminMiddleware, async (req, res) => {
  try {
    const msg = await ContactMessage.findById(req.params.id);
    if (!msg) return res.status(404).json({ error: 'Not found' });
    msg.read = true;
    await msg.save();
    res.json({ success: true, message: msg });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.get('/api/settings/owner_message', async (req, res) => {
  try {
    let setting = await OwnerMessage.findOne({ key: 'owner_message' });
    if (!setting) {
      setting = new OwnerMessage({ key: 'owner_message', value: 'Welcome to NjalaMarket! Your trusted marketplace.' });
      await setting.save();
    }
    res.json({ success: true, value: setting.value });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.post('/api/settings', authMiddleware, adminMiddleware, async (req, res) => {
  try {
    const { key, value } = req.body;
    let setting = await OwnerMessage.findOne({ key });
    if (setting) setting.value = value;
    else setting = new OwnerMessage({ key, value });
    await setting.save();
    log(`📝 Owner message updated: ${value.substring(0, 30)}...`);
    res.json({ success: true, setting });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// ============================================================
//  USER STATUS & SEARCH (unchanged)
// ============================================================
app.put('/api/users/status', authMiddleware, async (req, res) => {
  try {
    const { isOnline } = req.body;
    req.user.isOnline = isOnline;
    req.user.lastSeen = new Date();
    await req.user.save();
    res.json({ success: true });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.get('/api/users/:id/status', async (req, res) => {
  try {
    const user = await User.findById(req.params.id).select('isOnline lastSeen');
    if (!user) return res.status(404).json({ error: 'User not found' });
    res.json({ success: true, isOnline: user.isOnline, lastSeen: user.lastSeen });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.get('/api/search', async (req, res) => {
  try {
    const { q, category, location } = req.query;
    const query = {};
    if (q) query.$or = [
      { title: { $regex: q, $options: 'i' } },
      { company: { $regex: q, $options: 'i' } },
    ];
    if (location) query.location = { $regex: location, $options: 'i' };
    if (category) query.category = category;
    const [products, properties, jobs] = await Promise.all([
      Product.find(query).limit(10),
      Property.find(query).limit(10),
      Job.find(query).limit(10),
    ]);
    res.json({ success: true, results: { products, properties, jobs } });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// ============================================================
//  NOTIFICATION CENTER API (unchanged)
// ============================================================
app.get('/api/notifications', authMiddleware, async (req, res) => {
  try {
    const { limit = 50, skip = 0 } = req.query;
    const notifications = await Notification.find({ userId: req.user._id })
      .sort({ createdAt: -1 })
      .limit(Number(limit))
      .skip(Number(skip));
    const total = await Notification.countDocuments({ userId: req.user._id });
    const unread = await Notification.countDocuments({ userId: req.user._id, read: false });
    res.json({ success: true, notifications, total, unread });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.put('/api/notifications/:id/read', authMiddleware, async (req, res) => {
  try {
    const notification = await Notification.findOne({ _id: req.params.id, userId: req.user._id });
    if (!notification) return res.status(404).json({ error: 'Not found' });
    notification.read = true;
    await notification.save();
    res.json({ success: true, notification });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.put('/api/notifications/read-all', authMiddleware, async (req, res) => {
  try {
    await Notification.updateMany(
      { userId: req.user._id, read: false },
      { read: true }
    );
    res.json({ success: true });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.delete('/api/notifications/:id', authMiddleware, async (req, res) => {
  try {
    const result = await Notification.deleteOne({ _id: req.params.id, userId: req.user._id });
    if (result.deletedCount === 0) return res.status(404).json({ error: 'Not found' });
    res.json({ success: true });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.get('/api/notifications/unread-count', authMiddleware, async (req, res) => {
  try {
    const count = await Notification.countDocuments({ userId: req.user._id, read: false });
    res.json({ success: true, count });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// ============================================================
//  ERROR HANDLING
// ============================================================
app.use((err, req, res, next) => {
  log(`❌ Unhandled error: ${err.stack}`);
  res.status(500).json({ error: 'Internal server error' });
});

// ============================================================
//  START SERVER
// ============================================================
(async function testCloudinary() {
  try {
    const result = await cloudinary.api.ping();
    if (result.status === 'ok') {
      log('✅ Cloudinary connected successfully');
    } else {
      log('⚠️ Cloudinary ping responded but status not "ok"');
    }
  } catch (error) {
    log('❌ Cloudinary connection failed: ' + error.message);
  }
})();

log('🔌 Socket.IO server is running and ready for connections');

server.listen(PORT, () => {
  log(`🚀 Server running on port ${PORT}`);
  log(`📦 MongoDB: ${MONGODB_URI}`);
  log(`☁️ Cloudinary: ${process.env.CLOUDINARY_CLOUD_NAME || 'not set'}`);
  log(`📱 Twilio: ${TWILIO_PHONE ? 'configured' : 'mock mode'}`);
});