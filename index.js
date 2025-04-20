import express from 'express';
import cors from 'cors';
import jwt from 'jsonwebtoken';
import multer from 'multer';
import path from 'path';
import fs from 'fs';
import mongoose from 'mongoose';
import dotenv from 'dotenv';

dotenv.config();

const app = express();
const PORT = process.env.PORT || 5000;
const JWT_SECRET = process.env.JWT_SECRET || 'bgmi_super_secret';
const UPLOADS_DIR = path.resolve('./uploads');

// Ensure uploads directory exists
if (!fs.existsSync(UPLOADS_DIR)) fs.mkdirSync(UPLOADS_DIR);

const upload = multer({ dest: UPLOADS_DIR });

app.use(cors());
app.use(express.json());
app.use('/uploads', express.static(UPLOADS_DIR));

// --- Mongoose Models ---
const accountSchema = new mongoose.Schema({
  account_uid: String,
  account_name: String,
  account_level: Number,
  collection_level: Number,
  mythic_outfits: Number,
  laboratory_weapons: String,
  x_suits: String,
  image_url: String,
  video_url: String,
  sold: { type: Boolean, default: false },
  created_at: { type: Date, default: Date.now }
});

const adminSchema = new mongoose.Schema({
  username: { type: String, unique: true },
  password: String
});

const reviewSchema = new mongoose.Schema({
  account_id: mongoose.Schema.Types.ObjectId,
  name: String,
  review: String,
  created_at: { type: Date, default: Date.now }
});

const Account = mongoose.model('Account', accountSchema);
const Admin = mongoose.model('Admin', adminSchema);
const Review = mongoose.model('Review', reviewSchema);

// Connect to MongoDB
mongoose.connect(process.env.MONGO_URI, {
  useNewUrlParser: true,
  useUnifiedTopology: true
}).then(async () => {
  console.log('Connected to MongoDB');
  // Seed default admin if not exists
  const admin = await Admin.findOne({ username: 'admin' });
  if (!admin) {
    await Admin.create({ username: 'admin', password: 'admin123' });
    console.log('Default admin created');
  }
  app.listen(PORT, () => {
    console.log(`BGMI Store backend running on port ${PORT}`);
  });
}).catch(err => {
  console.error('MongoDB connection error:', err);
});

// Auth middleware
function authenticateToken(req, res, next) {
  const token = req.headers['authorization'];
  if (!token) return res.sendStatus(401);
  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) return res.sendStatus(403);
    req.user = user;
    next();
  });
}

// --- API ROUTES ---

// Auth
app.post('/api/admin/login', async (req, res) => {
  const { username, password } = req.body;
  const admin = await Admin.findOne({ username, password });
  if (!admin) return res.status(401).json({ error: 'Invalid credentials' });
  const token = jwt.sign({ username }, JWT_SECRET, { expiresIn: '2h' });
  res.json({ token });
});

// Get all accounts (with search)
app.get('/api/accounts', async (req, res) => {
  const { search } = req.query;
  let query = {};
  if (search) {
    query = {
      $or: [
        { laboratory_weapons: { $regex: search, $options: 'i' } },
        { x_suits: { $regex: search, $options: 'i' } }
      ]
    };
  }
  const accounts = await Account.find(query).sort({ created_at: -1 });
  res.json(accounts);
});

// Get single account
app.get('/api/accounts/:id', async (req, res) => {
  try {
    const account = await Account.findById(req.params.id);
    if (!account) return res.status(404).json({ error: 'Not found' });
    res.json(account);
  } catch (e) {
    res.status(400).json({ error: 'Invalid ID' });
  }
});

// Add account (admin)
app.post('/api/accounts', authenticateToken, upload.fields([{ name: 'image' }, { name: 'video' }]), async (req, res) => {
  const data = req.body;
  let image_url = '', video_url = '';
  if (req.files && req.files.image) image_url = `/uploads/${req.files.image[0].filename}`;
  if (req.files && req.files.video) video_url = `/uploads/${req.files.video[0].filename}`;
  const { account_uid, account_name, account_level, collection_level, mythic_outfits, laboratory_weapons, x_suits } = data;
  const account = await Account.create({
    account_uid,
    account_name,
    account_level,
    collection_level,
    mythic_outfits,
    laboratory_weapons,
    x_suits,
    image_url,
    video_url
  });
  res.json({ id: account._id });
});

// Update account (admin)
app.put('/api/accounts/:id', authenticateToken, async (req, res) => {
  const { account_uid, account_name, account_level, collection_level, mythic_outfits, laboratory_weapons, x_suits, sold } = req.body;
  await Account.findByIdAndUpdate(req.params.id, {
    account_uid,
    account_name,
    account_level,
    collection_level,
    mythic_outfits,
    laboratory_weapons,
    x_suits,
    sold
  });
  res.json({ success: true });
});

// Delete account (admin)
app.delete('/api/accounts/:id', authenticateToken, async (req, res) => {
  await Account.findByIdAndDelete(req.params.id);
  res.json({ success: true });
});

// Mark as sold (admin)
app.patch('/api/accounts/:id/sold', authenticateToken, async (req, res) => {
  await Account.findByIdAndUpdate(req.params.id, { sold: true });
  res.json({ success: true });
});

// Reviews
app.get('/api/reviews', async (req, res) => {
  const reviews = await Review.find().sort({ created_at: -1 }).limit(20);
  res.json(reviews);
});

app.post('/api/reviews', async (req, res) => {
  const { account_id, name, review } = req.body;
  await Review.create({ account_id, name, review });
  res.json({ success: true });
});
