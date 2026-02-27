const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const nodemailer = require('nodemailer');
require('dotenv').config();

const app = express();


app.use(cors());
app.use(express.json());


const transporter = nodemailer.createTransport({
  service: 'gmail',
  auth: {
    user: process.env.EMAIL_USER || 'your-email@gmail.com', 
    pass: process.env.EMAIL_PASS || 'your-app-password' 
  }
});

// In-memory OTP storage (in production, use Redis or database)
const otpStore = new Map();

// MongoDB Connection
const MONGODB_URI = process.env.MONGODB_URI || 'mongodb://localhost:27017/campus_canteen';
mongoose.connect(MONGODB_URI, {
  useNewUrlParser: true,
  useUnifiedTopology: true,
})
.then(() => console.log('MongoDB Connected Successfully'))
.catch(err => console.log('MongoDB Connection Error:', err));

// User Schema
const userSchema = new mongoose.Schema({
  name: { type: String, required: true },
  email: { type: String, required: true, unique: true },
  username: { type: String, required: true, unique: true },
  password: { type: String, required: true },
  userType: { type: String, enum: ['student', 'owner'], required: true },
  studentId: { type: String, default: '' },
  phone: { type: String, default: '' },
  profileImage: { type: String, default: '' },
  isVerified: { type: Boolean, default: false },
  createdAt: { type: Date, default: Date.now }
});

// Menu Item Schema
const menuItemSchema = new mongoose.Schema({
  name: { type: String, required: true },
  price: { type: Number, required: true },
  category: { type: String, required: true },
  description: { type: String, required: true },
  emoji: { type: String, default: '🍽️' },
  imageUrl: { type: String, default: '' },
  available: { type: Boolean, default: true },
  popular: { type: Boolean, default: false },
  createdAt: { type: Date, default: Date.now }
});

// Order Schema
const orderSchema = new mongoose.Schema({
  orderId: { type: String, required: true },
  userId: { type: String, required: true },
  items: [{
    name: String,
    price: Number,
    quantity: Number,
    emoji: String,
    imageUrl: String
  }],
  total: { type: Number, required: true },
  status: { type: String, enum: ['pending', 'preparing', 'ready', 'completed'], default: 'pending' },
  createdAt: { type: Date, default: Date.now }
});

// Booking Schema
const bookingSchema = new mongoose.Schema({
  bookingId: { type: String, required: true },
  userId: { type: String, required: true },
  userName: { type: String, required: true },
  timeSlot: { type: String, required: true },
  date: { type: String, required: true },
  seatNumber: { type: Number, required: true },
  status: { type: String, enum: ['confirmed', 'cancelled', 'completed', 'expired'], default: 'confirmed' },
  fine: { type: Number, default: 0 },
  expiresAt: { type: Date, required: true },
  createdAt: { type: Date, default: Date.now }
});

// Notice Schema
const noticeSchema = new mongoose.Schema({
  title: { type: String, required: true },
  message: { type: String, required: true },
  type: { type: String, enum: ['info', 'warning', 'closure', 'special'], default: 'info' },
  urgent: { type: Boolean, default: false },
  expiry: { type: Date },
  createdAt: { type: Date, default: Date.now }
});

// Time Slot Schema
const timeSlotSchema = new mongoose.Schema({
  time: { type: String, required: true },
  label: { type: String, required: true },
  booked: { type: Number, default: 0 },
  total: { type: Number, default: 20 },
  createdAt: { type: Date, default: Date.now }
});

// Complaint Schema
const complaintSchema = new mongoose.Schema({
  complaintId: { type: String, required: true },
  userId: { type: String, required: true },
  studentName: { type: String, required: true },
  subject: { type: String, required: true },
  description: { type: String, required: true },
  status: { type: String, enum: ['pending', 'in-progress', 'resolved'], default: 'pending' },
  response: { type: String, default: '' },
  createdAt: { type: Date, default: Date.now },
  resolvedAt: { type: Date }
});

// Models
const User = mongoose.model('User', userSchema);
const MenuItem = mongoose.model('MenuItem', menuItemSchema);
const Order = mongoose.model('Order', orderSchema);
const Booking = mongoose.model('Booking', bookingSchema);
const Notice = mongoose.model('Notice', noticeSchema);
const TimeSlot = mongoose.model('TimeSlot', timeSlotSchema);
const Complaint = mongoose.model('Complaint', complaintSchema);

// JWT Secret
const JWT_SECRET = process.env.JWT_SECRET || 'campus_canteen_secret_key_2023';

// Auth Middleware
const authMiddleware = async (req, res, next) => {
  try {
    const token = req.header('Authorization')?.replace('Bearer ', '');
    if (!token) {
      return res.status(401).json({ message: 'No token, authorization denied' });
    }

    const decoded = jwt.verify(token, JWT_SECRET);
    req.userId = decoded.userId;
    req.userType = decoded.userType;
    next();
  } catch (error) {
    res.status(401).json({ message: 'Token is not valid' });
  }
};

// Initialize default data (without demo users)
const initializeData = async () => {
  try {
    // Check if menu items exist
    const menuItemsCount = await MenuItem.countDocuments();
    if (menuItemsCount === 0) {
      const defaultMenuItems = [
        { name: 'Masala Dosa', price: 60, category: 'breakfast', description: 'Crispy South Indian crepe with spicy potato filling', emoji: '🫓', imageUrl: 'https://images.unsplash.com/photo-1630383249896-424e482df921?w=400', popular: true, available: true },
        { name: 'Idli Sambar', price: 40, category: 'breakfast', description: 'Steamed rice cakes with lentil soup', emoji: '🍘', imageUrl: 'https://images.unsplash.com/photo-1589301760014-d929f3979dbc?w=400', available: true },
        { name: 'Vada Pav', price: 25, category: 'snacks', description: 'Mumbai special potato fritter sandwich', emoji: '🍔', imageUrl: 'https://images.unsplash.com/photo-1606491048164-fad4a855d1f1?w=400', popular: true, available: true },
        { name: 'Paneer Butter Masala', price: 120, category: 'lunch', description: 'Cottage cheese in rich tomato gravy', emoji: '🍛', imageUrl: 'https://images.unsplash.com/photo-1631452180519-c014fe946bc7?w=400', popular: true, available: true },
        { name: 'Biryani', price: 150, category: 'lunch', description: 'Fragrant basmati rice with spices and vegetables', emoji: '🍚', imageUrl: 'https://images.unsplash.com/photo-1563379091339-03b21ab4a4f8?w=400', popular: true, available: true },
        { name: 'Samosa', price: 20, category: 'snacks', description: 'Crispy pastry filled with spiced potatoes', emoji: '🥟', imageUrl: 'https://images.unsplash.com/photo-1601050690597-df0568f70950?w=400', available: true },
        { name: 'Pav Bhaji', price: 80, category: 'lunch', description: 'Spicy vegetable mash served with bread', emoji: '🍲', imageUrl: 'https://images.unsplash.com/photo-1606491048164-fad4a855d1f1?w=400', available: true },
        { name: 'Chai', price: 15, category: 'beverages', description: 'Indian spiced tea', emoji: '☕', imageUrl: 'https://images.unsplash.com/photo-1571934811356-5cc061b6821f?w=400', popular: true, available: true },
        { name: 'Coffee', price: 20, category: 'beverages', description: 'Fresh brewed filter coffee', emoji: '☕', imageUrl: 'https://images.unsplash.com/photo-1509042239860-f550ce710b93?w=400', available: true },
        { name: 'Mango Lassi', price: 50, category: 'beverages', description: 'Sweet mango yogurt drink', emoji: '🥤', imageUrl: 'https://images.unsplash.com/photo-1623428454614-abaf00244e52?w=400', available: true },
        { name: 'Upma', price: 35, category: 'breakfast', description: 'Savory semolina porridge', emoji: '🍲', imageUrl: 'https://images.unsplash.com/photo-1589301773881-13a2b23f83b2?w=400', available: true },
        { name: 'Poha', price: 30, category: 'breakfast', description: 'Flattened rice with spices', emoji: '🍚', imageUrl: 'https://images.unsplash.com/photo-1626082927389-6cd097cdc6ec?w=400', available: true },
        { name: 'Spring Roll', price: 40, category: 'snacks', description: 'Crispy vegetable rolls', emoji: '🥙', imageUrl: 'https://images.unsplash.com/photo-1537047902294-62a40c20a6ae?w=400', available: true },
        { name: 'Gulab Jamun', price: 35, category: 'snacks', description: 'Sweet milk-solid dumplings', emoji: '🍡', imageUrl: 'https://images.unsplash.com/photo-1589217157232-464b505b197f?w=400', available: true },
        { name: 'Ice Cream', price: 45, category: 'snacks', description: 'Assorted flavors', emoji: '🍨', imageUrl: 'https://images.unsplash.com/photo-1563805042-7684c019e1cb?w=400', available: true }
      ];
      await MenuItem.insertMany(defaultMenuItems);
      console.log('✅ Added menu items with images');
    }

    // Check if time slots exist
    const timeSlotsCount = await TimeSlot.countDocuments();
    if (timeSlotsCount === 0) {
      const defaultTimeSlots = [
        { time: '08:00', label: 'Breakfast (8:00 AM - 10:00 AM)', total: 30, booked: 0 },
        { time: '12:00', label: 'Lunch (12:00 PM - 2:00 PM)', total: 50, booked: 0 },
        { time: '16:00', label: 'Snacks (4:00 PM - 6:00 PM)', total: 25, booked: 0 },
        { time: '19:00', label: 'Dinner (7:00 PM - 9:00 PM)', total: 40, booked: 0 }
      ];
      await TimeSlot.insertMany(defaultTimeSlots);
      console.log('✅ Added time slots');
    }

    // Check if notices exist
    const noticesCount = await Notice.countDocuments();
    if (noticesCount === 0) {
      const defaultNotices = [
        { 
          title: 'Welcome to Campus Canteen!', 
          message: 'Enjoy fresh food daily. Order now!', 
          type: 'info',
          urgent: false
        },
        { 
          title: 'Special Discount Today', 
          message: '20% off on all lunch items!', 
          type: 'special',
          urgent: true
        },
        { 
          title: 'New Menu Items', 
          message: 'Check out our new South Indian breakfast options', 
          type: 'info',
          urgent: false
        }
      ];
      await Notice.insertMany(defaultNotices);
      console.log('✅ Added notices');
    }
  } catch (error) {
    console.error('Error initializing data:', error);
  }
};

// Routes

// Test route
app.get('/', (req, res) => {
  res.json({ message: 'Campus Canteen API is running!' });
});

// Send OTP for registration
app.post('/api/send-otp', async (req, res) => {
  try {
    const { email, name } = req.body;

    if (!email) {
      return res.status(400).json({ message: 'Email is required' });
    }

    // Check if user already exists
    const existingUser = await User.findOne({ email });
    if (existingUser) {
      return res.status(400).json({ message: 'Email already registered' });
    }

    // Generate 6-digit OTP
    const otp = Math.floor(100000 + Math.random() * 900000).toString();
    
    // Store OTP with expiry (5 minutes)
    otpStore.set(email, {
      otp: otp,
      expiresAt: Date.now() + 5 * 60 * 1000,
      attempts: 0
    });

    // Send OTP via email
    const mailOptions = {
      from: process.env.EMAIL_USER || 'Campus Canteen <noreply@campuscanteen.com>',
      to: email,
      subject: '🎉 Welcome to Campus Canteen - Verify Your Email',
      html: `
        <div style="font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; max-width: 600px; margin: 0 auto; padding: 0; background-color: #f5f5f5;">
          <div style="background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); padding: 40px 20px; text-align: center;">
            <h1 style="color: white; margin: 0; font-size: 32px;">🍽️ Campus Canteen</h1>
            <p style="color: rgba(255,255,255,0.95); margin: 10px 0 0 0; font-size: 16px;">Your Digital Food Court Experience</p>
          </div>
          <div style="background-color: white; padding: 40px 30px; box-shadow: 0 4px 6px rgba(0,0,0,0.1);">
            <h2 style="color: #333; margin-top: 0; font-size: 24px;">Welcome, ${name || 'User'}! 👋</h2>
            <p style="color: #666; font-size: 16px; line-height: 1.6; margin-bottom: 20px;">
              Thank you for joining Campus Canteen! We're excited to have you on board. 
              To complete your registration and start enjoying delicious meals, please verify your email address.
            </p>
            
            <div style="background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); border-radius: 10px; padding: 25px; text-align: center; margin: 30px 0;">
              <p style="color: white; margin: 0 0 15px 0; font-size: 14px; opacity: 0.9;">Your Verification Code</p>
              <h1 style="color: white; margin: 0; font-size: 42px; letter-spacing: 10px; font-weight: bold; font-family: 'Courier New', monospace;">${otp}</h1>
            </div>
            
            <div style="background: #fff3cd; border-left: 4px solid #ffc107; padding: 15px; margin: 25px 0; border-radius: 4px;">
              <p style="color: #856404; margin: 0; font-size: 14px;">
                ⏰ <strong>Important:</strong> This OTP is valid for <strong>5 minutes</strong> only. Please enter it soon!
              </p>
            </div>
            
            <div style="background: #f8f9fa; padding: 25px; border-radius: 8px; margin: 25px 0;">
              <h3 style="color: #667eea; margin-top: 0; font-size: 18px;">What You Can Enjoy:</h3>
              <ul style="color: #555; font-size: 15px; line-height: 1.8; margin: 0; padding-left: 20px;">
                <li>✅ Browse our delicious menu with real-time availability</li>
                <li>✅ Place orders and skip the queue</li>
                <li>✅ Book tables for dine-in experience</li>
                <li>✅ Track your order status in real-time</li>
                <li>✅ View order history and favorites</li>
                <li>✅ Get exclusive deals and offers</li>
              </ul>
            </div>
            
            <p style="color: #666; font-size: 16px; line-height: 1.6; margin-top: 25px;">
              Once verified, you'll have instant access to all our services. <br>
              <strong>Happy eating! 🎉</strong>
            </p>
            
            <hr style="border: none; border-top: 1px solid #eee; margin: 30px 0;">
            <p style="color: #999; font-size: 12px; text-align: center; margin: 0;">
              If you didn't request this OTP, please ignore this email.
            </p>
          </div>
          <div style="background: #f8f9fa; padding: 25px; text-align: center;">
            <div style="font-size: 28px; margin-bottom: 10px;">🍕 🍔 🍰 ☕</div>
            <p style="color: #666; font-size: 14px; margin: 5px 0;">Campus Canteen - Making Campus Life Delicious!</p>
            <p style="color: #999; font-size: 12px; margin: 10px 0 0 0;">© 2025 Campus Canteen. All rights reserved.</p>
          </div>
        </div>
      `
    };

    // Try to send email
    try {
      await transporter.sendMail(mailOptions);
      console.log(`OTP sent to ${email}: ${otp}`); // For testing
      
      res.json({ 
        success: true,
        message: 'OTP sent to your email successfully',
        devOtp: process.env.NODE_ENV === 'development' ? otp : undefined
      });
    } catch (emailError) {
      console.error('Email sending failed:', emailError);
      console.log(`[FALLBACK] OTP for ${email}: ${otp}`);
      res.json({ 
        success: true,
        message: 'OTP generated (check console for testing)',
        devOtp: otp
      });
    }

  } catch (error) {
    console.error('Send OTP error:', error);
    res.status(500).json({ message: 'Failed to send OTP' });
  }
});

// User Registration with OTP verification
app.post('/api/register', async (req, res) => {
  try {
    const { name, email, username, password, userType, otp } = req.body;

    // Validation
    if (!name || !email || !username || !password || !userType || !otp) {
      return res.status(400).json({ 
        message: 'All fields including OTP are required' 
      });
    }

    if (password.length < 6) {
      return res.status(400).json({ 
        message: 'Password must be at least 6 characters long' 
      });
    }

    // Verify OTP
    const storedOtpData = otpStore.get(email);
    
    if (!storedOtpData) {
      return res.status(400).json({ 
        message: 'OTP expired or not found. Please request a new OTP.' 
      });
    }

    // Check if OTP is expired
    if (Date.now() > storedOtpData.expiresAt) {
      otpStore.delete(email);
      return res.status(400).json({ 
        message: 'OTP has expired. Please request a new OTP.' 
      });
    }

    // Check OTP attempts (prevent brute force)
    if (storedOtpData.attempts >= 3) {
      otpStore.delete(email);
      return res.status(400).json({ 
        message: 'Too many failed attempts. Please request a new OTP.' 
      });
    }

    // Verify OTP
    if (storedOtpData.otp !== otp) {
      storedOtpData.attempts += 1;
      otpStore.set(email, storedOtpData);
      return res.status(400).json({ 
        message: `Invalid OTP. ${3 - storedOtpData.attempts} attempts remaining.` 
      });
    }

    // OTP verified - remove from store
    otpStore.delete(email);

    // OTP verified - remove from store
    otpStore.delete(email);

    // Check if user already exists
    const existingUser = await User.findOne({ 
      $or: [{ email }, { username }] 
    });
    
    if (existingUser) {
      return res.status(400).json({ 
        message: 'User with this email or username already exists' 
      });
    }

    // Hash password
    const hashedPassword = await bcrypt.hash(password, 12);

    // Generate student ID if user is student
    let studentId = '';
    if (userType === 'student') {
      studentId = 'STU' + Math.floor(1000 + Math.random() * 9000);
    }

    // Create user
    const user = new User({
      name,
      email,
      username: username.toLowerCase(),
      password: hashedPassword,
      userType,
      studentId,
      isVerified: true
    });

    await user.save();

    // Generate JWT token
    const token = jwt.sign(
      { userId: user._id, userType: user.userType },
      JWT_SECRET,
      { expiresIn: '7d' }
    );

    res.status(201).json({
      message: 'User created successfully',
      token,
      user: {
        id: user._id,
        name: user.name,
        email: user.email,
        userType: user.userType,
        studentId: user.studentId
      }
    });
  } catch (error) {
    console.error('Registration error:', error);
    res.status(500).json({ message: 'Server error during registration' });
  }
});

// User Login
app.post('/api/login', async (req, res) => {
  try {
    const { username, password, userType } = req.body;

    // Validation
    if (!username || !password || !userType) {
      return res.status(400).json({ message: 'All fields are required' });
    }

    // Find user
    const user = await User.findOne({ 
      username: username.toLowerCase(), 
      userType 
    });
    
    if (!user) {
      return res.status(400).json({ message: 'Invalid username or password' });
    }

    // Check password
    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      return res.status(400).json({ message: 'Invalid username or password' });
    }

    // Generate JWT token
    const token = jwt.sign(
      { userId: user._id, userType: user.userType },
      JWT_SECRET,
      { expiresIn: '7d' }
    );

    res.json({
      message: 'Login successful',
      token,
      user: {
        id: user._id,
        name: user.name,
        email: user.email,
        userType: user.userType,
        studentId: user.studentId,
        phone: user.phone
      }
    });
  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({ message: 'Server error during login' });
  }
});

// Get user profile
app.get('/api/profile', authMiddleware, async (req, res) => {
  try {
    const user = await User.findById(req.userId).select('-password');
    if (!user) {
      return res.status(404).json({ message: 'User not found' });
    }
    res.json({ user });
  } catch (error) {
    console.error('Profile error:', error);
    res.status(500).json({ message: 'Server error' });
  }
});

// Update user profile
app.put('/api/profile', authMiddleware, async (req, res) => {
  try {
    const { name, phone, studentId, profileImage } = req.body;
    
    if (!name || !name.trim()) {
      return res.status(400).json({ message: 'Name is required' });
    }
    
    const updateData = { 
      name: name.trim(), 
      phone: phone ? phone.trim() : '',
      studentId: studentId ? studentId.trim() : ''
    };
    
    // Only update profile image if provided
    if (profileImage) {
      updateData.profileImage = profileImage;
    }
    
    const user = await User.findByIdAndUpdate(
      req.userId,
      updateData,
      { new: true }
    ).select('-password');

    if (!user) {
      return res.status(404).json({ message: 'User not found' });
    }

    // Update localStorage token data
    res.json({ 
      message: 'Profile updated successfully', 
      user 
    });
  } catch (error) {
    console.error('Profile update error:', error);
    res.status(500).json({ message: 'Server error' });
  }
});

// Get menu items
app.get('/api/menu', async (req, res) => {
  try {
    const { category } = req.query;
    let filter = { available: true };
    
    if (category && category !== 'all') {
      filter.category = category;
    }

    const menuItems = await MenuItem.find(filter);
    res.json(menuItems);
  } catch (error) {
    console.error('Menu error:', error);
    res.status(500).json({ message: 'Server error' });
  }
});

// Get time slots
app.get('/api/time-slots', async (req, res) => {
  try {
    const timeSlots = await TimeSlot.find();
    res.json(timeSlots);
  } catch (error) {
    console.error('Time slots error:', error);
    res.status(500).json({ message: 'Server error' });
  }
});

// Get notices
app.get('/api/notices', async (req, res) => {
  try {
    const notices = await Notice.find()
      .sort({ createdAt: -1 });
    res.json(notices);
  } catch (error) {
    console.error('Notices error:', error);
    res.status(500).json({ message: 'Server error' });
  }
});

// Create booking
app.post('/api/bookings', authMiddleware, async (req, res) => {
  try {
    const { timeSlot } = req.body;

    // Get user details
    const user = await User.findById(req.userId);
    if (!user) {
      return res.status(404).json({ message: 'User not found' });
    }

    // Find the time slot
    const slot = await TimeSlot.findOne({ time: timeSlot });
    if (!slot) {
      return res.status(404).json({ message: 'Time slot not found' });
    }

    // Check availability
    if (slot.booked >= slot.total) {
      return res.status(400).json({ message: 'Time slot is fully booked' });
    }

    // Calculate seat number (next available seat)
    const seatNumber = slot.booked + 1;

    // Calculate expiry time based on time slot
    const today = new Date();
    const [startTime, endTime] = slot.time.split('-');
    const [endHour, endMinute] = endTime.trim().split(':');
    const expiryDate = new Date(today);
    expiryDate.setHours(parseInt(endHour), parseInt(endMinute), 0, 0);

    // Generate booking ID
    const bookingId = 'BOOK' + Date.now().toString().slice(-6);

    // Create booking
    const booking = new Booking({
      bookingId,
      userId: req.userId,
      userName: user.name,
      timeSlot: slot.label,
      date: new Date().toLocaleDateString('en-IN'),
      seatNumber: seatNumber,
      expiresAt: expiryDate
    });

    // Update slot booked count
    slot.booked += 1;
    await slot.save();
    await booking.save();

    res.status(201).json({ 
      message: 'Booking created successfully', 
      booking 
    });
  } catch (error) {
    console.error('Booking error:', error);
    res.status(500).json({ message: 'Server error' });
  }
});

// Create order
app.post('/api/orders', authMiddleware, async (req, res) => {
  try {
    const { items, total } = req.body;

    // Get user details
    const user = await User.findById(req.userId);
    if (!user) {
      return res.status(404).json({ message: 'User not found' });
    }

    // Generate order ID
    const orderId = 'ORD' + Date.now().toString().slice(-6);

    // Create order
    const order = new Order({
      orderId,
      userId: req.userId,
      items,
      total
    });

    await order.save();

    // Send order receipt email
    try {
      const orderDate = new Date().toLocaleString('en-IN', { 
        dateStyle: 'medium', 
        timeStyle: 'short',
        timeZone: 'Asia/Kolkata'
      });

      // Build items HTML
      let itemsHtml = '';
      let itemNumber = 1;
      items.forEach(item => {
        itemsHtml += `
          <tr>
            <td style="padding: 12px; border-bottom: 1px solid #eee; color: #666;">${itemNumber++}</td>
            <td style="padding: 12px; border-bottom: 1px solid #eee; color: #333; font-weight: 500;">${item.name}</td>
            <td style="padding: 12px; border-bottom: 1px solid #eee; text-align: center; color: #666;">${item.quantity}</td>
            <td style="padding: 12px; border-bottom: 1px solid #eee; text-align: right; color: #333;">₹${item.price}</td>
            <td style="padding: 12px; border-bottom: 1px solid #eee; text-align: right; color: #333; font-weight: 500;">₹${item.price * item.quantity}</td>
          </tr>
        `;
      });

      const receiptEmail = {
        from: {
          name: 'Campus Canteen',
          address: process.env.EMAIL_USER
        },
        to: user.email,
        subject: `🧾 Order Receipt - ${orderId} | Campus Canteen`,
        html: `
          <!DOCTYPE html>
          <html>
          <head>
            <style>
              body { font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; margin: 0; padding: 0; background-color: #f5f5f5; }
              .container { max-width: 650px; margin: 0 auto; background: white; }
              .header { background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); padding: 40px 30px; text-align: center; color: white; }
              .header h1 { margin: 0; font-size: 32px; }
              .header p { margin: 10px 0 0 0; opacity: 0.95; font-size: 16px; }
              .content { padding: 40px 30px; }
              .order-info { background: #f8f9fa; padding: 25px; border-radius: 8px; margin-bottom: 30px; }
              .order-info-row { display: flex; justify-content: space-between; margin-bottom: 12px; }
              .order-info-label { color: #666; font-size: 14px; }
              .order-info-value { color: #333; font-weight: 600; font-size: 14px; }
              .order-id { font-size: 24px; color: #667eea; font-weight: bold; text-align: center; margin: 20px 0; }
              table { width: 100%; border-collapse: collapse; margin: 20px 0; }
              th { background: #f8f9fa; padding: 12px; text-align: left; font-size: 13px; color: #666; text-transform: uppercase; letter-spacing: 0.5px; }
              .total-row { background: #f8f9fa; }
              .total-row td { padding: 15px 12px; font-size: 18px; font-weight: bold; color: #333; }
              .footer { background: #f8f9fa; padding: 30px; text-align: center; color: #666; }
              .thank-you { font-size: 20px; color: #667eea; font-weight: 600; margin-bottom: 15px; }
              .emoji-row { font-size: 28px; margin: 20px 0; }
            </style>
          </head>
          <body>
            <div class="container">
              <div class="header">
                <h1>🍽️ Campus Canteen</h1>
                <p>Order Receipt</p>
              </div>
              
              <div class="content">
                <div class="thank-you">Thank You for Your Order! 🎉</div>
                
                <div class="order-info">
                  <div class="order-info-row">
                    <span class="order-info-label">Customer Name:</span>
                    <span class="order-info-value">${user.name}</span>
                  </div>
                  <div class="order-info-row">
                    <span class="order-info-label">Order ID:</span>
                    <span class="order-info-value">${orderId}</span>
                  </div>
                  <div class="order-info-row">
                    <span class="order-info-label">Order Date & Time:</span>
                    <span class="order-info-value">${orderDate}</span>
                  </div>
                  <div class="order-info-row">
                    <span class="order-info-label">Status:</span>
                    <span class="order-info-value" style="color: #28a745;">✅ Confirmed</span>
                  </div>
                </div>

                <h3 style="color: #333; margin-top: 30px;">Order Details:</h3>
                <table>
                  <thead>
                    <tr>
                      <th style="width: 40px;">#</th>
                      <th>Item</th>
                      <th style="text-align: center; width: 80px;">Qty</th>
                      <th style="text-align: right; width: 100px;">Price</th>
                      <th style="text-align: right; width: 100px;">Total</th>
                    </tr>
                  </thead>
                  <tbody>
                    ${itemsHtml}
                    <tr class="total-row">
                      <td colspan="4" style="text-align: right;">Grand Total:</td>
                      <td style="text-align: right; color: #667eea;">₹${total}</td>
                    </tr>
                  </tbody>
                </table>

                <div style="background: #fff3cd; border-left: 4px solid #ffc107; padding: 15px; margin: 25px 0; border-radius: 4px;">
                  <p style="margin: 0; color: #856404; font-size: 14px;">
                    ⏱️ <strong>Estimated Preparation Time:</strong> 15-20 minutes
                  </p>
                </div>

                <div style="text-align: center; margin: 30px 0;">
                  <p style="color: #666; font-size: 15px; line-height: 1.6;">
                    Your delicious food is being prepared with care! 👨‍🍳<br>
                    Please collect your order from the counter.
                  </p>
                </div>
              </div>

              <div class="footer">
                <div class="emoji-row">🍕 🍔 🍰 ☕</div>
                <p style="margin: 5px 0; font-size: 16px; color: #333;">Campus Canteen</p>
                <p style="margin: 5px 0; font-size: 14px;">Making Campus Life Delicious!</p>
                <p style="margin: 15px 0 0 0; font-size: 12px; color: #999;">
                  Need help? Contact us at the canteen counter
                </p>
              </div>
            </div>
          </body>
          </html>
        `
      };

      await transporter.sendMail(receiptEmail);
      console.log(`Order receipt sent to ${user.email} for order ${orderId}`);
    } catch (emailError) {
      console.error('Failed to send receipt email:', emailError);
      // Don't fail the order if email fails
    }

    res.status(201).json({ 
      message: 'Order created successfully', 
      order 
    });
  } catch (error) {
    console.error('Order error:', error);
    res.status(500).json({ message: 'Server error' });
  }
});

// Get user orders
app.get('/api/orders', authMiddleware, async (req, res) => {
  try {
    const orders = await Order.find({ userId: req.userId })
      .sort({ createdAt: -1 });
    res.json(orders);
  } catch (error) {
    console.error('Get orders error:', error);
    res.status(500).json({ message: 'Server error' });
  }
});

// Get user bookings
app.get('/api/bookings', authMiddleware, async (req, res) => {
  try {
    const bookings = await Booking.find({ userId: req.userId })
      .sort({ createdAt: -1 });
    res.json(bookings);
  } catch (error) {
    console.error('Get bookings error:', error);
    res.status(500).json({ message: 'Server error' });
  }
});

// Get all orders (for owner)
app.get('/api/admin/orders', authMiddleware, async (req, res) => {
  try {
    if (req.userType !== 'owner') {
      return res.status(403).json({ message: 'Access denied' });
    }

    const orders = await Order.find()
      .sort({ createdAt: -1 });
    res.json(orders);
  } catch (error) {
    console.error('Admin orders error:', error);
    res.status(500).json({ message: 'Server error' });
  }
});

// Get all bookings (for owner)
app.get('/api/admin/bookings', authMiddleware, async (req, res) => {
  try {
    if (req.userType !== 'owner') {
      return res.status(403).json({ message: 'Access denied' });
    }

    const bookings = await Booking.find()
      .sort({ createdAt: -1 });
    res.json(bookings);
  } catch (error) {
    console.error('Admin bookings error:', error);
    res.status(500).json({ message: 'Server error' });
  }
});

// Get all menu items (for owner)
app.get('/api/admin/menu', authMiddleware, async (req, res) => {
  try {
    if (req.userType !== 'owner') {
      return res.status(403).json({ message: 'Access denied' });
    }

    const menuItems = await MenuItem.find();
    res.json(menuItems);
  } catch (error) {
    console.error('Admin menu error:', error);
    res.status(500).json({ message: 'Server error' });
  }
});

// Add menu item (for owner)
app.post('/api/admin/menu', authMiddleware, async (req, res) => {
  try {
    if (req.userType !== 'owner') {
      return res.status(403).json({ message: 'Access denied' });
    }

    const { name, price, category, description, emoji, imageUrl } = req.body;

    const menuItem = new MenuItem({
      name,
      price,
      category,
      description,
      emoji: emoji || '🍽️',
      imageUrl: imageUrl || ''
    });

    await menuItem.save();

    res.status(201).json({ 
      message: 'Menu item added successfully', 
      menuItem 
    });
  } catch (error) {
    console.error('Add menu item error:', error);
    res.status(500).json({ message: 'Server error' });
  }
});

// Update menu item (for owner)
app.put('/api/admin/menu/:id', authMiddleware, async (req, res) => {
  try {
    if (req.userType !== 'owner') {
      return res.status(403).json({ message: 'Access denied' });
    }

    const { available, popular, price } = req.body;
    
    const updateData = {};
    if (available !== undefined) updateData.available = available;
    if (popular !== undefined) updateData.popular = popular;
    if (price !== undefined) updateData.price = price;
    
    const menuItem = await MenuItem.findByIdAndUpdate(
      req.params.id,
      updateData,
      { new: true }
    );

    if (!menuItem) {
      return res.status(404).json({ message: 'Menu item not found' });
    }

    res.json({ 
      message: 'Menu item updated successfully', 
      menuItem 
    });
  } catch (error) {
    console.error('Update menu item error:', error);
    res.status(500).json({ message: 'Server error' });
  }
});

// Delete menu item (for owner)
app.delete('/api/admin/menu/:id', authMiddleware, async (req, res) => {
  try {
    if (req.userType !== 'owner') {
      return res.status(403).json({ message: 'Access denied' });
    }

    const menuItem = await MenuItem.findByIdAndDelete(req.params.id);

    if (!menuItem) {
      return res.status(404).json({ message: 'Menu item not found' });
    }

    res.json({ 
      success: true,
      message: 'Menu item deleted successfully' 
    });
  } catch (error) {
    console.error('Delete menu item error:', error);
    res.status(500).json({ message: 'Server error' });
  }
});

// Create notice (for owner)
app.post('/api/admin/notices', authMiddleware, async (req, res) => {
  try {
    if (req.userType !== 'owner') {
      return res.status(403).json({ message: 'Access denied' });
    }

    const { title, message, type, urgent } = req.body;

    const notice = new Notice({
      title,
      message,
      type,
      urgent: urgent || false
    });

    await notice.save();

    res.status(201).json({ 
      message: 'Notice created successfully', 
      notice 
    });
  } catch (error) {
    console.error('Create notice error:', error);
    res.status(500).json({ message: 'Server error' });
  }
});

// Update order status (for owner)
app.patch('/api/admin/orders/:id/status', authMiddleware, async (req, res) => {
  try {
    if (req.userType !== 'owner') {
      return res.status(403).json({ message: 'Access denied' });
    }

    const { status } = req.body;

    const order = await Order.findOne({ orderId: req.params.id });
    if (!order) {
      return res.status(404).json({ message: 'Order not found' });
    }

    order.status = status;
    await order.save();

    res.json({ 
      message: 'Order status updated successfully', 
      order 
    });
  } catch (error) {
    console.error('Update order status error:', error);
    res.status(500).json({ message: 'Server error' });
  }
});

// Update time slot capacity (for owner)
app.put('/api/admin/time-slots/capacity', authMiddleware, async (req, res) => {
  try {
    if (req.userType !== 'owner') {
      return res.status(403).json({ message: 'Access denied' });
    }

    const { capacity } = req.body;

    await TimeSlot.updateMany({}, { total: capacity });
    
    res.json({ message: 'Capacity updated successfully' });
  } catch (error) {
    console.error('Update capacity error:', error);
    res.status(500).json({ message: 'Server error' });
  }
});

// Get dashboard stats (for owner)
app.get('/api/admin/dashboard', authMiddleware, async (req, res) => {
  try {
    if (req.userType !== 'owner') {
      return res.status(403).json({ message: 'Access denied' });
    }

    // Today's date
    const today = new Date();
    today.setHours(0, 0, 0, 0);
    const tomorrow = new Date(today);
    tomorrow.setDate(tomorrow.getDate() + 1);

    // Total revenue (all time)
    const allOrders = await Order.find();
    const totalRevenue = allOrders.reduce((sum, order) => sum + order.total, 0);

    // Today's revenue
    const todayOrders = await Order.find({
      createdAt: { $gte: today, $lt: tomorrow }
    });
    const todayRevenue = todayOrders.reduce((sum, order) => sum + order.total, 0);

    // Today's orders count
    const todayOrdersCount = todayOrders.length;

    // Today's bookings count
    const todayBookings = await Booking.find({
      createdAt: { $gte: today, $lt: tomorrow }
    });
    const todayBookingsCount = todayBookings.length;

    // Active notices count
    const activeNoticesCount = await Notice.countDocuments();

    // Popular items with revenue calculation
    const popularItems = await MenuItem.find({ popular: true });
    
    // Calculate revenue for each popular item (last 7 days)
    const last7DaysDate = new Date();
    last7DaysDate.setDate(last7DaysDate.getDate() - 7);
    
    const popularItemsWithRevenue = await Promise.all(popularItems.map(async (item) => {
      // Find all orders containing this item in last 7 days
      const orders = await Order.find({
        createdAt: { $gte: last7DaysDate },
        'items.name': item.name
      });
      
      // Calculate total revenue for this item
      let itemRevenue = 0;
      orders.forEach(order => {
        order.items.forEach(orderItem => {
          if (orderItem.name === item.name) {
            itemRevenue += orderItem.price * orderItem.quantity;
          }
        });
      });
      
      return {
        _id: item._id,
        name: item.name,
        price: item.price,
        imageUrl: item.imageUrl,
        emoji: item.emoji,
        popular: item.popular,
        available: item.available,
        weeklyRevenue: itemRevenue
      };
    }));

    // Pending complaints
    const pendingComplaints = await Complaint.countDocuments({ status: 'pending' });

    res.json({
      totalRevenue,
      todayRevenue,
      todayOrders: todayOrdersCount,
      todayBookings: todayBookingsCount,
      activeNotices: activeNoticesCount,
      popularItems: popularItemsWithRevenue,
      pendingComplaints
    });
  } catch (error) {
    console.error('Dashboard error:', error);
    res.status(500).json({ message: 'Server error' });
  }
});

// Cancel booking (for student)
app.patch('/api/bookings/:id/cancel', authMiddleware, async (req, res) => {
  try {
    const booking = await Booking.findOne({ bookingId: req.params.id, userId: req.userId });
    
    if (!booking) {
      return res.status(404).json({ message: 'Booking not found' });
    }

    if (booking.status !== 'confirmed') {
      return res.status(400).json({ message: 'Booking already cancelled or completed' });
    }

    // Check if within 10 minutes
    const bookingTime = new Date(booking.createdAt);
    const currentTime = new Date();
    const timeDiff = (currentTime - bookingTime) / 1000 / 60; // in minutes

    let fine = 0;
    if (timeDiff > 10) {
      fine = 100; // Rs 100 fine
    }

    booking.status = 'cancelled';
    booking.fine = fine;
    await booking.save();

    // Update time slot
    const timeSlot = await TimeSlot.findOne({ label: booking.timeSlot });
    if (timeSlot && timeSlot.booked > 0) {
      timeSlot.booked -= 1;
      await timeSlot.save();
    }

    res.json({ 
      message: fine > 0 ? `Booking cancelled with Rs ${fine} fine` : 'Booking cancelled successfully',
      booking,
      fine
    });
  } catch (error) {
    console.error('Cancel booking error:', error);
    res.status(500).json({ message: 'Server error' });
  }
});

// Mark booking as completed (when student finishes eating)
app.patch('/api/bookings/:id/complete', authMiddleware, async (req, res) => {
  try {
    const booking = await Booking.findOne({ bookingId: req.params.id, userId: req.userId });
    
    if (!booking) {
      return res.status(404).json({ message: 'Booking not found' });
    }

    if (booking.status !== 'confirmed') {
      return res.status(400).json({ message: 'Booking not active' });
    }

    booking.status = 'completed';
    await booking.save();

    res.json({ 
      message: 'Thank you! Your seat is now available',
      booking
    });
  } catch (error) {
    console.error('Complete booking error:', error);
    res.status(500).json({ message: 'Server error' });
  }
});

// Create complaint (for student)
app.post('/api/complaints', authMiddleware, async (req, res) => {
  try {
    const { subject, description } = req.body;

    if (!subject || !description) {
      return res.status(400).json({ message: 'Subject and description are required' });
    }

    const user = await User.findById(req.userId);
    if (!user) {
      return res.status(404).json({ message: 'User not found' });
    }

    const complaintId = 'COMP' + Date.now().toString().slice(-6);

    const complaint = new Complaint({
      complaintId,
      userId: req.userId,
      studentName: user.name,
      subject,
      description
    });

    await complaint.save();

    res.status(201).json({ 
      message: 'Complaint submitted successfully', 
      complaint 
    });
  } catch (error) {
    console.error('Create complaint error:', error);
    res.status(500).json({ message: 'Server error' });
  }
});

// Get student complaints
app.get('/api/complaints', authMiddleware, async (req, res) => {
  try {
    const complaints = await Complaint.find({ userId: req.userId })
      .sort({ createdAt: -1 });
    res.json(complaints);
  } catch (error) {
    console.error('Get complaints error:', error);
    res.status(500).json({ message: 'Server error' });
  }
});

// Get all complaints (for owner)
app.get('/api/admin/complaints', authMiddleware, async (req, res) => {
  try {
    if (req.userType !== 'owner') {
      return res.status(403).json({ message: 'Access denied' });
    }

    const complaints = await Complaint.find()
      .sort({ createdAt: -1 });
    res.json(complaints);
  } catch (error) {
    console.error('Admin complaints error:', error);
    res.status(500).json({ message: 'Server error' });
  }
});

// Update complaint status (for owner)
app.patch('/api/admin/complaints/:id/status', authMiddleware, async (req, res) => {
  try {
    if (req.userType !== 'owner') {
      return res.status(403).json({ message: 'Access denied' });
    }

    const { status, response } = req.body;

    const complaint = await Complaint.findOne({ complaintId: req.params.id });
    if (!complaint) {
      return res.status(404).json({ message: 'Complaint not found' });
    }

    complaint.status = status;
    if (response) complaint.response = response;
    if (status === 'resolved') complaint.resolvedAt = new Date();

    await complaint.save();

    res.json({ 
      message: 'Complaint updated successfully', 
      complaint 
    });
  } catch (error) {
    console.error('Update complaint error:', error);
    res.status(500).json({ message: 'Server error' });
  }
});

// Get revenue analytics
app.get('/api/admin/revenue-analytics', authMiddleware, async (req, res) => {
  try {
    if (req.userType !== 'owner') {
      return res.status(403).json({ message: 'Access denied' });
    }

    // Last 7 days revenue
    const last7Days = [];
    for (let i = 6; i >= 0; i--) {
      const date = new Date();
      date.setDate(date.getDate() - i);
      date.setHours(0, 0, 0, 0);
      const nextDate = new Date(date);
      nextDate.setDate(nextDate.getDate() + 1);

      const orders = await Order.find({
        createdAt: { $gte: date, $lt: nextDate }
      });
      const revenue = orders.reduce((sum, order) => sum + order.total, 0);

      last7Days.push({
        date: date.toLocaleDateString('en-US', { month: 'short', day: 'numeric' }),
        revenue: revenue
      });
    }

    res.json({ last7Days });
  } catch (error) {
    console.error('Revenue analytics error:', error);
    res.status(500).json({ message: 'Server error' });
  }
});

// ADVANCED ANALYTICS - MongoDB Aggregation Pipeline (MapReduce Alternative)
app.get('/api/admin/advanced-analytics', authMiddleware, async (req, res) => {
  try {
    if (req.userType !== 'owner') {
      return res.status(403).json({ message: 'Access denied' });
    }

    // 1. Category-wise Revenue using Aggregation (MapReduce concept)
    const categoryRevenue = await Order.aggregate([
      { $unwind: '$items' },
      {
        $lookup: {
          from: 'menuitems',
          localField: 'items.name',
          foreignField: 'name',
          as: 'itemDetails'
        }
      },
      { $unwind: { path: '$itemDetails', preserveNullAndEmptyArrays: true } },
      {
        $group: {
          _id: '$itemDetails.category',
          totalRevenue: { 
            $sum: { $multiply: ['$items.price', '$items.quantity'] } 
          },
          totalOrders: { $sum: 1 },
          avgOrderValue: { 
            $avg: { $multiply: ['$items.price', '$items.quantity'] } 
          }
        }
      },
      { $sort: { totalRevenue: -1 } }
    ]);

    // 2. Top selling items using Aggregation
    const topSellingItems = await Order.aggregate([
      { $unwind: '$items' },
      {
        $group: {
          _id: '$items.name',
          totalQuantity: { $sum: '$items.quantity' },
          totalRevenue: { 
            $sum: { $multiply: ['$items.price', '$items.quantity'] } 
          },
          avgPrice: { $avg: '$items.price' },
          orderCount: { $sum: 1 }
        }
      },
      { $sort: { totalQuantity: -1 } },
      { $limit: 10 }
    ]);

    // 3. Hourly sales pattern
    const hourlySales = await Order.aggregate([
      {
        $group: {
          _id: { $hour: '$createdAt' },
          orderCount: { $sum: 1 },
          totalRevenue: { $sum: '$total' },
          avgOrderValue: { $avg: '$total' }
        }
      },
      { $sort: { _id: 1 } }
    ]);

    // 4. Customer spending analysis with user details
    const customerAnalysis = await Order.aggregate([
      {
        $group: {
          _id: '$userId',
          totalSpent: { $sum: '$total' },
          orderCount: { $sum: 1 },
          avgOrderValue: { $avg: '$total' },
          lastOrder: { $max: '$createdAt' }
        }
      },
      { $sort: { totalSpent: -1 } },
      { $limit: 10 }
    ]);

    // Populate customer names
    const customersWithNames = await Promise.all(
      customerAnalysis.map(async (customer) => {
        const user = await User.findById(customer._id).select('name email studentId');
        return {
          ...customer,
          userName: user ? user.name : 'Unknown User',
          userEmail: user ? user.email : '',
          studentId: user ? user.studentId : ''
        };
      })
    );

    // 5. Revenue by day of week
    const dayWiseRevenue = await Order.aggregate([
      {
        $group: {
          _id: { $dayOfWeek: '$createdAt' },
          totalRevenue: { $sum: '$total' },
          orderCount: { $sum: 1 }
        }
      },
      { $sort: { _id: 1 } }
    ]);

    // 6. Peak hours analysis
    const peakHours = await Booking.aggregate([
      {
        $group: {
          _id: '$slot',
          bookingCount: { $sum: 1 }
        }
      },
      { $sort: { bookingCount: -1 } }
    ]);

    res.json({
      categoryRevenue,
      topSellingItems,
      hourlySales,
      customerAnalysis: customersWithNames,
      dayWiseRevenue,
      peakHours
    });
  } catch (error) {
    console.error('Advanced analytics error:', error);
    res.status(500).json({ message: 'Server error' });
  }
});

// Real-time Inventory Alert System
app.get('/api/admin/inventory-alerts', authMiddleware, async (req, res) => {
  try {
    if (req.userType !== 'owner') {
      return res.status(403).json({ message: 'Access denied' });
    }

    // Calculate item consumption rate (last 7 days)
    const sevenDaysAgo = new Date();
    sevenDaysAgo.setDate(sevenDaysAgo.getDate() - 7);

    const itemConsumption = await Order.aggregate([
      { $match: { createdAt: { $gte: sevenDaysAgo } } },
      { $unwind: '$items' },
      {
        $group: {
          _id: '$items.name',
          totalQuantity: { $sum: '$items.quantity' },
          avgDailyConsumption: { $avg: '$items.quantity' }
        }
      },
      { $sort: { totalQuantity: -1 } }
    ]);

    res.json({ itemConsumption });
  } catch (error) {
    console.error('Inventory alerts error:', error);
    res.status(500).json({ message: 'Server error' });
  }
});

// Performance Metrics Dashboard
app.get('/api/admin/performance-metrics', authMiddleware, async (req, res) => {
  try {
    if (req.userType !== 'owner') {
      return res.status(403).json({ message: 'Access denied' });
    }

    const today = new Date();
    today.setHours(0, 0, 0, 0);

    // Order fulfillment rate
    const orderStats = await Order.aggregate([
      {
        $group: {
          _id: '$status',
          count: { $sum: 1 }
        }
      }
    ]);

    // Average preparation time simulation
    const avgPrepTime = await Order.aggregate([
      { $match: { status: 'completed' } },
      {
        $project: {
          prepTime: {
            $divide: [
              { $subtract: ['$updatedAt', '$createdAt'] },
              60000 // Convert to minutes
            ]
          }
        }
      },
      {
        $group: {
          _id: null,
          avgTime: { $avg: '$prepTime' }
        }
      }
    ]);

    // Customer retention rate
    const retentionStats = await Order.aggregate([
      {
        $group: {
          _id: '$userId',
          orderCount: { $sum: 1 },
          firstOrder: { $min: '$createdAt' },
          lastOrder: { $max: '$createdAt' }
        }
      },
      {
        $project: {
          isReturning: { $gt: ['$orderCount', 1] }
        }
      },
      {
        $group: {
          _id: '$isReturning',
          count: { $sum: 1 }
        }
      }
    ]);

    res.json({
      orderStats,
      avgPrepTime: avgPrepTime[0] || { avgTime: 0 },
      retentionStats
    });
  } catch (error) {
    console.error('Performance metrics error:', error);
    res.status(500).json({ message: 'Server error' });
  }
});

// Initialize data and start server
const PORT = process.env.PORT || 5000;

// Automatic booking cleanup - runs every 5 minutes
async function cleanupExpiredBookings() {
  try {
    const now = new Date();
    
    // Find all confirmed bookings that have expired
    const expiredBookings = await Booking.find({
      status: 'confirmed',
      expiresAt: { $lt: now }
    });

    if (expiredBookings.length > 0) {
      console.log(`Found ${expiredBookings.length} expired bookings, releasing seats...`);
      
      for (const booking of expiredBookings) {
        // Update booking status to expired
        booking.status = 'expired';
        await booking.save();
        
        // Find the time slot and decrease booked count
        const slot = await TimeSlot.findOne({ label: booking.timeSlot });
        if (slot && slot.booked > 0) {
          slot.booked -= 1;
          await slot.save();
          console.log(`Released seat ${booking.seatNumber} for ${booking.timeSlot}`);
        }
      }
    }
  } catch (error) {
    console.error('Cleanup error:', error);
  }
}

// Run cleanup every 5 minutes
setInterval(cleanupExpiredBookings, 5 * 60 * 1000);

mongoose.connection.once('open', async () => {
  console.log('Connected to MongoDB');
  await initializeData();
  
  // Run initial cleanup on startup
  await cleanupExpiredBookings();
  console.log('Automatic seat cleanup enabled (runs every 5 minutes)');
  
  app.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
    console.log(`API URL: http://localhost:${PORT}`);
  });
});

mongoose.connection.on('error', (err) => {
  console.error('MongoDB connection error:', err);
});