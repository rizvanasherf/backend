const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 5000;

// ✅ WORKING CORS Configuration
app.use(cors({
  origin: 'http://localhost:3000',
  credentials: true
}));

app.use(express.json());

// ✅ MongoDB Connection
const connectDB = async () => {
  try {
    console.log('🔗 Connecting to MongoDB...');
    await mongoose.connect(process.env.MONGO_URI);
    console.log('✅ MongoDB Connected Successfully!');
  } catch (error) {
    console.error('❌ Database Connection Failed:', error.message);
  }
};

connectDB();

// ✅ Routes (keep your existing routes)
app.get('/', (req, res) => {
  res.json({ 
    message: '🚀 Wellness App Server is Running!',
    timestamp: new Date().toISOString()
  });
});

app.get('/health', (req, res) => {
  res.json({
    status: 'Server is running 🟢',
    database: mongoose.connection.readyState === 1 ? 'connected ✅' : 'disconnected ❌'
  });
});

app.get('/api/auth/test', (req, res) => {
  res.json({ 
    message: '✅ Auth routes are working!',
    timestamp: new Date().toISOString()
  });
});

app.post('/api/auth/signup', (req, res) => {
  console.log('📝 Signup request received:', req.body);

  const { name, email, password } = req.body;

  if (!name || !email || !password) {
    return res.status(400).json({
      status: 'fail',
      message: 'Please provide name, email, and password'
    });
  }

  return res.status(201).json({
    status: 'success',
    message: 'User created successfully!',
    data: {
      user: {
        name,
        email,
        id: 'user-' + Date.now()
      },
      accessToken: 'token-' + Date.now()
    }
  });
});

app.post('/api/auth/login', (req, res) => {
  console.log('🔐 Login request received:', req.body);

  const { email, password } = req.body;

  if (!email || !password) {
    return res.status(400).json({
      status: 'fail',
      message: 'Please provide email and password'
    });
  }

  return res.status(200).json({
    status: 'success',
    message: 'Logged in successfully!',
    data: {
      user: {
        name: 'Test User',
        email,
        id: 'test-user-123'
      },
      accessToken: 'token-' + Date.now()
    }
  });
});

// ✅ Start Server
app.listen(PORT, () => {
  console.log('\n✨ ====================================');
  console.log(`🚀 Server running on port ${PORT}`);
  console.log(`🌐 http://localhost:${PORT}`);
  console.log(`🔗 http://localhost:${PORT}/api/auth/test`);
  console.log('====================================\n');
});