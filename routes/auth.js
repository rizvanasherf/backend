const express = require('express');
const jwt = require('jsonwebtoken');
const User = require('../models/User');
const { protect, authLimiter, apiLimiter } = require('../middleware/authMiddleware');
const router = express.Router();

// Apply rate limiting to all auth routes
router.use(authLimiter);

// Create a JWT token function
const signToken = (id) => {
  return jwt.sign({ id }, process.env.JWT_SECRET, {
    expiresIn: process.env.JWT_EXPIRES_IN || '15m', // Shorter expiry for access tokens
  });
};

// Create refresh token function
const signRefreshToken = (id) => {
  return jwt.sign({ id }, process.env.JWT_REFRESH_SECRET, {
    expiresIn: process.env.JWT_REFRESH_EXPIRES_IN || '7d',
  });
};

// Input validation middleware
const validateSignup = (req, res, next) => {
  const { name, email, password } = req.body;
  
  if (!name || !email || !password) {
    return res.status(400).json({
      status: 'fail',
      message: 'Please provide name, email, and password'
    });
  }

  // Email validation
  const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  if (!emailRegex.test(email)) {
    return res.status(400).json({
      status: 'fail',
      message: 'Please provide a valid email address'
    });
  }

  // Name validation
  if (name.trim().length < 2 || name.trim().length > 50) {
    return res.status(400).json({
      status: 'fail',
      message: 'Name must be between 2 and 50 characters'
    });
  }

  next();
};

// Password strength validation
const validatePasswordStrength = (req, res, next) => {
  const { password } = req.body;
  
  if (!password) {
    return res.status(400).json({
      status: 'fail',
      message: 'Password is required'
    });
  }

  const passwordErrors = User.validatePassword(password);
  
  if (passwordErrors.length > 0) {
    const requirements = User.getPasswordRequirements();
    
    let message = 'Password does not meet requirements: ';
    const errorMessages = [];
    
    if (passwordErrors.includes('min')) {
      errorMessages.push(`minimum ${requirements.minLength} characters`);
    }
    if (passwordErrors.includes('uppercase')) {
      errorMessages.push('at least one uppercase letter');
    }
    if (passwordErrors.includes('lowercase')) {
      errorMessages.push('at least one lowercase letter');
    }
    if (passwordErrors.includes('digits')) {
      errorMessages.push('at least one number');
    }
    if (passwordErrors.includes('spaces')) {
      errorMessages.push('no spaces allowed');
    }
    
    message += errorMessages.join(', ');
    
    return res.status(400).json({
      status: 'fail',
      message,
      requirements: {
        minLength: requirements.minLength,
        requiresUppercase: requirements.requiresUppercase,
        requiresLowercase: requirements.requiresLowercase,
        requiresDigit: requirements.requiresDigit,
        noSpaces: requirements.noSpaces
      }
    });
  }

  next();
};

// SIGN UP ROUTE
router.post('/signup', validateSignup, validatePasswordStrength, async (req, res) => {
  try {
    const { name, email, password, ageRange, stressLevel, goals } = req.body;

    // Check if user already exists
    const existingUser = await User.findOne({ email });
    if (existingUser) {
      return res.status(409).json({
        status: 'fail',
        message: 'User already exists with this email'
      });
    }

    // Create new user
    const newUser = await User.create({
      name: name.trim(),
      email: email.toLowerCase().trim(),
      password,
      ageRange: ageRange || 'Prefer not to say',
      stressLevel: stressLevel || 'Medium',
      goals: goals || ['General Wellness']
    });

    // Generate tokens
    const accessToken = signToken(newUser._id);
    const refreshToken = signRefreshToken(newUser._id);

    // Remove password from output
    newUser.password = undefined;

    // Set refresh token as httpOnly cookie
    res.cookie('refreshToken', refreshToken, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production', // Use secure in production
      sameSite: 'strict',
      maxAge: 7 * 24 * 60 * 60 * 1000 // 7 days
    });

    res.status(201).json({
      status: 'success',
      message: 'User created successfully!',
      data: {
        user: newUser,
        accessToken,
        expiresIn: process.env.JWT_EXPIRES_IN || '15m'
      }
    });

  } catch (error) {
    console.error('Signup error:', error);
    
    // Don't expose internal error details
    res.status(500).json({
      status: 'error',
      message: 'Unable to create account. Please try again.'
    });
  }
});

// LOGIN ROUTE
router.post('/login', async (req, res) => {
  try {
    const { email, password } = req.body;

    // Check if email and password exist
    if (!email || !password) {
      return res.status(400).json({
        status: 'fail',
        message: 'Please provide email and password'
      });
    }

    // Find user and include password
    const user = await User.findOne({ email: email.toLowerCase() }).select('+password');
    
    // Always return the same message for security (don't reveal if user exists)
    if (!user || !(await user.correctPassword(password, user.password))) {
      return res.status(401).json({
        status: 'fail',
        message: 'Invalid email or password'
      });
    }

    // Generate tokens
    const accessToken = signToken(user._id);
    const refreshToken = signRefreshToken(user._id);

    // Remove password from output
    user.password = undefined;

    // Set refresh token as httpOnly cookie
    res.cookie('refreshToken', refreshToken, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'strict',
      maxAge: 7 * 24 * 60 * 60 * 1000 // 7 days
    });

    res.status(200).json({
      status: 'success',
      message: 'Logged in successfully!',
      data: {
        user,
        accessToken,
        expiresIn: process.env.JWT_EXPIRES_IN || '15m'
      }
    });

  } catch (error) {
    console.error('Login error:', error);
    
    res.status(500).json({
      status: 'error',
      message: 'Unable to login. Please try again.'
    });
  }
});

// REFRESH TOKEN ROUTE
router.post('/refresh-token', async (req, res) => {
  try {
    const refreshToken = req.cookies.refreshToken;
    
    if (!refreshToken) {
      return res.status(401).json({
        status: 'fail',
        message: 'Refresh token required'
      });
    }

    // Verify refresh token
    const decoded = jwt.verify(refreshToken, process.env.JWT_REFRESH_SECRET);
    
    // Check if user still exists
    const user = await User.findById(decoded.id);
    if (!user) {
      return res.status(401).json({
        status: 'fail',
        message: 'User no longer exists'
      });
    }

    // Generate new access token
    const newAccessToken = signToken(user._id);

    res.status(200).json({
      status: 'success',
      data: {
        accessToken: newAccessToken,
        expiresIn: process.env.JWT_EXPIRES_IN || '15m'
      }
    });

  } catch (error) {
    console.error('Refresh token error:', error);
    
    if (error.name === 'JsonWebTokenError') {
      return res.status(401).json({
        status: 'fail',
        message: 'Invalid refresh token'
      });
    }
    
    if (error.name === 'TokenExpiredError') {
      return res.status(401).json({
        status: 'fail',
        message: 'Refresh token expired'
      });
    }

    res.status(500).json({
      status: 'error',
      message: 'Unable to refresh token'
    });
  }
});

// LOGOUT ROUTE
router.post('/logout', (req, res) => {
  // Clear the refresh token cookie
  res.cookie('refreshToken', '', {
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production',
    sameSite: 'strict',
    maxAge: 1 // Immediately expire
  });

  res.status(200).json({
    status: 'success',
    message: 'Logged out successfully'
  });
});

// GET CURRENT USER PROFILE (Protected)
router.get('/profile', protect, async (req, res) => {
  try {
    // User is already attached to req by protect middleware
    const user = await User.findById(req.user.id);
    
    res.status(200).json({
      status: 'success',
      data: {
        user
      }
    });

  } catch (error) {
    console.error('Profile error:', error);
    
    res.status(500).json({
      status: 'error',
      message: 'Unable to fetch profile'
    });
  }
});

// UPDATE USER PROFILE (Protected)
router.patch('/profile', protect, async (req, res) => {
  try {
    const { name, ageRange, stressLevel, goals } = req.body;
    
    // Filter allowed fields
    const allowedUpdates = {};
    if (name) allowedUpdates.name = name.trim();
    if (ageRange) allowedUpdates.ageRange = ageRange;
    if (stressLevel) allowedUpdates.stressLevel = stressLevel;
    if (goals) allowedUpdates.goals = goals;

    const updatedUser = await User.findByIdAndUpdate(
      req.user.id,
      allowedUpdates,
      { new: true, runValidators: true }
    );

    res.status(200).json({
      status: 'success',
      message: 'Profile updated successfully',
      data: {
        user: updatedUser
      }
    });

  } catch (error) {
    console.error('Profile update error:', error);
    
    res.status(500).json({
      status: 'error',
      message: 'Unable to update profile'
    });
  }
});

// GET PASSWORD REQUIREMENTS (Public)
router.get('/password-requirements', (req, res) => {
  const requirements = User.getPasswordRequirements();
  
  res.status(200).json({
    status: 'success',
    data: {
      requirements
    }
  });
});

module.exports = router;