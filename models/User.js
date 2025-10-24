const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');

// Define the user schema (structure of user data)
const userSchema = new mongoose.Schema({
  name: {
    type: String,
    required: [true, 'Please provide a name'],
    maxlength: 50
  },
  email: {
    type: String,
    required: [true, 'Please provide an email'],
    unique: true,
    lowercase: true,
    match: [
      /^\w+([.-]?\w+)*@\w+([.-]?\w+)*(\.\w{2,3})+$/,
      'Please provide a valid email'
    ]
  },
  password: {
    type: String,
    required: [true, 'Please provide a password'],
    minlength: 6
  },
  ageRange: {
    type: String,
    enum: ['Under 18', '18-25', '26-35', '36-45', '46-55', '56+', 'Prefer not to say'],
    default: 'Prefer not to say'
  },
  stressLevel: {
    type: String,
    enum: ['Very Low', 'Low', 'Medium', 'High', 'Very High'],
    default: 'Medium'
  },
  goals: {
    type: [String], // Array of strings
    enum: ['Reduce Stress', 'Improve Sleep', 'Increase Focus', 'Manage Anxiety', 'Build Habits', 'General Wellness'],
    default: ['General Wellness']
  },
  profileCompleted: {
    type: Boolean,
    default: false
  }
}, {
  timestamps: true // This adds createdAt and updatedAt fields automatically
});

// Hash password before saving user
userSchema.pre('save', async function(next) {
  // Only hash the password if it's modified (or new)
  if (!this.isModified('password')) {
    return next();
  }
  
  // Hash the password with cost of 12
  this.password = await bcrypt.hash(this.password, 12);
  next();
});

// Method to check if password is correct
userSchema.methods.correctPassword = async function(candidatePassword, userPassword) {
  return await bcrypt.compare(candidatePassword, userPassword);
};

// Create the User model
const User = mongoose.model('User', userSchema);

module.exports = User;
const passwordValidator = require('password-validator');

// Create a password schema
const passwordSchema = new passwordValidator();

// Add password requirements
passwordSchema
  .is().min(8)                                    // Minimum length 8
  .is().max(100)                                  // Maximum length 100
  .has().uppercase()                              // Must have uppercase letters
  .has().lowercase()                              // Must have lowercase letters
  .has().digits(1)                                // Must have at least 1 digit
  .has().not().spaces()                           // Should not have spaces
  .is().not().oneOf(['Passw0rd', 'Password123']); // Blacklist these values

// Add this method to your userSchema
userSchema.statics.validatePassword = (password) => {
  return passwordSchema.validate(password, { list: true });
};

// Add this method to get password requirements
userSchema.statics.getPasswordRequirements = () => {
  return {
    minLength: 8,
    requiresUppercase: true,
    requiresLowercase: true,
    requiresDigit: true,
    noSpaces: true
  };
};