const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');

const userSchema = new mongoose.Schema(
  {
    // ─── Personal Info ───────────────────────────────────────────
    firstName: {
      type: String,
      required: [true, 'First name is required'],
      trim: true,
      minlength: [2, 'First name must be at least 2 characters'],
      maxlength: [50, 'First name cannot exceed 50 characters'],
    },
    lastName: {
      type: String,
      required: [true, 'Last name is required'],
      trim: true,
      minlength: [2, 'Last name must be at least 2 characters'],
      maxlength: [50, 'Last name cannot exceed 50 characters'],
    },
    email: {
      type: String,
      required: [true, 'Email address is required'],
      unique: true,
      lowercase: true,
      trim: true,
      match: [/^\S+@\S+\.\S+$/, 'Please provide a valid email address'],
    },

    // ─── Authentication ──────────────────────────────────────────
    password: {
      type: String,
      required: [true, 'Password is required'],
      minlength: [8, 'Password must be at least 8 characters'],
      select: false, // Never return password in queries
    },

    // ─── Email Verification ──────────────────────────────────────
    isEmailVerified: {
      type: Boolean,
      default: false,
    },
    emailVerificationOTP: {
      type: String,
      select: false,
    },
    emailVerificationOTPExpires: {
      type: Date,
      select: false,
    },
    emailVerificationAttempts: {
      type: Number,
      default: 0,
      select: false,
    },

    // ─── Account Status ──────────────────────────────────────────
    role: {
      type: String,
      enum: ['user', 'admin', 'moderator'],
      default: 'user',
    },
    isActive: {
      type: Boolean,
      default: true,
    },
    isBanned: {
      type: Boolean,
      default: false,
    },

    // ─── Session Tracking ────────────────────────────────────────
    lastLoginAt: {
      type: Date,
    },
    lastLoginIP: {
      type: String,
    },
    loginCount: {
      type: Number,
      default: 0,
    },

    // ─── Refresh Token ───────────────────────────────────────────
    refreshTokens: {
      type: [String],
      select: false,
      default: [],
    },
  },
  {
    timestamps: true, // adds createdAt and updatedAt
    toJSON: { virtuals: true },
    toObject: { virtuals: true },
  }
);

// ─── Virtual: Full Name ────────────────────────────────────────────────────
userSchema.virtual('fullName').get(function () {
  return `${this.firstName} ${this.lastName}`;
});

// ─── Index ─────────────────────────────────────────────────────────────────
userSchema.index({ email: 1 });
userSchema.index({ createdAt: -1 });

// ─── Pre-save Hook: Hash Password ──────────────────────────────────────────
userSchema.pre('save', async function (next) {
  // Only hash password if it was modified
  if (!this.isModified('password')) return next();

  const saltRounds = 12;
  this.password = await bcrypt.hash(this.password, saltRounds);
  next();
});

// ─── Instance Method: Compare Password ────────────────────────────────────
userSchema.methods.comparePassword = async function (candidatePassword) {
  return bcrypt.compare(candidatePassword, this.password);
};

// ─── Instance Method: Safe User Object (no sensitive fields) ──────────────
userSchema.methods.toSafeObject = function () {
  return {
    id: this._id,
    firstName: this.firstName,
    lastName: this.lastName,
    fullName: this.fullName,
    email: this.email,
    role: this.role,
    isEmailVerified: this.isEmailVerified,
    isActive: this.isActive,
    lastLoginAt: this.lastLoginAt,
    loginCount: this.loginCount,
    createdAt: this.createdAt,
    updatedAt: this.updatedAt,
  };
};

// ─── Static Method: Find by Email (with password) ─────────────────────────
userSchema.statics.findByEmailWithPassword = function (email) {
  return this.findOne({ email: email.toLowerCase() }).select('+password');
};

const User = mongoose.model('User', userSchema);

module.exports = User;
