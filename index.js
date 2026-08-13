require('dotenv').config();
const express = require('express');
const cors = require('cors');
const nodemailer = require('nodemailer');
const { initializeApp, cert } = require('firebase-admin/app');
const { getAuth } = require('firebase-admin/auth');
const serviceAccount = require('./serviceAccountKey.json');

const app = express();

// Initialize Firebase Admin SDK
initializeApp({
  credential: cert(serviceAccount),
});

app.use(cors());
app.use(express.json());

// Temporary in-memory storage for OTPs
// Format: { "email@example.com": { otp: "1234", expiresAt: timestamp, verified: false } }
const otpStore = {};

// Setup nodemailer transporter using Gmail
const transporter = nodemailer.createTransport({
  service: 'gmail',
  auth: {
    user: process.env.GMAIL_USER,
    pass: process.env.GMAIL_APP_PASSWORD,
  },
});

// Test route to check if server is running
app.get('/', (req, res) => {
  res.send('OLV Autos Backend is running!');
});

// Route: Send OTP to user's email
app.post('/send-otp', async (req, res) => {
  const { email } = req.body;

  if (!email) {
    return res.status(400).json({ success: false, message: 'Email is required' });
  }

  // Generate 4-digit OTP
  const otp = Math.floor(1000 + Math.random() * 9000).toString();

  // Set expiry to 5 minutes from now
  const expiresAt = Date.now() + 5 * 60 * 1000;

  // Save OTP in memory
  otpStore[email] = { otp, expiresAt, verified: false };

  // Email content
  const mailOptions = {
    from: `"OLV Autos" <${process.env.GMAIL_USER}>`,
    to: email,
    subject: 'OLV Autos - Password Reset OTP',
    text: `Your OTP for password reset is: ${otp}\n\nThis OTP will expire in 5 minutes.`,
  };

  try {
    await transporter.sendMail(mailOptions);
    console.log(`OTP sent to ${email}: ${otp}`);
    return res.status(200).json({ success: true, message: 'OTP sent successfully' });
  } catch (error) {
    console.error('Error sending email:', error);
    return res.status(500).json({ success: false, message: 'Failed to send OTP' });
  }
});

// Route: Verify OTP
app.post('/verify-otp', (req, res) => {
  const { email, otp } = req.body;

  if (!email || !otp) {
    return res.status(400).json({ success: false, message: 'Email and OTP are required' });
  }

  const record = otpStore[email];

  if (!record) {
    return res.status(400).json({ success: false, message: 'No OTP found for this email. Please request a new one.' });
  }

  if (Date.now() > record.expiresAt) {
    delete otpStore[email];
    return res.status(400).json({ success: false, message: 'OTP has expired. Please request a new one.' });
  }

  if (record.otp !== otp) {
    return res.status(400).json({ success: false, message: 'Invalid OTP' });
  }

  // Mark this email as verified so reset-password can be allowed
  otpStore[email].verified = true;

  return res.status(200).json({ success: true, message: 'OTP verified successfully' });
});

// Route: Reset password using Firebase Admin SDK
app.post('/reset-password', async (req, res) => {
  const { email, newPassword } = req.body;

  if (!email || !newPassword) {
    return res.status(400).json({ success: false, message: 'Email and new password are required' });
  }

  const record = otpStore[email];

  if (!record || !record.verified) {
    return res.status(400).json({ success: false, message: 'OTP not verified for this email. Please verify OTP first.' });
  }

  try {
    // Find the Firebase user by email
    const user = await getAuth().getUserByEmail(email);

    // Update the password
    await getAuth().updateUser(user.uid, {
      password: newPassword,
    });

    // Clear the OTP record after successful password reset
    delete otpStore[email];

    return res.status(200).json({ success: true, message: 'Password reset successfully' });
  } catch (error) {
    console.error('Error resetting password:', error);
    return res.status(500).json({ success: false, message: 'Failed to reset password' });
  }
});

const PORT = process.env.PORT || 5000;
app.listen(PORT, () => {
  console.log(`Server is running on port ${PORT}`);
});