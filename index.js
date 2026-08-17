require('dotenv').config();
const express = require('express');
const cors = require('cors');
const nodemailer = require('nodemailer');
const admin = require('firebase-admin');
const { getFirestore } = require('firebase-admin/firestore');
const fs = require('fs');
const path = require('path');

// On Render/Vercel, use the FIREBASE_SERVICE_ACCOUNT environment variable.
// On local machine, fall back to the local serviceAccountKey.json file.
let serviceAccount;
if (process.env.FIREBASE_SERVICE_ACCOUNT) {
  serviceAccount = JSON.parse(process.env.FIREBASE_SERVICE_ACCOUNT);
} else {
  const keyPath = path.join(__dirname, 'serviceAccountKey.json');
  serviceAccount = JSON.parse(fs.readFileSync(keyPath, 'utf8'));
}

const app = express();

// Initialize Firebase Admin SDK
admin.initializeApp({
  credential: admin.credential.cert(serviceAccount),
});

const db = getFirestore();

app.use(cors());
app.use(express.json());

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

  const otp = Math.floor(1000 + Math.random() * 9000).toString();
  const expiresAt = Date.now() + 5 * 60 * 1000;

  await db.collection('password_reset_otps').doc(email).set({
    otp,
    expiresAt,
    verified: false,
  });

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
app.post('/verify-otp', async (req, res) => {
  const { email, otp } = req.body;

  if (!email || !otp) {
    return res.status(400).json({ success: false, message: 'Email and OTP are required' });
  }

  const docRef = db.collection('password_reset_otps').doc(email);
  const docSnap = await docRef.get();

  if (!docSnap.exists) {
    return res.status(400).json({ success: false, message: 'No OTP found for this email. Please request a new one.' });
  }

  const record = docSnap.data();

  if (Date.now() > record.expiresAt) {
    await docRef.delete();
    return res.status(400).json({ success: false, message: 'OTP has expired. Please request a new one.' });
  }

  if (record.otp !== otp) {
    return res.status(400).json({ success: false, message: 'Invalid OTP' });
  }

  await docRef.update({ verified: true });

  return res.status(200).json({ success: true, message: 'OTP verified successfully' });
});

// Route: Reset password using Firebase Admin SDK
app.post('/reset-password', async (req, res) => {
  const { email, newPassword } = req.body;

  if (!email || !newPassword) {
    return res.status(400).json({ success: false, message: 'Email and new password are required' });
  }

  const docRef = db.collection('password_reset_otps').doc(email);
  const docSnap = await docRef.get();

  if (!docSnap.exists || !docSnap.data().verified) {
    return res.status(400).json({ success: false, message: 'OTP not verified for this email. Please verify OTP first.' });
  }

  try {
    const user = await admin.auth().getUserByEmail(email);

    await admin.auth().updateUser(user.uid, {
      password: newPassword,
    });

    await docRef.delete();

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