const transporter = require("../config/emailtransporter")
const otpVerifyModel = require('../module/auth/model/otpverify')

const userOTPverify = async (req, user) => {
  // Generate a random 4-digit number
  const otp = Math.floor(1000 + Math.random() * 9000);

  // Save OTP in Database
  const gg = await new otpVerifyModel({ userId: user._id, otp: otp }).save();
  console.log('hh', gg);

  //  OTP Verification Link for admin
  // ADMIN_VERIFYEMAIL = http://localhost:3004/verifyuser
  const otpVerificationLink = "Put frontend link here";

  await transporter.sendMail({
    from: process.env.EMAIL_FROM,
    to: user.email,
    subject: "OTP - Verify your account",
    html: `<p>Dear ${user.name},</p><p>Thank you for signing up with our website. To complete your registration, please verify your email address by entering the following one-time password (OTP)</p>
    <h2>OTP: ${otp}</h2>
    <p><a href="${otpVerificationLink}">Click here to verify your email</a></p>
    <p>This OTP is valid for 15 minutes. If you didn't request this OTP, please ignore this email.</p>`
  })
  return otp
}


module.exports = userOTPverify