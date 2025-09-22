import nodemailer from "nodemailer";
import logger from "../config/logger.js";

const transporter = nodemailer.createTransport({
  service: "gmail",
  auth: {
    user: process.env.NODEMAILER_USER,
    pass: process.env.NODEMAILER_PASS,
  },
  port: 587,
  secure: false,
  host: "smtp.gmail.com",
});

export const sendResetEmail = async (email, token) => {
  const resetUrl = `${process.env.BASE_URL}/reset-password?token=${token}`;
  const mailOptions = {
    from: process.env.NODEMAILER_USER,
    to: email,
    subject: "Password Reset",
    text: `Click to reset: ${resetUrl}`,
  };
  try {
    logger.info(`Sending reset email to ${email} with URL: ${resetUrl}`);
    await transporter.sendMail(mailOptions);
    logger.info(`Email sent successfully to ${email}`);
  } catch (err) {
    logger.error("Email Send Error:", {
      message: err.message,
      stack: err.stack,
      email,
      resetUrl,
    });
    throw new Error(`Email sending failed: ${err.message}`);
  }
};
