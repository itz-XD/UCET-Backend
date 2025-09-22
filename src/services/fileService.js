import { S3Client, PutObjectCommand } from "@aws-sdk/client-s3";
import multer from "multer";
import path from "path";
import logger from "../config/logger.js";

const s3 = new S3Client({
  region: process.env.AWS_REGION,
  credentials: {
    accessKeyId: process.env.AWS_ACCESS_KEY_ID,
    secretAccessKey: process.env.AWS_SECRET_ACCESS_KEY,
  },
});

const uploadToS3 = async (file) => {
  const params = {
    Bucket: process.env.AWS_S3_BUCKET,
    Key: `${Date.now()}-${path.basename(file.originalname)}`,
    Body: file.buffer,
    ContentType: file.mimetype,
  };
  const command = new PutObjectCommand(params);
  await s3.send(command);
  return `https://${process.env.AWS_S3_BUCKET}.s3.${process.env.AWS_REGION}.amazonaws.com/${params.Key}`;
};

export const multerConfig = multer({
  fileFilter: (req, file, cb) => {
    const allowedTypes = [
      "application/pdf",
      "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
      "image/png",
      "image/jpeg",
    ];
    if (allowedTypes.includes(file.mimetype)) cb(null, true);
    else
      cb(
        new Error("Invalid file type: only PDF, DOCX, PNG, JPG allowed"),
        false
      );
  },
  storage: multer.memoryStorage(),
}).single("file");

export const handleUpload = async (file) => {
  try {
    const fileUrl = await uploadToS3(file);
    return fileUrl;
  } catch (err) {
    logger.error("S3 Upload Error:", err);
    throw new Error("File upload failed");
  }
};
