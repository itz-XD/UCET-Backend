import express, { urlencoded } from "express";
import dotenv from "dotenv";
import helmet from "helmet";
import morgan from "morgan";
import rateLimit from "express-rate-limit";
import cors from "cors";
import jwt from "jsonwebtoken";
import bcrypt from "bcrypt";
import { eq, asc, desc } from "drizzle-orm";
import { drizzle } from "drizzle-orm/node-postgres";
import { Pool } from "pg";
import { z } from "zod";
import sanitizeHtml from "sanitize-html";
import * as schemas from "./models/schema.js";
import { authenticate } from "./middlewares/auth.js";
import logger from "./config/logger.js";
import { multerConfig, handleUpload } from "./services/fileService.js";
import { sendResetEmail } from "./services/emailService.js";
import { S3Client, DeleteObjectCommand } from "@aws-sdk/client-s3";

// Load environment variables conditionally
dotenv.config({
  path: process.env.NODE_ENV === "development" ? ".env.local" : ".env",
});

dotenv.config();

const app = express();
const port = process.env.PORT || 5000;

// DB Connection
const pool = new Pool({ connectionString: process.env.DATABASE_URL });
pool.on("connect", () => logger.info("Database connected"));
pool.on("error", (err) => logger.error("Database connection error:", err));
const db = drizzle(pool, { schema: schemas });

// Middleware
app.use(helmet());
app.use(
  morgan("combined", {
    stream: { write: (msg) => logger.info(msg.trim()) },
    format: (tokens, req, res) =>
      [
        tokens.method(req, res),
        tokens.url(req, res),
        tokens.status(req, res),
        tokens.res(req, res, "content-length"),
        "-",
        tokens["response-time"](req, res),
        "ms",
        `UserID: ${req.user?.id || "N/A"}`,
        `Role: ${req.user?.role || "N/A"}`,
      ].join(" "),
  })
);
app.use(cors({ origin: process.env.BASE_URL || "http://localhost:3000" }));
app.use(express.json());
app.use(urlencoded({ extended: true }));
const authLimiter = rateLimit({ windowMs: 15 * 60 * 1000, max: 20 });
const limiter = rateLimit({ windowMs: 15 * 60 * 1000, max: 100 });
app.use("/api/v1/auth/", authLimiter);
app.use(limiter);

// HTTPS Redirect
// app.use((req, res, next) => {
//   if (req.get("X-Forwarded-Proto") !== "https" && process.env.NODE_ENV === "production") {
//     return res.redirect(301, `https://${req.get("host")}${req.url}`);
//   }
//   next();
// });

// Sanitize inputs
const sanitizeInput = (req, res, next) => {
  for (const key in req.body) {
    if (typeof req.body[key] === "string") {
      req.body[key] = sanitizeHtml(req.body[key], {
        allowedTags: [],
        allowedAttributes: {},
      });
    }
  }
  next();
};

// Error Handler
app.use((err, req, res, next) => {
  if (err instanceof z.ZodError) {
    res.status(400).json({ error: "Invalid input", details: err.errors });
  } else {
    logger.error(err.message, { stack: err.stack, userId: req.user?.id });
    res
      .status(err.status || 500)
      .json({ error: err.message || "Internal Server Error" });
  }
});

// Auth Routes (/api/v1/auth/)
const userSchema = z.object({
  name: z.string().min(1),
  email: z.string().email(),
  password: z.string().min(8),
  role: z.enum(["admin", "faculty", "student", "alumni"]).optional(),
});

app.post("/api/v1/auth/register", sanitizeInput, async (req, res, next) => {
  try {
    const data = userSchema.parse(req.body);
    const existing = await db.query.users.findFirst({
      where: eq(schemas.users.email, data.email),
    });
    if (existing) throw new Error("User exists");

    const hash = await bcrypt.hash(data.password, 12);
    const [user] = await db
      .insert(schemas.users)
      .values({
        name: data.name,
        email: data.email,
        passwordHash: hash,
        role: data.role || "student",
      })
      .returning();
    res.status(201).json({ message: "Registered", userId: user.id });
  } catch (err) {
    next(err);
  }
});

app.post("/api/v1/auth/login", sanitizeInput, async (req, res, next) => {
  try {
    const loginSchema = z.object({
      email: z.string().email(),
      password: z.string(),
    });
    const { email, password } = loginSchema.parse(req.body);

    const user = await db.query.users.findFirst({
      where: eq(schemas.users.email, email),
    });
    if (!user || !(await bcrypt.compare(password, user.passwordHash)))
      throw new Error("Invalid credentials");

    const accessToken = jwt.sign(
      { id: user.id, role: user.role },
      process.env.JWT_SECRET,
      { expiresIn: process.env.JWT_EXPIRY }
    );
    const refreshToken = jwt.sign({ id: user.id }, process.env.REFRESH_SECRET, {
      expiresIn: process.env.REFRESH_EXPIRY,
    });

    res.json({ accessToken, refreshToken });
  } catch (err) {
    next(err);
  }
});

app.post("/api/v1/auth/refresh-token", async (req, res, next) => {
  try {
    const { refreshToken } = z
      .object({ refreshToken: z.string() })
      .parse(req.body);
    if (!refreshToken) throw new Error("Refresh token required");

    const decoded = jwt.verify(refreshToken, process.env.REFRESH_SECRET);
    const user = await db.query.users.findFirst({
      where: eq(schemas.users.id, decoded.id),
    });
    if (!user) throw new Error("User not found");

    const accessToken = jwt.sign(
      { id: user.id, role: user.role },
      process.env.JWT_SECRET,
      { expiresIn: process.env.JWT_EXPIRY }
    );
    res.json({ accessToken });
  } catch (err) {
    next(err);
  }
});

app.post("/api/v1/auth/logout", (req, res) => {
  res.json({ message: "Logged out" });
});

app.post(
  "/api/v1/auth/forgot-password",
  sanitizeInput,
  async (req, res, next) => {
    try {
      const { email } = z.object({ email: z.string().email() }).parse(req.body);
      const user = await db.query.users.findFirst({
        where: eq(schemas.users.email, email),
      });
      if (!user) throw new Error("User not found");

      const resetToken = jwt.sign({ id: user.id }, process.env.JWT_SECRET, {
        expiresIn: "1h",
      });
      await sendResetEmail(email, resetToken);
      res.json({ message: "Reset link sent" });
    } catch (err) {
      next(err);
    }
  }
);

app.post(
  "/api/v1/auth/reset-password",
  sanitizeInput,
  async (req, res, next) => {
    try {
      const { token, newPassword } = z
        .object({ token: z.string(), newPassword: z.string().min(8) })
        .parse(req.body);
      const decoded = jwt.verify(token, process.env.JWT_SECRET);
      const hash = await bcrypt.hash(newPassword, 12);
      await db
        .update(schemas.users)
        .set({ passwordHash: hash })
        .where(eq(schemas.users.id, decoded.id));
      res.json({ message: "Password reset" });
    } catch (err) {
      next(err);
    }
  }
);

// Admissions Routes (/api/v1/admissions/)
const admissionSchema = z.object({
  studentName: z.string().min(1),
  branch: z.string().min(1),
  year: z.coerce.number().int().positive(),
});

app.post(
  "/api/v1/admissions/apply",
  authenticate(["student", "admin"]),
  sanitizeInput,
  async (req, res, next) => {
    try {
      const data = admissionSchema.parse(req.body);
      const [admission] = await db
        .insert(schemas.admissions)
        .values({
          ...data,
          status: "pending",
        })
        .returning();
      res.status(201).json(admission);
    } catch (err) {
      next(err);
    }
  }
);

app.get(
  "/api/v1/admissions/",
  authenticate(["admin"]),
  async (req, res, next) => {
    try {
      const applicants = await db.select().from(schemas.admissions);
      res.json(applicants);
    } catch (err) {
      next(err);
    }
  }
);

app.put(
  "/api/v1/admissions/:id",
  authenticate(["admin"]),
  sanitizeInput,
  async (req, res, next) => {
    try {
      const { id } = z
        .object({ id: z.string().transform(Number) })
        .parse(req.params);
      const data = z
        .object({
          status: z.enum(["pending", "accepted", "rejected"]).optional(),
        })
        .parse(req.body);
      const [updated] = await db
        .update(schemas.admissions)
        .set(data)
        .where(eq(schemas.admissions.id, id))
        .returning();
      if (!updated) throw new Error("Admission not found");
      res.json(updated);
    } catch (err) {
      next(err);
    }
  }
);

app.delete(
  "/api/v1/admissions/:id",
  authenticate(["admin"]),
  async (req, res, next) => {
    try {
      const { id } = z
        .object({ id: z.string().transform(Number) })
        .parse(req.params);
      const [deleted] = await db
        .delete(schemas.admissions)
        .where(eq(schemas.admissions.id, id))
        .returning();
      if (!deleted) throw new Error("Admission not found");
      res.status(204).send();
    } catch (err) {
      next(err);
    }
  }
);

// Events Routes (/api/v1/events/)
const dateSchema = z
  .string()
  .datetime()
  .transform((val) => new Date(val));
const eventSchema = z.object({
  title: z.string().min(1),
  description: z.string().optional(),
  date: dateSchema,
  location: z.string().optional(),
});

app.post(
  "/api/v1/events/",
  authenticate(["admin"]),
  sanitizeInput,
  async (req, res, next) => {
    try {
      logger.debug("Inserting event:", req.body);
      const data = eventSchema.parse(req.body);
      const [event] = await db.insert(schemas.events).values(data).returning();
      res.status(201).json(event);
    } catch (err) {
      next(err);
    }
  }
);

app.get("/api/v1/events/", async (req, res, next) => {
  try {
    const events = await db
      .select()
      .from(schemas.events)
      .orderBy(asc(schemas.events.date));
    res.json(events);
  } catch (err) {
    next(err);
  }
});

app.put(
  "/api/v1/events/:id",
  authenticate(["admin"]),
  sanitizeInput,
  async (req, res, next) => {
    try {
      const { id } = z
        .object({ id: z.string().transform(Number) })
        .parse(req.params);
      const data = eventSchema.partial().parse(req.body);
      const [updated] = await db
        .update(schemas.events)
        .set(data)
        .where(eq(schemas.events.id, id))
        .returning();
      if (!updated) throw new Error("Event not found");
      res.json(updated);
    } catch (err) {
      next(err);
    }
  }
);

app.delete(
  "/api/v1/events/:id",
  authenticate(["admin"]),
  async (req, res, next) => {
    try {
      const { id } = z
        .object({ id: z.string().transform(Number) })
        .parse(req.params);
      const [deleted] = await db
        .delete(schemas.events)
        .where(eq(schemas.events.id, id))
        .returning();
      if (!deleted) throw new Error("Event not found");
      res.status(204).send();
    } catch (err) {
      next(err);
    }
  }
);

// E-Library Routes (/api/v1/resources/)
const resourceSchema = z.object({
  title: z.string().min(1),
  type: z.enum(["syllabus", "pyq", "ebook", "timetable"]),
  branch: z.string().optional(),
  semester: z.coerce.number().int().optional(),
});

app.post(
  "/api/v1/resources/",
  authenticate(["admin", "faculty"]),
  multerConfig,
  sanitizeInput,
  async (req, res, next) => {
    try {
      if (!req.file) throw new Error("File required");
      const fileUrl = await handleUpload(req.file);
      const data = resourceSchema.parse(req.body);
      const [resource] = await db
        .insert(schemas.resources)
        .values({ ...data, fileUrl })
        .returning();
      res.status(201).json(resource);
    } catch (err) {
      next(err);
    }
  }
);

app.get("/api/v1/resources/", async (req, res, next) => {
  try {
    const { branch, semester, type } = z
      .object({
        branch: z.string().optional(),
        semester: z.coerce.number().int().optional(),
        type: z.enum(["syllabus", "pyq", "ebook", "timetable"]).optional(),
      })
      .parse(req.query);
    let query = db.select().from(schemas.resources);
    if (branch) query = query.where(eq(schemas.resources.branch, branch));
    if (semester)
      query = query.where(eq(schemas.resources.semester, parseInt(semester)));
    if (type) query = query.where(eq(schemas.resources.type, type));
    const resources = await query;
    res.json(resources);
  } catch (err) {
    next(err);
  }
});

app.put(
  "/api/v1/resources/:id",
  authenticate(["admin", "faculty"]),
  sanitizeInput,
  async (req, res, next) => {
    try {
      const { id } = z
        .object({ id: z.string().transform(Number) })
        .parse(req.params);
      const data = resourceSchema.partial().parse(req.body);
      const [updated] = await db
        .update(schemas.resources)
        .set(data)
        .where(eq(schemas.resources.id, id))
        .returning();
      if (!updated) throw new Error("Resource not found");
      res.json(updated);
    } catch (err) {
      next(err);
    }
  }
);

app.delete(
  "/api/v1/resources/:id",
  authenticate(["admin", "faculty"]),
  async (req, res, next) => {
    try {
      const { id } = z
        .object({ id: z.string().transform(Number) })
        .parse(req.params);
      const [resource] = await db
        .select({ fileUrl: schemas.resources.fileUrl })
        .from(schemas.resources)
        .where(eq(schemas.resources.id, id));
      if (!resource) throw new Error("Resource not found");

      if (resource.fileUrl) {
        const key = resource.fileUrl.split("/").slice(-1)[0];
        await s3.send(
          new DeleteObjectCommand({
            Bucket: process.env.AWS_S3_BUCKET,
            Key: key,
          })
        );
      }

      const [deleted] = await db
        .delete(schemas.resources)
        .where(eq(schemas.resources.id, id))
        .returning();
      res.status(204).send();
    } catch (err) {
      next(err);
    }
  }
);

// Examination Routes (/api/v1/exams/)
const examSchema = z.object({
  name: z.string().min(1),
  date: dateSchema,
  syllabusUrl: z.string().url().optional(),
  branch: z.string().optional(),
});

app.post(
  "/api/v1/exams/",
  authenticate(["admin"]),
  sanitizeInput,
  async (req, res, next) => {
    try {
      logger.debug("Inserting exam:", req.body);
      const data = examSchema.parse(req.body);
      const [exam] = await db.insert(schemas.exams).values(data).returning();
      res.status(201).json(exam);
    } catch (err) {
      next(err);
    }
  }
);

app.get("/api/v1/exams/", async (req, res, next) => {
  try {
    const exams = await db
      .select()
      .from(schemas.exams)
      .orderBy(asc(schemas.exams.date));
    res.json(exams);
  } catch (err) {
    next(err);
  }
});

app.get(
  "/api/v1/exams/results/:studentId",
  authenticate(["admin", "student"]),
  async (req, res, next) => {
    try {
      const { studentId } = z
        .object({ studentId: z.string().transform(Number) })
        .parse(req.params);
      if (req.user.role === "student" && req.user.id !== studentId)
        throw new Error("Forbidden");
      const results = await db
        .select()
        .from(schemas.results)
        .where(eq(schemas.results.studentId, studentId));
      res.json(results);
    } catch (err) {
      next(err);
    }
  }
);

app.post(
  "/api/v1/exams/results",
  authenticate(["admin"]),
  sanitizeInput,
  async (req, res, next) => {
    try {
      const resultSchema = z.object({
        studentId: z.number().int().positive(),
        examId: z.number().int().positive(),
        marks: z.number().int().optional(),
        grade: z.string().optional(),
      });
      const data = resultSchema.parse(req.body);
      const [result] = await db
        .insert(schemas.results)
        .values(data)
        .returning();
      res.status(201).json(result);
    } catch (err) {
      next(err);
    }
  }
);

app.put(
  "/api/v1/exams/:id",
  authenticate(["admin"]),
  sanitizeInput,
  async (req, res, next) => {
    try {
      const { id } = z
        .object({ id: z.string().transform(Number) })
        .parse(req.params);
      const data = examSchema.partial().parse(req.body);
      const [updated] = await db
        .update(schemas.exams)
        .set(data)
        .where(eq(schemas.exams.id, id))
        .returning();
      if (!updated) throw new Error("Exam not found");
      res.json(updated);
    } catch (err) {
      next(err);
    }
  }
);

app.delete(
  "/api/v1/exams/:id",
  authenticate(["admin"]),
  async (req, res, next) => {
    try {
      const { id } = z
        .object({ id: z.string().transform(Number) })
        .parse(req.params);
      const [deleted] = await db
        .delete(schemas.exams)
        .where(eq(schemas.exams.id, id))
        .returning();
      if (!deleted) throw new Error("Exam not found");
      res.status(204).send();
    } catch (err) {
      next(err);
    }
  }
);

// Notices Routes (/api/v1/notices/)
const noticeSchema = z.object({
  title: z.string().min(1),
  description: z.string().optional(),
});

app.post(
  "/api/v1/notices/",
  authenticate(["admin"]),
  multerConfig,
  sanitizeInput,
  async (req, res, next) => {
    try {
      let fileUrl = null;
      if (req.file) fileUrl = await handleUpload(req.file);
      const data = noticeSchema.parse(req.body);
      const [notice] = await db
        .insert(schemas.notices)
        .values({ ...data, fileUrl })
        .returning();
      res.status(201).json(notice);
    } catch (err) {
      next(err);
    }
  }
);

app.get("/api/v1/notices/", async (req, res, next) => {
  try {
    const notices = await db
      .select()
      .from(schemas.notices)
      .orderBy(desc(schemas.notices.createdAt));
    res.json(notices);
  } catch (err) {
    next(err);
  }
});

app.put(
  "/api/v1/notices/:id",
  authenticate(["admin"]),
  sanitizeInput,
  async (req, res, next) => {
    try {
      const { id } = z
        .object({ id: z.string().transform(Number) })
        .parse(req.params);
      const data = noticeSchema.partial().parse(req.body);
      const [updated] = await db
        .update(schemas.notices)
        .set(data)
        .where(eq(schemas.notices.id, id))
        .returning();
      if (!updated) throw new Error("Notice not found");
      res.json(updated);
    } catch (err) {
      next(err);
    }
  }
);

app.delete(
  "/api/v1/notices/:id",
  authenticate(["admin"]),
  async (req, res, next) => {
    try {
      const { id } = z
        .object({ id: z.string().transform(Number) })
        .parse(req.params);
      const [notice] = await db
        .select({ fileUrl: schemas.notices.fileUrl })
        .from(schemas.notices)
        .where(eq(schemas.notices.id, id));
      if (!notice) throw new Error("Notice not found");

      if (notice.fileUrl) {
        const key = notice.fileUrl.split("/").slice(-1)[0];
        await s3.send(
          new DeleteObjectCommand({
            Bucket: process.env.AWS_S3_BUCKET,
            Key: key,
          })
        );
      }

      const [deleted] = await db
        .delete(schemas.notices)
        .where(eq(schemas.notices.id, id))
        .returning();
      res.status(204).send();
    } catch (err) {
      next(err);
    }
  }
);

// Faculty Routes (/api/v1/faculty/)
const facultySchema = z.object({
  name: z.string().min(1),
  department: z.string().min(1),
  designation: z.string().min(1),
  contact: z.string().optional(),
});

app.post(
  "/api/v1/faculty/",
  authenticate(["admin"]),
  sanitizeInput,
  async (req, res, next) => {
    try {
      const data = facultySchema.parse(req.body);
      const [fac] = await db.insert(schemas.faculty).values(data).returning();
      res.status(201).json(fac);
    } catch (err) {
      next(err);
    }
  }
);

app.get("/api/v1/faculty/", async (req, res, next) => {
  try {
    const facultyList = await db.select().from(schemas.faculty);
    res.json(facultyList);
  } catch (err) {
    next(err);
  }
});

app.put(
  "/api/v1/faculty/:id",
  authenticate(["admin"]),
  sanitizeInput,
  async (req, res, next) => {
    try {
      const { id } = z
        .object({ id: z.string().transform(Number) })
        .parse(req.params);
      const data = facultySchema.partial().parse(req.body);
      const [updated] = await db
        .update(schemas.faculty)
        .set(data)
        .where(eq(schemas.faculty.id, id))
        .returning();
      if (!updated) throw new Error("Faculty not found");
      res.json(updated);
    } catch (err) {
      next(err);
    }
  }
);

app.delete(
  "/api/v1/faculty/:id",
  authenticate(["admin"]),
  async (req, res, next) => {
    try {
      const { id } = z
        .object({ id: z.string().transform(Number) })
        .parse(req.params);
      const [deleted] = await db
        .delete(schemas.faculty)
        .where(eq(schemas.faculty.id, id))
        .returning();
      if (!deleted) throw new Error("Faculty not found");
      res.status(204).send();
    } catch (err) {
      next(err);
    }
  }
);

// Alumni Routes (/api/v1/alumni/)
const alumniSchema = z.object({
  name: z.string().min(1),
  batchYear: z.coerce.number().int().positive(),
  achievement: z.string().optional(),
  contactInfo: z.string().optional(),
  email: z.string().email().optional(),
});

app.post("/api/v1/alumni/register", sanitizeInput, async (req, res, next) => {
  try {
    const data = alumniSchema.parse(req.body);
    const { email, ...alumniData } = data;

    let userId = null;
    if (email) {
      const existingUser = await db.query.users.findFirst({
        where: eq(schemas.users.email, email),
      });
      if (existingUser && existingUser.role !== "alumni") {
        throw new Error("Email already registered with different role");
      }
      if (!existingUser) {
        const hash = await bcrypt.hash("default_alumni_password", 12);
        const [user] = await db
          .insert(schemas.users)
          .values({
            name: data.name,
            email,
            passwordHash: hash,
            role: "alumni",
          })
          .returning();
        userId = user.id;
      } else {
        userId = existingUser.id;
      }
    }

    const [alum] = await db
      .insert(schemas.alumni)
      .values({ ...alumniData, userId })
      .returning();
    res.status(201).json(alum);
  } catch (err) {
    next(err);
  }
});

app.get("/api/v1/alumni/", async (req, res, next) => {
  try {
    const alumniList = await db.select().from(schemas.alumni);
    res.json(alumniList);
  } catch (err) {
    next(err);
  }
});

app.put(
  "/api/v1/alumni/:id",
  authenticate(["admin"]),
  sanitizeInput,
  async (req, res, next) => {
    try {
      const { id } = z
        .object({ id: z.string().transform(Number) })
        .parse(req.params);
      const data = alumniSchema.partial().parse(req.body);
      const [updated] = await db
        .update(schemas.alumni)
        .set(data)
        .where(eq(schemas.alumni.id, id))
        .returning();
      if (!updated) throw new Error("Alumni not found");
      res.json(updated);
    } catch (err) {
      next(err);
    }
  }
);

app.delete(
  "/api/v1/alumni/:id",
  authenticate(["admin"]),
  async (req, res, next) => {
    try {
      const { id } = z
        .object({ id: z.string().transform(Number) })
        .parse(req.params);
      const [deleted] = await db
        .delete(schemas.alumni)
        .where(eq(schemas.alumni.id, id))
        .returning();
      if (!deleted) throw new Error("Alumni not found");
      res.status(204).send();
    } catch (err) {
      next(err);
    }
  }
);

// Highlights Routes (/api/v1/highlights/)
const highlightsSchema = z.object({
  title: z.string().min(1),
  description: z.string().optional(),
  imageUrl: z.string().url(),
  link: z.string().min(1),
});

// app.post(
//   "/api/v1/highlights/",
//   authenticate(["admin"]),
//   sanitizeInput,
//   async (req, res, next) => {
//     try {
//       const data = highlightsSchema.parse(req.body);
//       const [highlight] = await db
//         .insert(schemas.highlights)
//         .values(data)
//         .returning();
//       res.status(201).json(highlight);
//     } catch (err) {
//       next(err);
//     }
//   }
// );

app.post(
  "/api/v1/highlights/",
  authenticate(["admin"]),
  sanitizeInput,
  async (req, res, next) => {
    try {
      logger.info("Highlights POST: Route hit");
      const data = highlightsSchema.parse(req.body);
      logger.info("Highlights POST: Validation passed", data);
      const [highlight] = await db
        .insert(schemas.highlights)
        .values(data)
        .returning();
      logger.info("Highlights POST: Insert success", highlight);
      res.status(201).json(highlight);
    } catch (err) {
      logger.error("Highlights POST: Error", {
        message: err.message,
        stack: err.stack,
      });
      next(err);
    }
  }
);

app.get("/api/v1/highlights/", async (req, res, next) => {
  try {
    const highlights = await db
      .select()
      .from(schemas.highlights)
      .orderBy(desc(schemas.highlights.createdAt))
      .limit(5);
    res.json(highlights);
  } catch (err) {
    next(err);
  }
});

app.put(
  "/api/v1/highlights/:id",
  authenticate(["admin"]),
  sanitizeInput,
  async (req, res, next) => {
    try {
      const { id } = z
        .object({ id: z.string().transform(Number) })
        .parse(req.params);
      const data = highlightsSchema.partial().parse(req.body);
      const [updated] = await db
        .update(schemas.highlights)
        .set(data)
        .where(eq(schemas.highlights.id, id))
        .returning();
      if (!updated) throw new Error("Highlight not found");
      res.json(updated);
    } catch (err) {
      next(err);
    }
  }
);

app.delete(
  "/api/v1/highlights/:id",
  authenticate(["admin"]),
  async (req, res, next) => {
    try {
      const { id } = z
        .object({ id: z.string().transform(Number) })
        .parse(req.params);
      const [deleted] = await db
        .delete(schemas.highlights)
        .where(eq(schemas.highlights.id, id))
        .returning();
      if (!deleted) throw new Error("Highlight not found");
      res.status(204).send();
    } catch (err) {
      next(err);
    }
  }
);

// Start Server
app.listen(port, () => logger.info(`Server running on port ${port}`));
