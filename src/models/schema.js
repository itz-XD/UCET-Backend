import {
  pgTable,
  serial,
  text,
  varchar,
  integer,
  timestamp,
  pgEnum,
} from "drizzle-orm/pg-core";

export const userRoles = pgEnum("role", [
  "admin",
  "faculty",
  "student",
  "alumni",
]);

export const users = pgTable("users", {
  id: serial("id").primaryKey(),
  name: varchar("name", { length: 255 }).notNull(),
  email: varchar("email", { length: 255 }).unique().notNull(),
  passwordHash: text("password_hash").notNull(),
  role: userRoles("role").default("student").notNull(),
  createdAt: timestamp("created_at").defaultNow(),
});

export const admissions = pgTable("admissions", {
  id: serial("id").primaryKey(),
  studentName: varchar("student_name", { length: 255 }).notNull(),
  branch: varchar("branch", { length: 100 }).notNull(),
  year: integer("year").notNull(),
  status: varchar("status", { length: 50 }).default("pending").notNull(),
});

export const events = pgTable("events", {
  id: serial("id").primaryKey(),
  title: varchar("title", { length: 255 }).notNull(),
  description: text("description"),
  date: timestamp("date").notNull(),
  location: varchar("location", { length: 255 }),
});

export const resourceTypes = pgEnum("type", [
  "syllabus",
  "pyq",
  "ebook",
  "timetable",
]);

export const resources = pgTable("resources", {
  id: serial("id").primaryKey(),
  title: varchar("title", { length: 255 }).notNull(),
  type: resourceTypes("type").notNull(),
  branch: varchar("branch", { length: 100 }),
  semester: integer("semester"),
  fileUrl: text("file_url").notNull(),
});

export const exams = pgTable("exams", {
  id: serial("id").primaryKey(),
  name: varchar("name", { length: 255 }).notNull(),
  date: timestamp("date").notNull(),
  syllabusUrl: text("syllabus_url"),
  branch: varchar("branch", { length: 100 }),
});

export const results = pgTable("results", {
  id: serial("id").primaryKey(),
  studentId: integer("student_id")
    .notNull()
    .references(() => users.id),
  examId: integer("exam_id")
    .notNull()
    .references(() => exams.id),
  marks: integer("marks"),
  grade: varchar("grade", { length: 10 }),
});

export const notices = pgTable("notices", {
  id: serial("id").primaryKey(),
  title: varchar("title", { length: 255 }).notNull(),
  description: text("description"),
  fileUrl: text("file_url"),
  createdAt: timestamp("created_at").defaultNow(),
});

export const faculty = pgTable("faculty", {
  id: serial("id").primaryKey(),
  name: varchar("name", { length: 255 }).notNull(),
  department: varchar("department", { length: 100 }).notNull(),
  designation: varchar("designation", { length: 100 }).notNull(),
  contact: varchar("contact", { length: 255 }),
});

export const alumni = pgTable("alumni", {
  id: serial("id").primaryKey(),
  name: varchar("name", { length: 255 }).notNull(),
  batchYear: integer("batch_year").notNull(),
  achievement: text("achievement"),
  contactInfo: varchar("contact_info", { length: 255 }),
});

export const highlights = pgTable("highlights", {
  id: serial("id").primaryKey(),
  title: varchar("title", { length: 255 }).notNull(),
  description: text("description"),
  imageUrl: text("image_url").notNull(),
  link: varchar("link", { length: 255 }).notNull(),
  createdAt: timestamp("created_at").defaultNow(),
});
