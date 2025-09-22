CREATE TYPE "public"."type" AS ENUM('syllabus', 'pyq', 'ebook', 'timetable');--> statement-breakpoint
CREATE TYPE "public"."role" AS ENUM('admin', 'faculty', 'student', 'alumni');--> statement-breakpoint
CREATE TABLE "admissions" (
	"id" serial PRIMARY KEY NOT NULL,
	"student_name" varchar(255) NOT NULL,
	"branch" varchar(100) NOT NULL,
	"year" integer NOT NULL,
	"status" varchar(50) DEFAULT 'pending'
);
--> statement-breakpoint
CREATE TABLE "alumni" (
	"id" serial PRIMARY KEY NOT NULL,
	"name" varchar(255) NOT NULL,
	"batch_year" integer NOT NULL,
	"achievement" text,
	"contact_info" varchar(255)
);
--> statement-breakpoint
CREATE TABLE "events" (
	"id" serial PRIMARY KEY NOT NULL,
	"title" varchar(255) NOT NULL,
	"description" text,
	"date" timestamp NOT NULL,
	"location" varchar(255)
);
--> statement-breakpoint
CREATE TABLE "exams" (
	"id" serial PRIMARY KEY NOT NULL,
	"name" varchar(255) NOT NULL,
	"date" timestamp NOT NULL,
	"syllabus_url" text,
	"branch" varchar(100)
);
--> statement-breakpoint
CREATE TABLE "faculty" (
	"id" serial PRIMARY KEY NOT NULL,
	"name" varchar(255) NOT NULL,
	"department" varchar(100) NOT NULL,
	"designation" varchar(100) NOT NULL,
	"contact" varchar(255)
);
--> statement-breakpoint
CREATE TABLE "notices" (
	"id" serial PRIMARY KEY NOT NULL,
	"title" varchar(255) NOT NULL,
	"description" text,
	"file_url" text,
	"created_at" timestamp DEFAULT now()
);
--> statement-breakpoint
CREATE TABLE "resources" (
	"id" serial PRIMARY KEY NOT NULL,
	"title" varchar(255) NOT NULL,
	"type" "type" NOT NULL,
	"branch" varchar(100),
	"semester" integer,
	"file_url" text NOT NULL
);
--> statement-breakpoint
CREATE TABLE "results" (
	"id" serial PRIMARY KEY NOT NULL,
	"student_id" integer NOT NULL,
	"exam_id" integer NOT NULL,
	"marks" integer,
	"grade" varchar(10)
);
--> statement-breakpoint
CREATE TABLE "users" (
	"id" serial PRIMARY KEY NOT NULL,
	"name" varchar(255) NOT NULL,
	"email" varchar(255) NOT NULL,
	"password_hash" text NOT NULL,
	"role" "role" DEFAULT 'student' NOT NULL,
	"created_at" timestamp DEFAULT now(),
	CONSTRAINT "users_email_unique" UNIQUE("email")
);
--> statement-breakpoint
ALTER TABLE "results" ADD CONSTRAINT "results_student_id_users_id_fk" FOREIGN KEY ("student_id") REFERENCES "public"."users"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "results" ADD CONSTRAINT "results_exam_id_exams_id_fk" FOREIGN KEY ("exam_id") REFERENCES "public"."exams"("id") ON DELETE no action ON UPDATE no action;