from django.db import migrations, models
import django.db.models.deletion
import django.utils.timezone


class Migration(migrations.Migration):

    dependencies = [
        ('api', '0008_farmrequest'),
    ]

    operations = [

        # ==================== VerificationRequest ====================
        migrations.RunSQL(
            sql="""
            CREATE TABLE IF NOT EXISTS "verification_requests" (
                "id" serial NOT NULL PRIMARY KEY,
                "rsbsa_number" varchar(100) NOT NULL,
                "valid_id_image" varchar(100) NOT NULL,
                "notes" text NOT NULL,
                "status" varchar(20) NOT NULL DEFAULT 'pending',
                "review_notes" text NOT NULL,
                "reviewed_at" timestamp with time zone NULL,
                "created_at" timestamp with time zone NOT NULL,
                "updated_at" timestamp with time zone NOT NULL,
                "user_id" integer NOT NULL REFERENCES "users"("id") DEFERRABLE INITIALLY DEFERRED,
                "reviewed_by_id" integer NULL REFERENCES "users"("id") DEFERRABLE INITIALLY DEFERRED
            );
            """,
            reverse_sql="DROP TABLE IF EXISTS verification_requests;",
        ),

        # ==================== Farm ====================
        migrations.RunSQL(
            sql="""
            CREATE TABLE IF NOT EXISTS "farms" (
                "id" serial NOT NULL PRIMARY KEY,
                "name" varchar(200) NOT NULL,
                "address" varchar(500) NOT NULL,
                "lat" double precision NOT NULL,
                "lng" double precision NOT NULL,
                "size" double precision NULL,
                "crop_type" varchar(100) NULL,
                "is_verified" boolean NOT NULL DEFAULT true,
                "created_at" timestamp with time zone NOT NULL,
                "updated_at" timestamp with time zone NOT NULL,
                "user_id" integer NOT NULL REFERENCES "users"("id") DEFERRABLE INITIALLY DEFERRED,
                "created_by_id" integer NULL REFERENCES "users"("id") DEFERRABLE INITIALLY DEFERRED
            );
            """,
            reverse_sql="DROP TABLE IF EXISTS farms;",
        ),

        # ==================== approved_farm FK on farm_requests ====================
        migrations.RunSQL(
            sql="""
            DO $$
            BEGIN
                IF NOT EXISTS (
                    SELECT 1 FROM information_schema.columns
                    WHERE table_name='farm_requests' AND column_name='approved_farm_id'
                ) THEN
                    ALTER TABLE "farm_requests"
                    ADD COLUMN "approved_farm_id" integer NULL
                    REFERENCES "farms"("id") DEFERRABLE INITIALLY DEFERRED;
                END IF;
            END$$;
            """,
            reverse_sql="ALTER TABLE farm_requests DROP COLUMN IF EXISTS approved_farm_id;",
        ),

        # ==================== PestDetection ====================
        migrations.RunSQL(
            sql="""
            CREATE TABLE IF NOT EXISTS "pest_detections" (
                "id" serial NOT NULL PRIMARY KEY,
                "image" varchar(100) NULL,
                "crop_type" varchar(10) NOT NULL,
                "pest_name" varchar(255) NOT NULL,
                "pest_type" varchar(200) NULL,
                "confidence" double precision NOT NULL DEFAULT 0.0,
                "severity" varchar(20) NOT NULL,
                "status" varchar(20) NOT NULL DEFAULT 'pending',
                "latitude" double precision NOT NULL,
                "longitude" double precision NOT NULL,
                "address" varchar(255) NOT NULL,
                "description" text NULL,
                "active" boolean NOT NULL DEFAULT true,
                "confirmed" boolean NOT NULL DEFAULT false,
                "detected_at" timestamp with time zone NOT NULL,
                "reported_at" timestamp with time zone NULL,
                "resolved_at" timestamp with time zone NULL,
                "admin_notes" text NOT NULL,
                "user_id" integer NOT NULL REFERENCES "users"("id") DEFERRABLE INITIALLY DEFERRED,
                "farm_id" integer NULL REFERENCES "farms"("id") DEFERRABLE INITIALLY DEFERRED,
                "verified_by_id" integer NULL REFERENCES "users"("id") DEFERRABLE INITIALLY DEFERRED
            );
            """,
            reverse_sql="DROP TABLE IF EXISTS pest_detections;",
        ),

        # ==================== PestInfo ====================
        migrations.RunSQL(
            sql="""
            CREATE TABLE IF NOT EXISTS "pest_info" (
                "id" serial NOT NULL PRIMARY KEY,
                "name" varchar(100) NOT NULL UNIQUE,
                "scientific_name" varchar(100) NOT NULL,
                "crop_affected" varchar(50) NOT NULL,
                "description" text NOT NULL,
                "symptoms" text NOT NULL,
                "control_methods" text NOT NULL,
                "prevention" text NOT NULL,
                "image_url" varchar(200) NOT NULL,
                "is_published" boolean NOT NULL DEFAULT true,
                "created_at" timestamp with time zone NOT NULL,
                "updated_at" timestamp with time zone NOT NULL,
                "created_by_id" integer NULL REFERENCES "users"("id") DEFERRABLE INITIALLY DEFERRED
            );
            """,
            reverse_sql="DROP TABLE IF EXISTS pest_info;",
        ),

        # ==================== InfestationReport ====================
        migrations.RunSQL(
            sql="""
            CREATE TABLE IF NOT EXISTS "infestation_reports" (
                "id" serial NOT NULL PRIMARY KEY,
                "area_affected" double precision NOT NULL,
                "notes" text NOT NULL,
                "is_verified" boolean NOT NULL DEFAULT false,
                "reported_at" timestamp with time zone NOT NULL,
                "detection_id" integer NOT NULL UNIQUE REFERENCES "pest_detections"("id") DEFERRABLE INITIALLY DEFERRED,
                "verified_by_id" integer NULL REFERENCES "users"("id") DEFERRABLE INITIALLY DEFERRED
            );
            """,
            reverse_sql="DROP TABLE IF EXISTS infestation_reports;",
        ),

        # ==================== Alert ====================
        migrations.RunSQL(
            sql="""
            CREATE TABLE IF NOT EXISTS "alerts" (
                "id" serial NOT NULL PRIMARY KEY,
                "title" varchar(200) NOT NULL,
                "message" text NOT NULL,
                "alert_type" varchar(20) NOT NULL DEFAULT 'info',
                "target_area" varchar(100) NOT NULL,
                "is_active" boolean NOT NULL DEFAULT true,
                "created_at" timestamp with time zone NOT NULL,
                "expires_at" timestamp with time zone NULL,
                "created_by_id" integer NOT NULL REFERENCES "users"("id") DEFERRABLE INITIALLY DEFERRED
            );
            """,
            reverse_sql="DROP TABLE IF EXISTS alerts;",
        ),

        # ==================== UserActivity ====================
        migrations.RunSQL(
            sql="""
            CREATE TABLE IF NOT EXISTS "user_activities" (
                "id" serial NOT NULL PRIMARY KEY,
                "action" varchar(100) NOT NULL,
                "details" text NOT NULL,
                "ip_address" inet NULL,
                "timestamp" timestamp with time zone NOT NULL,
                "user_id" integer NOT NULL REFERENCES "users"("id") DEFERRABLE INITIALLY DEFERRED
            );
            """,
            reverse_sql="DROP TABLE IF EXISTS user_activities;",
        ),

        # ==================== NotificationPreference ====================
        migrations.RunSQL(
            sql="""
            CREATE TABLE IF NOT EXISTS "notification_preferences" (
                "id" serial NOT NULL PRIMARY KEY,
                "push_enabled" boolean NOT NULL DEFAULT true,
                "detection_alerts" boolean NOT NULL DEFAULT true,
                "critical_alerts" boolean NOT NULL DEFAULT true,
                "push_subscription" jsonb NULL,
                "updated_at" timestamp with time zone NOT NULL,
                "user_id" integer NOT NULL UNIQUE REFERENCES "users"("id") DEFERRABLE INITIALLY DEFERRED
            );
            """,
            reverse_sql="DROP TABLE IF EXISTS notification_preferences;",
        ),

        # ==================== Notification ====================
        migrations.RunSQL(
            sql="""
            CREATE TABLE IF NOT EXISTS "notifications" (
                "id" serial NOT NULL PRIMARY KEY,
                "notification_type" varchar(30) NOT NULL,
                "title" varchar(200) NOT NULL,
                "message" text NOT NULL,
                "is_read" boolean NOT NULL DEFAULT false,
                "related_id" integer NULL,
                "created_at" timestamp with time zone NOT NULL,
                "user_id" integer NOT NULL REFERENCES "users"("id") DEFERRABLE INITIALLY DEFERRED
            );
            """,
            reverse_sql="DROP TABLE IF EXISTS notifications;",
        ),

    ]