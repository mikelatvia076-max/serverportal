// =====================================
// AGNES MEMORIAL MEDICAL HOSPITAL
// BACKEND SERVER (API only - the websites are in their own repos)
// =====================================

require("dotenv").config();
const express = require("express");
const cors = require("cors");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const db = require("./database");

const app = express();
// A known default secret would let anyone forge staff tokens, so if JWT_SECRET
// is not set on the host, a random one is made (staff must log in again after a restart).
const JWT_SECRET = process.env.JWT_SECRET || require("crypto").randomBytes(48).toString("hex");
if (!process.env.JWT_SECRET) console.log("WARNING: JWT_SECRET is not set. Add it in your host's environment variables.");

// ================================
// MIDDLEWARE
// ================================

app.set("trust proxy", 1); // correct visitor IP behind Render (for login lockout)
// CORS: the hospital site and staff portal are separate websites (e.g. on Vercel).
// Set CORS_ORIGINS on the host to their addresses, comma separated, no trailing slash:
//   CORS_ORIGINS=https://my-hospital.vercel.app,https://my-staff-portal.vercel.app
const ALLOWED_ORIGINS = (process.env.CORS_ORIGINS || "").split(",").map(o => o.trim().replace(/\/$/, "")).filter(Boolean);
if (!ALLOWED_ORIGINS.length) console.log("WARNING: CORS_ORIGINS is not set, so any website can call this API. Set it on your host.");
app.use(cors({
    origin: (origin, cb) => cb(null, !origin || !ALLOWED_ORIGINS.length || ALLOWED_ORIGINS.includes(origin))
}));
app.use(express.json({ limit: "100kb" }));

// Token Verification Middleware
const verifyToken = (req, res, next) => {
    const token = req.headers["authorization"]?.split(" ")[1];
    if (!token) return res.status(403).json({ message: "No token provided" });

    jwt.verify(token, JWT_SECRET, (err, decoded) => {
        if (err) return res.status(401).json({ message: "Unauthorized access" });
        req.user = decoded;
        next();
    });
};

// ================================
// HELPER: EXACT KENYA DATE ONLY (NO TIME)
// ================================
const getKenyaDate = () => {
    return new Date().toLocaleDateString("en-GB", { 
        timeZone: "Africa/Nairobi", 
        year: "numeric",
        month: "2-digit",
        day: "2-digit"
    });
};

// ================================
// TEST SERVER
// ================================

app.get("/", (req, res) => res.send("Agnes Memorial Hospital Backend Running"));
app.get("/health", (req, res) => res.json({ status: "ok" }));

// ================================
// REGISTER USER (Web Account Sign-up)
// ================================

app.post("/register", async (req, res) => {
    const { patient_id, name, email, phone, password } = req.body;

    if (!email || !password) {
        return res.status(400).json({ message: "Missing required fields" });
    }

    try {
        const hashedPassword = await bcrypt.hash(password, 10);
        const assignedId = patient_id || "AMMH" + Math.floor(1000 + Math.random() * 9000);

        const sql = `
            INSERT INTO users (patient_id, name, email, phone, password)
            VALUES (?, ?, ?, ?, ?)
        `;

        db.query(sql, [assignedId, name, email, phone, hashedPassword], (err, result) => {
            if (err) {
                if (err.code === "ER_DUP_ENTRY") {
                    return res.status(400).json({ message: "Email or User ID already registered" });
                }
                console.error("Registration Error:", err);
                return res.status(500).json({ message: "Registration failed" });
            }
            res.status(201).json({ message: "User registered successfully", patient_id: assignedId });
        });
    } catch (error) {
        res.status(500).json({ message: "Server error during registration" });
    }
});

// ================================
// LOGIN USER / PATIENT
// ================================

app.post("/login", (req, res) => {
    const { email, password } = req.body;

    if (!email || !password) {
        return res.status(400).json({ message: "Email and password required" });
    }

    db.query("SELECT * FROM users WHERE email=?", [email], async (err, result) => {
        if (err) {
            console.error("Login Error:", err);
            return res.status(500).json({ message: "Database error" });
        }

        let user = result[0];

        if (!user) {
            db.query("SELECT * FROM patients WHERE email=?", [email], async (pErr, pResult) => {
                if (pErr || pResult.length === 0) {
                    return res.status(401).json({ message: "Invalid login details" });
                }
                user = pResult[0];
                return processUserLogin(user, password, res);
            });
        } else {
            return processUserLogin(user, password, res);
        }
    });
});

async function processUserLogin(user, password, res) {
    const isMatch = await bcrypt.compare(password, user.password);

    if (!isMatch) {
        return res.status(401).json({ message: "Invalid login details" });
    }

    const token = jwt.sign(
        { id: user.id, patient_id: user.patient_id, email: user.email },
        JWT_SECRET,
        { expiresIn: "24h" }
    );

    delete user.password;

    res.json({
        message: "Login successful",
        token,
        patient: user
    });
}

// ================================
// GET PATIENTS (Hospital Managed Only)
// ================================

app.get("/patients", (req, res) => {
    db.query("SELECT * FROM patients ORDER BY id DESC", (err, result) => {
        if (err) {
            console.error(err);
            return res.status(500).json({ message: "Failed to retrieve patients" });
        }
        res.json(result);
    });
});

// ================================
// GET PATIENTS COUNT (Hospital Database)
// ================================

app.get("/api/patients/count", (req, res) => {
    db.query("SELECT COUNT(*) AS totalPatients FROM patients", (err, results) => {
        if (err) {
            console.error("Error fetching patient count:", err);
            return res.status(500).json({ message: "Failed to fetch patient count" });
        }
        res.json({ totalPatients: results[0].totalPatients || 0 });
    });
});

// ================================
// ADD PATIENT (Hospital Staff Action)
// ================================

app.post("/patients", (req, res) => {
    const { patient_id, name, age, gender, phone, email, address, status, registered } = req.body;
    const assignedId = patient_id || "AMMH" + Math.floor(1000 + Math.random() * 9000);
    const regDate = registered || getKenyaDate();

    const sql = `
        INSERT INTO patients (patient_id, name, age, gender, phone, email, address, status, registered)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
    `;

    db.query(sql, [assignedId, name, age || null, gender || null, phone, email, address || null, status || "Active", regDate], (err, result) => {
        if (err) {
            console.error("Add Patient Error:", err);
            return res.status(500).json({ message: "Failed to add patient", error: err.message });
        }
        res.status(201).json({ message: "Patient registered by hospital successfully", id: result.insertId });
    });
});

// ================================
// DELETE PATIENT
// ================================

app.delete("/patients/:id", (req, res) => {
    db.query("DELETE FROM patients WHERE id = ?", [req.params.id], (err) => {
        if (err) return res.status(500).json({ message: "Deletion failed" });
        res.json({ message: "Patient record deleted successfully" });
    });
});

// ================================
// SAVE APPOINTMENT
// ================================

app.post("/appointments", (req, res) => {
    const {
        patient_id,
        patient_name,
        email,
        department,
        staff,
        date,
        time,
        reason,
        status
    } = req.body;

    const sql = `
        INSERT INTO appointments
        (patient_id, patient_name, email, department, staff, date, time, reason, status, deleted_by_hospital, deleted_by_patient)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 0, 0)
    `;

    db.query(
        sql,
        [patient_id, patient_name, email, department, staff, date, time, reason, status || "Pending"],
        (err, result) => {
            if (err) {
                console.error("Appointment Insert Error:", err);
                return res.status(500).json({ message: "Appointment creation failed" });
            }

            const appointmentId = result.insertId;
            const notifDateStr = getKenyaDate();
            const notifSql = `
                INSERT INTO notifications (patient_id, title, message, user_type, created_at, status) 
                VALUES (?, ?, ?, 'Patient', ?, 'unread')
            `;
            const notifTitle = "Appointment Booked";
            const notifMsg = `Your appointment for ${date} has been submitted successfully.`;

            db.query(notifSql, [patient_id, notifTitle, notifMsg, notifDateStr], (nErr) => {
                if (nErr) console.error("Auto-notification error:", nErr);

                res.status(201).json({
                    message: "Appointment saved successfully",
                    id: appointmentId
                });
            });
        }
    );
});

// ================================
// GET PATIENT APPOINTMENTS
// ================================

app.get("/patient-appointments/:id", (req, res) => {
    const patient_id = req.params.id;

    db.query(
        "SELECT * FROM appointments WHERE patient_id=? AND COALESCE(deleted_by_patient, 0) = 0 ORDER BY id DESC",
        [patient_id],
        (err, result) => {
            if (err) {
                console.error(err);
                return res.status(500).json({ message: "Failed to load appointments" });
            }
            res.json(result);
        }
    );
});

// ================================
// GET ALL APPOINTMENTS
// ================================

app.get("/appointments", (req, res) => {
    db.query("SELECT * FROM appointments WHERE COALESCE(deleted_by_hospital, 0) = 0 ORDER BY id DESC", (err, result) => {
        if (err) {
            console.error(err);
            return res.status(500).json({ message: "Failed to load appointments" });
        }
        res.json(result);
    });
});

// ================================
// CANCEL APPOINTMENT
// ================================

app.put("/cancel-appointment/:id", (req, res) => {
    const { id } = req.params;

    db.query(
        "UPDATE appointments SET status='Cancelled' WHERE id=?",
        [id],
        (err) => {
            if (err) {
                console.error(err);
                return res.status(500).json({ message: "Cancellation failed" });
            }
            res.json({ message: "Appointment cancelled" });
        }
    );
});

// ==========================================
// PATIENT NOTIFICATIONS
// ==========================================

app.post("/notifications", (req, res) => {
    const { patient_id, title, message, user_type } = req.body;
    const currentDate = getKenyaDate();

    const sql = `
        INSERT INTO notifications (patient_id, title, message, user_type, created_at, status) 
        VALUES (?, ?, ?, ?, ?, 'unread')
    `;

    db.query(sql, [patient_id, title, message, user_type || "Patient", currentDate], (err, result) => {
        if (err) {
            console.error("Error saving notification:", err);
            return res.status(500).json({ message: "Failed to create notification" });
        }
        res.status(201).json({ message: "Notification sent successfully", id: result.insertId });
    });
});

app.get("/notifications/:id", (req, res) => {
    const patient_id = req.params.id;

    db.query(
        "SELECT * FROM notifications WHERE patient_id=? ORDER BY id DESC",
        [patient_id],
        (err, result) => {
            if (err) {
                console.error(err);
                return res.status(500).json({ message: "Failed to fetch notifications" });
            }
            res.json(result);
        }
    );
});

app.put("/notifications/mark-read/:id", (req, res) => {
    db.query("UPDATE notifications SET status = 'read' WHERE id = ?", [req.params.id], (err) => {
        if (err) return res.status(500).json({ message: "Update failed" });
        res.json({ message: "Notification marked as read" });
    });
});

app.delete("/notifications/:id", (req, res) => {
    db.query("DELETE FROM notifications WHERE id = ?", [req.params.id], (err) => {
        if (err) return res.status(500).json({ message: "Deletion failed" });
        res.json({ message: "Notification deleted" });
    });
});

// ==========================================
// HOSPITAL NOTIFICATIONS
// ==========================================

app.post("/hospital-notifications", (req, res) => {
    const { patient_name, staff, date, type } = req.body;
    const currentDate = getKenyaDate();

    const sql = `
        INSERT INTO hospital_notifications 
        (patient_name, staff, date, created_at, type, is_read) 
        VALUES (?, ?, ?, ?, ?, 0)
    `;

    db.query(sql, [patient_name, staff, date, currentDate, type || "Appointment Request"], (err, result) => {
        if (err) {
            console.error("Error saving hospital notification:", err);
            return res.status(500).json({ message: "Failed to log hospital notification" });
        }
        res.status(201).json({ message: "Hospital notification created", id: result.insertId });
    });
});

app.get("/hospital-notifications", (req, res) => {
    db.query("SELECT * FROM hospital_notifications ORDER BY id DESC", (err, results) => {
        if (err) {
            console.error("Error fetching hospital notifications:", err);
            return res.status(500).json({ message: "Failed to fetch notifications" });
        }
        res.json(results);
    });
});

app.put("/hospital-notifications/mark-read/:id", (req, res) => {
    db.query("UPDATE hospital_notifications SET is_read = 1 WHERE id = ?", [req.params.id], (err) => {
        if (err) return res.status(500).json({ message: "Update failed" });
        res.json({ message: "Hospital notification marked as read" });
    });
});

app.delete("/hospital-notifications/:id", (req, res) => {
    db.query("DELETE FROM hospital_notifications WHERE id = ?", [req.params.id], (err) => {
        if (err) return res.status(500).json({ message: "Deletion failed" });
        res.json({ message: "Hospital notification deleted" });
    });
});

// ================================
// DOCTORS & NURSES
// ================================

app.get("/doctors", (req, res) => {
    db.query("SELECT * FROM doctors ORDER BY id DESC", (err, result) => {
        if (err) return res.status(500).json({ message: "Database query error" });
        res.json(result);
    });
});

app.post("/doctors", (req, res) => {
    const { doctor_id, name, specialization, department, phone, email, availability } = req.body;
    const sql = `INSERT INTO doctors (doctor_id, name, specialization, department, phone, email, availability) VALUES (?, ?, ?, ?, ?, ?, ?)`;

    db.query(sql, [doctor_id, name, specialization, department, phone, email, availability], (err, result) => {
        if (err) {
            console.error(err);
            return res.status(500).json({ message: "Doctor registration failed" });
        }
        res.status(201).json({ message: "Doctor registered successfully", id: result.insertId });
    });
});

app.delete("/doctors/:id", (req, res) => {
    db.query("DELETE FROM doctors WHERE id = ?", [req.params.id], (err) => {
        if (err) return res.status(500).json({ message: "Deletion failed" });
        res.json({ message: "Doctor deleted successfully" });
    });
});

app.get("/nurses", (req, res) => {
    db.query("SELECT * FROM nurses ORDER BY id DESC", (err, result) => {
        if (err) return res.status(500).json({ message: "Database query error" });
        res.json(result);
    });
});

app.post("/nurses", (req, res) => {
    const { nurse_id, name, department, phone, email, shift, status } = req.body;
    const sql = `INSERT INTO nurses (nurse_id, name, department, phone, email, shift, status) VALUES (?, ?, ?, ?, ?, ?, ?)`;

    db.query(sql, [nurse_id, name, department, phone, email, shift, status || "Active"], (err, result) => {
        if (err) {
            console.error(err);
            return res.status(500).json({ message: "Nurse registration failed" });
        }
        res.status(201).json({ message: "Nurse registered successfully", id: result.insertId });
    });
});

app.delete("/nurses/:id", (req, res) => {
    db.query("DELETE FROM nurses WHERE id = ?", [req.params.id], (err) => {
        if (err) return res.status(500).json({ message: "Deletion failed" });
        res.json({ message: "Nurse deleted successfully" });
    });
});

// =========================================================
// APPOINTMENT UPDATE WITH CROSS-PORTAL SYNC
// =========================================================

app.post("/hospital-update-appointment/:id", (req, res) => {
    const appointmentId = req.params.id;
    const { status, staff_name, department } = req.body;
    const notifDateStr = getKenyaDate();

    db.query(
        `UPDATE appointments SET status = ?, staff = ?, department = ? WHERE id = ?`,
        [status, staff_name, department, appointmentId],
        (err) => {
            if (err) {
                console.error("Update Error:", err);
                return res.status(500).json({ message: "Hospital update failed" });
            }

            db.query(`SELECT patient_id FROM appointments WHERE id = ?`, [appointmentId], (err, searchResult) => {
                if (err || searchResult.length === 0) {
                    return res.json({ message: "Updated successfully" });
                }

                const targetPatient = searchResult[0].patient_id;
                const title = `Appointment Status Updated`;
                const message = `Your appointment status has been updated to "${status}" by ${staff_name || 'Hospital Staff'}.`;

                db.query(
                    `INSERT INTO notifications (patient_id, title, message, user_type, created_at, status) VALUES (?, ?, ?, 'Patient', ?, 'unread')`,
                    [targetPatient, title, message, notifDateStr],
                    (notificationErr) => {
                        if (notificationErr) console.error("Failed to log tracking alert:", notificationErr);

                        res.json({
                            message: "Hospital portal changes synchronized successfully",
                            appointmentId
                        });
                    }
                );
            });
        }
    );
});

app.delete("/delete-appointment/:id", (req, res) => {
    db.query("DELETE FROM appointments WHERE id=?", [req.params.id], (err) => {
        if (err) return res.status(500).json({ message: "Deletion failed" });
        res.json({ message: "Appointment deleted permanently" });
    });
});

app.delete("/hospital-delete-appointment/:id", (req, res) => {
    db.query("UPDATE appointments SET deleted_by_hospital = 1 WHERE id = ?", [req.params.id], (err) => {
        if (err) {
            console.error("Hospital soft-delete error:", err);
            return res.status(500).json({ message: "System deletion failed" });
        }
        res.json({ message: "Appointment deleted from hospital portal" });
    });
});

app.delete("/patient-delete-appointment/:id", (req, res) => {
    db.query("UPDATE appointments SET deleted_by_patient = 1 WHERE id = ?", [req.params.id], (err) => {
        if (err) {
            console.error("Patient soft-delete error:", err);
            return res.status(500).json({ message: "System deletion failed" });
        }
        res.json({ message: "Appointment deleted from patient portal" });
    });
});

app.put("/appointments/:id/status", (req, res) => {
    const { id } = req.params;
    const { status } = req.body;

    db.query("UPDATE appointments SET status = ? WHERE id = ?", [status, id], (err) => {
        if (err) {
            console.error("Error updating appointment system status:", err);
            return res.status(500).json({ message: "Database update failed" });
        }
        res.json({ message: `Appointment status set to ${status}` });
    });
});

// ================================
// STAFF ACCOUNTS (no public sign-up; admin issues accounts)
// ================================

// Hospital staff login (hospital-login.html): username + password + role, first-login password change,
// forgot-password requests. Reads the employees created in the Staff Portal.
app.use("/staff", require("./staff-login")(JWT_SECRET));

// Staff Portal API: portal admins sign up / log in, then create and delete employee logins.
// portal.js calls API_URL + "/staff/...", so in the PORTAL config.js set
//   API_URL = "https://YOUR-BACKEND.onrender.com/portal-api"
// (kept apart from /staff above, which belongs to the hospital login page).
const portalApi = require("./portal-api")(JWT_SECRET);
app.use("/portal-api/staff", portalApi);
app.use("/portal-api", portalApi);

// ================================
// START SERVER
// ================================

const PORT = process.env.PORT || 5000;
app.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
});