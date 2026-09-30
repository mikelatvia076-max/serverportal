// AGNES MEMORIAL - STAFF PORTAL API (replaces staff-api.js in the portal repo)
// Portal admins sign up here (needs PORTAL_SIGNUP_CODE), then create/delete the
// hospital login details (username, email, password, role) stored in `employees`.
const express = require("express");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const crypto = require("crypto");
const db = require("./database").promise();

const ROLES = ["Admin", "Doctor", "Nurse", "Receptionist", "Pharmacist", "Laboratory"];
const DUMMY_HASH = bcrypt.hashSync("not-a-real-password", 10);
const now = () => new Date().toISOString().slice(0, 16).replace("T", " ");
const strong = (p) => typeof p === "string" && p.length >= 8 && /[A-Za-z]/.test(p) && /\d/.test(p);
const tempPassword = () => {
    const chars = "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnpqrstuvwxyz23456789";
    let p = "";
    for (const b of crypto.randomBytes(10)) p += chars[b % chars.length];
    return p;
};
const view = (e) => ({
    id: e.id, employee_id: e.employee_id, name: e.name, username: e.username, email: e.email,
    role: e.role, status: e.status, must_change_password: !!e.must_change_password,
    created_at: e.created_at, last_login: e.last_login
});
const same = (a, b) => {
    const x = Buffer.from(String(a)), y = Buffer.from(String(b));
    return x.length === y.length && crypto.timingSafeEqual(x, y);
};

module.exports = function (JWT_SECRET) {
    const router = express.Router();
    // type "portal" so a hospital "staff" token can never open this portal (and vice versa)
    const sign = (a) => jwt.sign({ id: a.id, type: "portal" }, JWT_SECRET, { expiresIn: "12h" });

    (async () => {
        try {
            await db.query(`CREATE TABLE IF NOT EXISTS portal_users (
                id INT AUTO_INCREMENT PRIMARY KEY,
                name VARCHAR(150) NOT NULL,
                username VARCHAR(60) NOT NULL UNIQUE,
                password VARCHAR(255) NOT NULL,
                created_at VARCHAR(30),
                last_login VARCHAR(30)
            ) CHARACTER SET utf8mb4`);
            // same shape the hospital login reads
            await db.query(`CREATE TABLE IF NOT EXISTS employees (
                id INT AUTO_INCREMENT PRIMARY KEY,
                employee_id VARCHAR(20) UNIQUE,
                name VARCHAR(150) NOT NULL,
                username VARCHAR(60) NOT NULL UNIQUE,
                email VARCHAR(191) NOT NULL UNIQUE,
                phone VARCHAR(30),
                role VARCHAR(30) NOT NULL,
                department VARCHAR(100),
                password VARCHAR(255) NOT NULL,
                status VARCHAR(20) DEFAULT 'Active',
                must_change_password TINYINT DEFAULT 1,
                token_version INT DEFAULT 0,
                created_at VARCHAR(30),
                last_login VARCHAR(30)
            ) CHARACTER SET utf8mb4`);
            await db.query(`CREATE TABLE IF NOT EXISTS password_requests (
                id INT AUTO_INCREMENT PRIMARY KEY,
                employee_id INT NOT NULL,
                name VARCHAR(150),
                username VARCHAR(60),
                created_at VARCHAR(30),
                status VARCHAR(20) DEFAULT 'Pending'
            ) CHARACTER SET utf8mb4`);
            if (!process.env.PORTAL_SIGNUP_CODE) console.warn("PORTAL_SIGNUP_CODE not set: portal sign-up is disabled.");
            console.log("Staff portal ready");
        } catch (err) { console.error("Portal setup error:", err.message); }
    })();

    async function auth(req, res, next) {
        const token = (req.headers.authorization || "").split(" ")[1];
        if (!token) return res.status(401).json({ message: "Please log in" });
        try {
            const d = jwt.verify(token, JWT_SECRET);
            if (d.type !== "portal") throw new Error("wrong token");
            const [[a]] = await db.query("SELECT * FROM portal_users WHERE id=?", [d.id]);
            if (!a) throw new Error("gone");
            req.admin = a;
            next();
        } catch (err) { res.status(401).json({ message: "Session expired. Please log in again." }); }
    }

    // ---------- portal account: sign up + login ----------
    const fails = new Map();
    const blocked = (key) => {
        const f = fails.get(key);
        if (f && Date.now() >= f.until) { fails.delete(key); return false; }
        return !!f && f.n >= 5;
    };
    const fail = (key) => {
        const f = fails.get(key);
        fails.set(key, { n: (f ? f.n : 0) + 1, until: f ? f.until : Date.now() + 15 * 60 * 1000 });
    };

    router.post("/signup", async (req, res) => {
        const { name, username, password, code } = req.body || {};
        if (!process.env.PORTAL_SIGNUP_CODE) return res.status(503).json({ message: "Sign-up is not enabled. Ask the system owner." });
        const key = "signup|" + req.ip;
        if (blocked(key)) return res.status(429).json({ message: "Too many attempts. Try again in 15 minutes." });
        if (!same(code || "", process.env.PORTAL_SIGNUP_CODE)) { fail(key); return res.status(403).json({ message: "Wrong registration code" }); }

        const u = String(username || "").trim().toLowerCase();
        const n = String(name || "").trim();
        if (!n) return res.status(400).json({ message: "Enter your full name" });
        if (!/^[a-z0-9._-]{3,60}$/.test(u)) return res.status(400).json({ message: "Username: 3+ letters, numbers, . _ -" });
        if (!strong(password)) return res.status(400).json({ message: "Password needs 8+ characters with letters and numbers" });
        try {
            const [r] = await db.query("INSERT INTO portal_users (name, username, password, created_at) VALUES (?, ?, ?, ?)",
                [n, u, await bcrypt.hash(password, 10), now()]);
            const a = { id: r.insertId, name: n, username: u };
            res.status(201).json({ message: "Account created", token: sign(a), admin: { name: n, username: u } });
        } catch (err) {
            if (err.code === "ER_DUP_ENTRY") return res.status(400).json({ message: "That username is taken" });
            console.error("Portal signup error:", err);
            res.status(500).json({ message: "Could not create account" });
        }
    });

    router.post("/login", async (req, res) => {
        const { username, password } = req.body || {};
        if (!username || !password) return res.status(400).json({ message: "Username and password are required" });
        const key = req.ip + "|" + String(username).toLowerCase();
        if (blocked(key)) return res.status(429).json({ message: "Too many failed attempts. Try again in 15 minutes." });
        try {
            const [[a]] = await db.query("SELECT * FROM portal_users WHERE username=?", [String(username).trim().toLowerCase()]);
            const ok = await bcrypt.compare(String(password), a ? a.password : DUMMY_HASH);
            if (!a || !ok) { fail(key); return res.status(401).json({ message: "Invalid login details" }); }
            fails.delete(key);
            await db.query("UPDATE portal_users SET last_login=? WHERE id=?", [now(), a.id]);
            res.json({ token: sign(a), admin: { name: a.name, username: a.username } });
        } catch (err) { res.status(500).json({ message: "Server error. Try again." }); }
    });

    router.get("/me", auth, (req, res) => res.json({ admin: { name: req.admin.name, username: req.admin.username } }));

    // ---------- employees (hospital login details) ----------
    router.get("/employees", auth, async (req, res) => {
        try { const [rows] = await db.query("SELECT * FROM employees ORDER BY id DESC"); res.json(rows.map(view)); }
        catch (err) { res.status(500).json({ message: "Could not load employees" }); }
    });

    router.post("/employees", auth, async (req, res) => {
        const b = req.body || {};
        const username = String(b.username || "").trim().toLowerCase();
        const email = String(b.email || "").trim().toLowerCase();
        const name = String(b.name || "").trim() || username;
        const { role, password } = b;

        if (!/^[a-z0-9._-]{3,60}$/.test(username)) return res.status(400).json({ message: "Username: 3+ letters, numbers, . _ -" });
        if (!/^\S+@\S+\.\S+$/.test(email)) return res.status(400).json({ message: "Enter a valid email address" });
        if (!ROLES.includes(role)) return res.status(400).json({ message: "Select a valid role" });
        if (!strong(password)) return res.status(400).json({ message: "Password needs 8+ characters with letters and numbers" });
        try {
            const [r] = await db.query(
                "INSERT INTO employees (name, username, email, role, password, created_at) VALUES (?, ?, ?, ?, ?, ?)",
                [name, username, email, role, await bcrypt.hash(password, 10), now()]);
            const empId = "AMMH-E" + String(r.insertId).padStart(4, "0");
            await db.query("UPDATE employees SET employee_id=? WHERE id=?", [empId, r.insertId]);
            res.status(201).json({ message: "Employee registered", employee: { name, role, email }, credentials: { username, password } });
        } catch (err) {
            if (err.code === "ER_DUP_ENTRY")
                return res.status(400).json({ message: /email/.test(err.sqlMessage || "") ? "That email is already registered" : "That username is already taken" });
            console.error("Create employee error:", err);
            res.status(500).json({ message: "Could not register employee" });
        }
    });

    // employee quit -> remove their login for good
    router.delete("/employees/:id", auth, async (req, res) => {
        try {
            const [r] = await db.query("DELETE FROM employees WHERE id=?", [req.params.id]);
            if (!r.affectedRows) return res.status(404).json({ message: "Employee not found" });
            await db.query("DELETE FROM password_requests WHERE employee_id=?", [req.params.id]);
            res.json({ message: "Employee deleted. They can no longer log in." });
        } catch (err) { res.status(500).json({ message: "Could not delete employee" }); }
    });

    // ---------- forgot-password requests coming from the hospital login page ----------
    router.get("/password-requests", auth, async (req, res) => {
        try { const [rows] = await db.query("SELECT * FROM password_requests WHERE status='Pending' ORDER BY id DESC"); res.json(rows); }
        catch (err) { res.status(500).json({ message: "Could not load requests" }); }
    });

    router.post("/password-requests/:id/dismiss", auth, async (req, res) => {
        try { await db.query("UPDATE password_requests SET status='Dismissed' WHERE id=?", [req.params.id]); res.json({ message: "Dismissed" }); }
        catch (err) { res.status(500).json({ message: "Could not dismiss request" }); }
    });

    router.post("/employees/:id/reset-password", auth, async (req, res) => {
        try {
            const password = tempPassword();
            const [r] = await db.query(
                "UPDATE employees SET password=?, must_change_password=1, token_version=token_version+1 WHERE id=?",
                [await bcrypt.hash(password, 10), req.params.id]);
            if (!r.affectedRows) return res.status(404).json({ message: "Employee not found" });
            await db.query("UPDATE password_requests SET status='Done' WHERE employee_id=? AND status='Pending'", [req.params.id]);
            const [[e]] = await db.query("SELECT name, username, email, role FROM employees WHERE id=?", [req.params.id]);
            res.json({ employee: e, credentials: { username: e.username, password } });
        } catch (err) { res.status(500).json({ message: "Could not reset password" }); }
    });

    // ---------- delete own portal account (needs the password) ----------
    router.post("/account/delete", auth, async (req, res) => {
        const password = String((req.body || {}).password || "");
        if (!password) return res.status(400).json({ message: "Enter your password to confirm" });
        const key = "delacc|" + req.admin.id;
        if (blocked(key)) return res.status(429).json({ message: "Too many wrong attempts. Try again in 15 minutes." });
        try {
            if (!(await bcrypt.compare(password, req.admin.password))) {
                fail(key);
                return res.status(403).json({ message: "Wrong password" });   // 403, not 401, so the page does not log out
            }
            await db.query("DELETE FROM portal_users WHERE id=?", [req.admin.id]);
            fails.delete(key);
            res.json({ message: "Account deleted" });
        } catch (err) {
            console.error("Delete account error:", err);
            res.status(500).json({ message: "Could not delete account" });
        }
    });

    return router;
};