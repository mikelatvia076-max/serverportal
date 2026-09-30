// AGNES MEMORIAL - HOSPITAL STAFF LOGIN API (mounted at /staff)
// Used by hospital-login.html / login.js. Reads the `employees` table that the
// Staff Portal fills in: login with username + password + role, first-login
// password change, and forgot-password requests (shown in the portal).
const express = require("express");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const crypto = require("crypto");
const db = require("./database").promise();

const DUMMY_HASH = bcrypt.hashSync("not-a-real-password", 10);
const now = () => new Date().toISOString().slice(0, 16).replace("T", " ");
const strong = (p) => typeof p === "string" && p.length >= 8 && /[A-Za-z]/.test(p) && /\d/.test(p);
const view = (e) => ({
    id: e.id, employee_id: e.employee_id, name: e.name, username: e.username, email: e.email,
    role: e.role, department: e.department, must_change_password: !!e.must_change_password
});

module.exports = function (JWT_SECRET) {
    const router = express.Router();

    // A temporary-password login only gets a "pending" token, signed with a different key,
    // so it can open nothing except /change-password.
    const PENDING_SECRET = JWT_SECRET + "|pending";
    const signStaff = (e) => jwt.sign({ id: e.id, role: e.role, type: "staff", tv: e.token_version || 0 }, JWT_SECRET, { expiresIn: "12h" });
    const signPending = (e) => jwt.sign({ id: e.id, type: "staff-pending", tv: e.token_version || 0 }, PENDING_SECRET, { expiresIn: "15m" });

    // ---- lockout after 5 failed attempts (15 minutes) ----
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

    async function tokenEmployee(token, secret) {
        const d = jwt.verify(token, secret);
        const [[e]] = await db.query("SELECT * FROM employees WHERE id=?", [d.id]);
        // password reset / change bumps token_version, which logs old tokens out
        if (!e || e.status !== "Active" || (e.token_version || 0) !== (d.tv || 0)) throw new Error("invalid");
        return e;
    }

    // ---------- login ----------
    router.post("/login", async (req, res) => {
        const { username, password, role } = req.body || {};
        if (!username || !password || !role) return res.status(400).json({ message: "Username, password and role are required" });
        const u = String(username).trim().toLowerCase();
        const key = req.ip + "|" + u;
        if (blocked(key)) return res.status(429).json({ message: "Too many failed attempts. Try again in 15 minutes." });
        try {
            const [[e]] = await db.query("SELECT * FROM employees WHERE username=?", [u]);
            const ok = await bcrypt.compare(String(password), e ? e.password : DUMMY_HASH);
            if (!e || !ok) { fail(key); return res.status(401).json({ message: "Invalid login details" }); }
            if (e.status && e.status !== "Active") return res.status(403).json({ message: "This account is not active. Contact the administrator." });
            if (e.role !== role) return res.status(403).json({ message: "The selected role does not match this account" });

            fails.delete(key);
            await db.query("UPDATE employees SET last_login=? WHERE id=?", [now(), e.id]);

            if (e.must_change_password) return res.json({ token: signPending(e), employee: view(e) });
            res.json({ token: signStaff(e), employee: view(e) });
        } catch (err) {
            console.error("Staff login error:", err);
            res.status(500).json({ message: "Server error. Try again." });
        }
    });

    // ---------- first login: choose own password ----------
    router.post("/change-password", async (req, res) => {
        const token = (req.headers.authorization || "").split(" ")[1];
        const { current_password, new_password } = req.body || {};
        if (!token) return res.status(401).json({ message: "Please log in again" });
        if (!strong(new_password)) return res.status(400).json({ message: "Password needs 8+ characters with letters and numbers" });
        try {
            let e;
            try { e = await tokenEmployee(token, PENDING_SECRET); }
            catch (err) { e = await tokenEmployee(token, JWT_SECRET); } // already-logged-in staff can change too
            if (!(await bcrypt.compare(String(current_password || ""), e.password)))
                return res.status(401).json({ message: "Current password is wrong" });
            if (current_password === new_password)
                return res.status(400).json({ message: "Choose a different password from the temporary one" });

            await db.query("UPDATE employees SET password=?, must_change_password=0, token_version=token_version+1 WHERE id=?",
                [await bcrypt.hash(new_password, 10), e.id]);
            const [[fresh]] = await db.query("SELECT * FROM employees WHERE id=?", [e.id]);
            res.json({ message: "Password changed", token: signStaff(fresh), employee: view(fresh) });
        } catch (err) {
            if (err.name === "JsonWebTokenError" || err.name === "TokenExpiredError" || err.message === "invalid")
                return res.status(401).json({ message: "Session expired. Please log in again." });
            console.error("Change password error:", err);
            res.status(500).json({ message: "Could not change password" });
        }
    });

    // ---------- forgot password: shows up in the Staff Portal for the admin ----------
    router.post("/forgot-password", async (req, res) => {
        const { username, email } = req.body || {};
        const reply = { message: "If those details match a staff account, the administrator has been told and will give you a new temporary password." };
        if (!username || !email) return res.status(400).json({ message: "Enter your username and email" });
        const key = "forgot|" + req.ip;
        if (blocked(key)) return res.status(429).json({ message: "Too many requests. Try again later." });
        fail(key);
        try {
            const [[e]] = await db.query("SELECT id, name, username FROM employees WHERE username=? AND email=?",
                [String(username).trim().toLowerCase(), String(email).trim().toLowerCase()]);
            if (e) {
                const [[open]] = await db.query("SELECT id FROM password_requests WHERE employee_id=? AND status='Pending'", [e.id]);
                if (!open) await db.query("INSERT INTO password_requests (employee_id, name, username, created_at, status) VALUES (?, ?, ?, ?, 'Pending')",
                    [e.id, e.name, e.username, now()]);
            }
            res.json(reply);
        } catch (err) {
            console.error("Forgot password error:", err);
            res.status(500).json({ message: "Server error. Try again." });
        }
    });

    // ---------- who am I (check a saved staff token) ----------
    router.get("/me", async (req, res) => {
        try {
            const e = await tokenEmployee((req.headers.authorization || "").split(" ")[1], JWT_SECRET);
            res.json({ employee: view(e) });
        } catch (err) { res.status(401).json({ message: "Session expired. Please log in again." }); }
    });

    return router;
};