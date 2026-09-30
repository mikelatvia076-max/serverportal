// =================================
// AGNES MEMORIAL HOSPITAL DATABASE  (hospital backend)
// Shared MySQL database: the Staff Portal writes the "employees" and
// "password_requests" tables, this backend reads them. Both tables are
// created here too, with the SAME columns as the portal, so it does not
// matter which service starts first.
// =================================

const mysql = require("mysql2");

// Pool: reconnects by itself (a single connection is dropped by cloud MySQL).
// Cloud databases (Aiven, TiDB Cloud, Railway...) usually need SSL: set DB_SSL=true.
const db = mysql.createPool({
    host: process.env.DB_HOST || "localhost",
    user: process.env.DB_USER || "root",
    password: process.env.DB_PASSWORD || "",
    database: process.env.DB_NAME || "agnes_hospital",
    port: Number(process.env.DB_PORT) || 3306,
    dateStrings: true,
    waitForConnections: true,
    connectionLimit: 10,
    queueLimit: 0,
    enableKeepAlive: true,
    ssl: process.env.DB_SSL === "true" ? { rejectUnauthorized: false } : undefined
});

db.getConnection((err, connection) => {
    if (err) {
        console.log("Database connection failed");
        console.log(err);
    } else {
        console.log("Database connected successfully");
        connection.release();
    }
});

// ---- AUTO-CREATE TABLES (safe to run on every start) ----
const tableStatements = [

`CREATE TABLE IF NOT EXISTS users (
    id INT AUTO_INCREMENT PRIMARY KEY,
    patient_id VARCHAR(50) NOT NULL UNIQUE,
    name VARCHAR(150),
    email VARCHAR(191) NOT NULL UNIQUE,
    phone VARCHAR(30),
    password VARCHAR(255) NOT NULL
) CHARACTER SET utf8mb4`,

`CREATE TABLE IF NOT EXISTS patients (
    id INT AUTO_INCREMENT PRIMARY KEY,
    patient_id VARCHAR(50),
    name VARCHAR(150),
    age INT NULL,
    gender VARCHAR(20) NULL,
    phone VARCHAR(30),
    email VARCHAR(191),
    address VARCHAR(255) NULL,
    status VARCHAR(30) DEFAULT 'Active',
    registered VARCHAR(30),
    password VARCHAR(255) NULL
) CHARACTER SET utf8mb4`,

`CREATE TABLE IF NOT EXISTS appointments (
    id INT AUTO_INCREMENT PRIMARY KEY,
    patient_id VARCHAR(50),
    patient_name VARCHAR(150),
    email VARCHAR(191),
    department VARCHAR(100),
    staff VARCHAR(150),
    date VARCHAR(50),
    time VARCHAR(50),
    reason TEXT,
    status VARCHAR(30) DEFAULT 'Pending',
    deleted_by_hospital TINYINT DEFAULT 0,
    deleted_by_patient TINYINT DEFAULT 0
) CHARACTER SET utf8mb4`,

`CREATE TABLE IF NOT EXISTS notifications (
    id INT AUTO_INCREMENT PRIMARY KEY,
    patient_id VARCHAR(50),
    title VARCHAR(255),
    message TEXT,
    user_type VARCHAR(30) DEFAULT 'Patient',
    created_at VARCHAR(30),
    status VARCHAR(20) DEFAULT 'unread'
) CHARACTER SET utf8mb4`,

`CREATE TABLE IF NOT EXISTS hospital_notifications (
    id INT AUTO_INCREMENT PRIMARY KEY,
    patient_name VARCHAR(150),
    staff VARCHAR(150),
    date VARCHAR(50),
    created_at VARCHAR(30),
    type VARCHAR(100) DEFAULT 'Appointment Request',
    is_read TINYINT DEFAULT 0
) CHARACTER SET utf8mb4`,

`CREATE TABLE IF NOT EXISTS doctors (
    id INT AUTO_INCREMENT PRIMARY KEY,
    doctor_id VARCHAR(50),
    name VARCHAR(150),
    specialization VARCHAR(150),
    department VARCHAR(100),
    phone VARCHAR(30),
    email VARCHAR(191),
    availability VARCHAR(100)
) CHARACTER SET utf8mb4`,

`CREATE TABLE IF NOT EXISTS nurses (
    id INT AUTO_INCREMENT PRIMARY KEY,
    nurse_id VARCHAR(50),
    name VARCHAR(150),
    department VARCHAR(100),
    phone VARCHAR(30),
    email VARCHAR(191),
    shift VARCHAR(50),
    status VARCHAR(30)
) CHARACTER SET utf8mb4`,

// ---- shared with the Staff Portal (must match portal-api.js) ----
`CREATE TABLE IF NOT EXISTS portal_users (
    id INT AUTO_INCREMENT PRIMARY KEY,
    name VARCHAR(150) NOT NULL,
    username VARCHAR(60) NOT NULL UNIQUE,
    password VARCHAR(255) NOT NULL,
    created_at VARCHAR(30),
    last_login VARCHAR(30)
) CHARACTER SET utf8mb4`,

`CREATE TABLE IF NOT EXISTS employees (
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
) CHARACTER SET utf8mb4`,

`CREATE TABLE IF NOT EXISTS password_requests (
    id INT AUTO_INCREMENT PRIMARY KEY,
    employee_id INT NOT NULL,
    name VARCHAR(150),
    username VARCHAR(60),
    created_at VARCHAR(30),
    status VARCHAR(20) DEFAULT 'Pending'
) CHARACTER SET utf8mb4`

];

let tablesDone = 0;
tableStatements.forEach((sql) => {
    db.query(sql, (err) => {
        if (err) console.log("Table setup error:", err.message);
        tablesDone++;
        if (tablesDone === tableStatements.length) console.log("Database tables checked / created");
    });
});

module.exports = db;