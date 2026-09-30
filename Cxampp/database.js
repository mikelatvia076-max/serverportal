// =================================
// AGNES MEMORIAL HOSPITAL DATABASE
// =================================

const mysql = require("mysql2");

// ---- ORIGINAL (single connection) - kept for reference ----
// const db = mysql.createConnection({
//     host: process.env.DB_HOST || "localhost",
//     user: process.env.DB_USER || "root",
//     password: process.env.DB_PASSWORD || "",
//     database: process.env.DB_NAME || "agnes_hospital",
//     port: process.env.DB_PORT || 3306,
//     dateStrings: true
// });
//
// db.connect((err)=>{
//     if(err){
//         console.log("Database connection failed");
//         console.log(err);
//     }
//     else{
//         console.log("Database connected successfully");
//     }
// });

// ---- CORRECTED: connection pool ----
// A single connection gets closed by cloud MySQL after a while of no use
// and then every login fails. A pool reconnects by itself. db.query(...)
// is used exactly the same way, so server.js needs no change.
//
// Cloud databases (Aiven, TiDB Cloud, PlanetScale, Railway...) usually need
// SSL. On your host set DB_SSL=true to turn it on.
const db = mysql.createPool({
    host: process.env.DB_HOST || "localhost",
    user: process.env.DB_USER || "root",
    password: process.env.DB_PASSWORD || "",
    database: process.env.DB_NAME || "agnes_hospital",
    port: process.env.DB_PORT || 3306,
    dateStrings: true,
    waitForConnections: true,
    connectionLimit: 10,
    enableKeepAlive: true,
    ssl: process.env.DB_SSL === "true" ? { rejectUnauthorized: false } : undefined
});

db.getConnection((err, connection)=>{
    if(err){
        console.log("Database connection failed");
        console.log(err);
    }
    else{
        console.log("Database connected successfully");
        connection.release();
    }
});

// ---- AUTO-CREATE TABLES (added) ----
// A new cloud database starts empty. These statements create every table
// server.js uses, only if it does not exist yet, so they are safe to run on
// every start and never touch data that is already there.
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
) CHARACTER SET utf8mb4`

];

let tablesDone = 0;

tableStatements.forEach((sql)=>{
    db.query(sql, (err)=>{
        if(err){
            console.log("Table setup error:", err.message);
        }
        tablesDone++;
        if(tablesDone === tableStatements.length){
            console.log("Database tables checked / created");
        }
    });
});

module.exports = db;