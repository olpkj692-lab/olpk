const express = require("express");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const multer = require("multer");
const path = require("path");

const app = express();

app.use(express.json());
app.use(express.static("public"));
app.use("/uploads", express.static("uploads"));

const SECRET = "youtube_secret_key";

let users = [];

const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    cb(null, "uploads/");
  },
  filename: (req, file, cb) => {
    cb(null, Date.now() + "-" + file.originalname);
  }
});

const upload = multer({ storage });

app.post("/register", async (req, res) => {
  const { username, password } = req.body;

  const hash = await bcrypt.hash(password, 10);

  users.push({
    username,
    password: hash
  });

  res.json({ message: "Account created" });
});

app.post("/login", async (req, res) => {
  const { username, password } = req.body;

  const user = users.find(u => u.username === username);

  if (!user)
    return res.status(401).json({ message: "User not found" });

  const valid = await bcrypt.compare(
    password,
    user.password
  );

  if (!valid)
    return res.status(401).json({ message: "Wrong password" });

  const token = jwt.sign(
    { username },
    SECRET,
    { expiresIn: "24h" }
  );

  res.json({ token });
});

function auth(req, res, next) {
  const token = req.headers.authorization;

  if (!token)
    return res.sendStatus(401);

  try {
    jwt.verify(token, SECRET);
    next();
  } catch {
    res.sendStatus(403);
  }
}

app.post(
  "/upload",
  auth,
  upload.single("video"),
  (req, res) => {
    res.json({
      success: true,
      file: req.file.filename
    });
  }
);

app.listen(3000, () =>
  console.log("Server running on 3000")
);