const express = require('express');
const bcrypt = require('bcrypt');
const path = require('path');
const router = express.Router();
const multer = require('multer');
const dbSingleton = require('../dbSingleton');
const db = dbSingleton.getConnection();

const storage = multer.diskStorage({
  destination: function (req, file, cb) {
    cb(null, 'uploads/');
  },
  filename: function (req, file, cb) {
    cb(null, Date.now() + path.extname(file.originalname));
  },
});

const upload = multer({ storage: storage });

router.get('/', (req, res) => {
  const query = 'SELECT id, name, username, email, role, profile_picture FROM users';
  db.query(query, (err, results) => {
    if (err) return res.status(500).json({ error: 'Database error', details: err });
    res.json(results);
  });
});


router.post('/register', (req, res) => {
  const { name, username, email, password } = req.body;
  if (!name || !username || !email || !password) {
    return res.status(400).json({ error: 'All fields are required' });
  }

  
  const checkQuery = 'SELECT id FROM users WHERE username = ? OR email = ?';
  db.query(checkQuery, [username, email], (err, results) => {
    if (err) return res.status(500).json({ error: 'Database error', details: err });

    if (results.length > 0) {
      return res.status(400).json({ error: 'Username or email already exists' });
    }

 
    bcrypt.hash(password, 10, (err, hashedPassword) => {
      if (err) return res.status(500).json({ error: 'Error hashing password', details: err });

      const insertQuery = 'INSERT INTO users (name, username, email, password_hash) VALUES (?, ?, ?, ?)';
      db.query(insertQuery, [name, username, email, hashedPassword], (err, result) => {
        if (err) return res.status(500).json({ error: 'Database error', details: err });
        res.status(201).json({ message: 'User registered successfully', id: result.insertId });
      });
    });
  });
});





router.post('/login', (req, res) => {
  const { username, email, password } = req.body;
  if (!username || !email || !password) {
    return res.status(400).json({ error: 'Username, email, and password are required' });
  }

  const query = 'SELECT id, name, username, email, profile_picture, role, password_hash FROM users WHERE username = ? AND email = ?';
  db.query(query, [username, email], (err, results) => {
    if (err) return res.status(500).json({ error: 'Database error', details: err });
    if (results.length === 0) return res.status(401).json({ error: 'Invalid username, email, or password' });

    const user = results[0];
    bcrypt.compare(password, user.password_hash, (compareErr, isMatch) => {
      if (compareErr) return res.status(500).json({ error: 'Error comparing passwords', details: compareErr });
      if (!isMatch) return res.status(401).json({ error: 'Invalid username, email, or password' });

      req.session.user = {
        id: user.id,
        name: user.name,
        username: user.username,
        profile_picture: user.profile_picture,
        email: user.email,
        role: user.role
      };

      res.cookie('role', user.role, {
        httpOnly: true
      });

      res.json({
        message: 'Login successful',
        user: req.session.user
      });
    });
  });
});


router.get('/current', (req, res) => {
  if (!req.session.user) {
    return res.status(401).json({ error: 'Not authenticated' });
  }

  const query = 'SELECT id, name, username, email, profile_picture, role FROM users WHERE id = ?';
  db.query(query, [req.session.user.id], (err, results) => {
    if (err) return res.status(500).json({ error: 'Database error', details: err });
    if (results.length === 0) {
      req.session.destroy(); // אם המשתמש נמחק, ננקה את הסשן
      return res.status(404).json({ error: 'User not found' });
    }

    req.session.user = results[0];
    res.json(req.session.user); 
  });
});




router.post('/logout', (req, res) => {
  req.session.destroy((err) => {
    if (err) return res.status(500).json({ error: 'Logout failed', details: err });

    res.clearCookie('role');
    res.json({ message: 'Logout successful' });
  });
});



router.put('/:id', upload.single('profile_picture'), (req, res) => {
  const { id } = req.params;
  const { name, username, email } = req.body;
  const profile_picture = req.file ? `/uploads/${req.file.filename}` : null;

  if (!name || !username || !email) {
    return res.status(400).json({ error: 'All fields are required' });
  }

  
  const checkQuery = 'SELECT id FROM users WHERE (username = ? OR email = ?) AND id != ?';
  db.query(checkQuery, [username, email, id], (err, results) => {
    if (err) return res.status(500).json({ error: 'Database error', details: err });

    if (results.length > 0) {
      return res.status(400).json({ error: 'Username or email already taken' });
    }


    let query, params;

    if (profile_picture) {
      query = 'UPDATE users SET name = ?, username = ?, email = ?, profile_picture = ? WHERE id = ?';
      params = [name, username, email, profile_picture, id];
    } else {
      query = 'UPDATE users SET name = ?, username = ?, email = ? WHERE id = ?';
      params = [name, username, email, id];
    }

    db.query(query, params, (err, result) => {
      if (err) return res.status(500).json({ error: 'Database error', details: err });
      res.json({ message: 'User updated successfully', profile_picture });
    });
  });
});


router.delete('/:id', (req, res) => {
  const userId = req.params.id;

  const deleteQuery = 'DELETE FROM users WHERE id = ?';
  db.query(deleteQuery, [userId], (err, result) => {
    if (err) return res.status(500).json({ error: 'Database error', details: err });

    res.json({ message: 'User deleted successfully' });
  });
});

router.post('/verify', (req, res) => {
  const { email, password } = req.body;

  if (!email || !password) {
    return res.status(400).json({ error: 'Email and password are required' });
  }

  const query = 'SELECT id, password_hash FROM users WHERE email = ?';
  db.query(query, [email], (err, results) => {
    if (err) return res.status(500).json({ error: 'Database error', details: err });
    if (results.length === 0) return res.status(401).json({ error: 'Invalid email or password' });

    const user = results[0];
    bcrypt.compare(password, user.password_hash, (compareErr, isMatch) => {
      if (compareErr) return res.status(500).json({ error: 'Error comparing passwords', details: compareErr });
      if (!isMatch) return res.status(401).json({ error: 'Invalid email or password' });

      res.json({ valid: true });
    });
  });
});


module.exports = router;
