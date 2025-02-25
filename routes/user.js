const express = require('express');
const bcrypt = require('bcrypt');
const router = express.Router();
const dbSingleton = require('../dbSingleton');
const db = dbSingleton.getConnection();

router.post('/register', (req, res) => {
  const { name, email, password } = req.body;
  if (!name || !email || !password) {
    return res.status(400).json({ error: 'All fields are required' });
  }

  bcrypt.hash(password, 10, (err, hashedPassword) => {
    if (err) return res.status(500).json({ error: 'Error hashing password', details: err });

    const query = 'INSERT INTO users (name, email, password_hash) VALUES (?, ?, ?)';
    db.query(query, [name, email, hashedPassword], (err, result) => {
      if (err) return res.status(500).json({ error: 'Database error', details: err });
      res.status(201).json({ message: 'User registered successfully', id: result.insertId });
    });
  });
});

router.get('/users/:id', (req, res) => {
  const userId = req.params.id;
  const query = 'SELECT id, name, email, profile_picture, role FROM users WHERE id = ?';
  db.query(query, [userId], (err, results) => {
    if (err) return res.status(500).json({ error: 'Database error', details: err });
    if (results.length === 0) return res.status(404).json({ error: 'User not found' });
    res.json(results[0]);
  });
});

router.post('/login', (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) {
    return res.status(400).json({ error: 'Email and password are required' });
  }

  const query = 'SELECT id, name, email, profile_picture, role, password_hash FROM users WHERE email = ?';
  db.query(query, [email], (err, results) => {
    if (err) return res.status(500).json({ error: 'Database error', details: err });
    if (results.length === 0) return res.status(401).json({ error: 'Invalid email or password' });

    const user = results[0];
    bcrypt.compare(password, user.password_hash, (compareErr, isMatch) => {
      if (compareErr) return res.status(500).json({ error: 'Error comparing passwords', details: compareErr });
      if (!isMatch) return res.status(401).json({ error: 'Invalid email or password' });

      req.session.user = {
        id: user.id,
        name: user.name,
        role: user.role
      };

      res.cookie('role', user.role, { httpOnly: true });

      res.json({
        message: 'You have successfully logged in.',
        user: {
          id: user.id,
          name: user.name,
          email: user.email,
          profile_picture: user.profile_picture,
          role: user.role
        }
      });
    });
  });
});



router.post('/logout', (req, res) => {
  req.session.destroy((err) => {
    if (err) {
      return res.status(500).json({ error: 'Logout failed', details: err });
    }

    res.clearCookie('role'); 
    res.json({ message: 'Logout successful' });
  });
});


router.put('/users/:id', (req, res) => {
  const { name, email } = req.body;
  const userId = req.params.id;

  if (!name || !email) {
    return res.status(400).json({ error: 'All fields are required' });
  }

  const query = 'UPDATE users SET name = ?, email = ? WHERE id = ?';
  db.query(query, [name, email, userId], (err, result) => {
    if (err) return res.status(500).json({ error: 'Database error', details: err });

    res.json({ message: 'User updated successfully' });
  });
});


router.delete('/users/:id', (req, res) => {
  const userId = req.params.id;

  const deleteQuery = 'DELETE FROM users WHERE id = ?';
  db.query(deleteQuery, [userId], (err, result) => {
    if (err) return res.status(500).json({ error: 'Database error', details: err });

    res.json({ message: 'User deleted successfully' });
  });
});

module.exports = router;
