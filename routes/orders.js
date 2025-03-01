const express = require('express');
const router = express.Router();
const dbSingleton = require('../dbSingleton');
const db = dbSingleton.getConnection();

// API to create an order
router.post('/', (req, res) => {
  const { user_id, user_name, product_id, product_name } = req.body;

  console.log('Received order request:', req.body); // ✅ הדפסת הנתונים המתקבלים

  if (!user_id || !user_name || !product_id || !product_name) {
    console.error('Missing order details:', req.body);
    return res.status(400).json({ error: 'Missing order details', receivedData: req.body });
  }

  const query = 'INSERT INTO orders (user_id, user_name, product_id, product_name, created_at) VALUES (?, ?, ?, ?, NOW())';
  db.query(query, [user_id, user_name, product_id, product_name], (err, result) => {
    if (err) {
      console.error('Database error:', err);
      return res.status(500).json({ error: 'Database error', details: err.message });
    }
    res.status(201).json({ message: 'Order added successfully', orderId: result.insertId });
  });
});



module.exports = router;
