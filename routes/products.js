const express = require('express');
const multer = require('multer');
const path = require('path');
const router = express.Router();
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

router.get('/', (req, res, next) => {
  db.query('SELECT * FROM products', (err, results) => {
    if (err) return next(err);
    res.json(results);
  });
});

// API for creating an order
router.post('/orders', (req, res) => {
  const { user_id, items } = req.body;

  if (!user_id || !Array.isArray(items) || items.length === 0) {
    return res.status(400).json({ error: 'Invalid request payload' });
  }

  // Extract product IDs and check their existence
  const productIds = items.map(item => item.product_id);
  const checkProductsQuery = 'SELECT id, price, stock FROM products WHERE id IN (?)';

  db.query(checkProductsQuery, [productIds], (err, result) => {
    if (err) {
      return res.status(500).json({ error: 'Failed to check products' });
    }

    const existingProducts = Object.fromEntries(result.map(product => [product.id, product]));
    const invalidProductIds = productIds.filter(id => !existingProducts[id]);

    if (invalidProductIds.length > 0) {
      return res.status(400).json({
        error: `Invalid product IDs: ${invalidProductIds.join(', ')}`,
      });
    }

    // Validate stock availability
    const outOfStockItems = items.filter(item => existingProducts[item.product_id].stock < item.quantity);
    if (outOfStockItems.length > 0) {
      return res.status(400).json({
        error: `Insufficient stock for product IDs: ${outOfStockItems.map(i => i.product_id).join(', ')}`,
      });
    }

    // Start transaction
    db.beginTransaction((err) => {
      if (err) return res.status(500).json({ error: 'Transaction error' });

      // Insert order
      const orderQuery = 'INSERT INTO orders (user_id) VALUES (?)';
      db.query(orderQuery, [user_id], (err, result) => {
        if (err) {
          db.rollback(() => res.status(500).json({ error: 'Order creation failed' }));
          return;
        }

        const orderId = result.insertId;
        const orderItems = items.map(item => [orderId, item.product_id, item.quantity, existingProducts[item.product_id].price]);
        const itemsQuery = 'INSERT INTO order_items (order_id, product_id, quantity, price) VALUES ?';

        db.query(itemsQuery, [orderItems], (err) => {
          if (err) {
            db.rollback(() => res.status(500).json({ error: 'Order items creation failed' }));
            return;
          }

          // Update stock levels
          const stockUpdates = items.map(item => {
            return new Promise((resolve, reject) => {
              const updateStockQuery = 'UPDATE products SET stock = stock - ? WHERE id = ?';
              db.query(updateStockQuery, [item.quantity, item.product_id], (err) => {
                if (err) reject(err);
                else resolve();
              });
            });
          });

          Promise.all(stockUpdates)
            .then(() => {
              db.commit((err) => {
                if (err) {
                  db.rollback(() => res.status(500).json({ error: 'Transaction commit failed' }));
                  return;
                }
                res.status(201).json({ message: 'Order created successfully', orderId });
              });
            })
            .catch(() => {
              db.rollback(() => res.status(500).json({ error: 'Stock update failed' }));
            });
        });
      });
    });
  });
});

router.post('/', upload.single('image'), (req, res, next) => {
  console.log('Received request:', req.body); 
  console.log('Received file:', req.file); 

  const { name, description, detailedDescription, instruction, type, price, stock } = req.body;
  const image = req.file ? `/uploads/${req.file.filename}` : null;

  if (!name || !image || !description || !detailedDescription || !type || !price || stock === undefined) {
    return res.status(400).json({ error: 'Missing required fields' });
  }

  const query = 'INSERT INTO products (name, image, description, detailedDescription, instruction, type, price, stock) VALUES (?, ?, ?, ?, ?, ?, ?, ?)';
  db.query(query, [name, image, description, detailedDescription, instruction, type, price, stock], (err, result) => {
    if (err) return next(err);
    res.status(201).json({ message: 'Product added successfully', id: result.insertId });
  });
});



router.put('/:id', (req, res, next) => {
  const { id } = req.params;
  const { name, description, detailedDescription, instruction, type, price, image, stock } = req.body;

  if (stock !== undefined && isNaN(stock)) {
    return res.status(400).json({ error: 'Stock must be a number' });
  }

  const query = 'UPDATE products SET name=?, description=?, detailedDescription=?, instruction=?, type=?, price=?, image=?, stock=? WHERE id=?';
  db.query(query, [name, description, detailedDescription, instruction, type, price, image, stock, id], (err, result) => {
    if (err) return next(err);
    res.json({ message: 'Product updated successfully' });
  });
});


router.delete('/:id', (req, res, next) => {
  const { id } = req.params;
  const query = 'DELETE FROM products WHERE id=?';
  db.query(query, [id], (err, result) => {
    if (err) return next(err);
    res.json({ message: 'Product deleted successfully' });
  });
});



module.exports = router;