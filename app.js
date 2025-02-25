const express = require('express');
const session = require('express-session');

const app = express();

const userRoutes = require('./routes/user');
const productRoutes = require('./routes/products');
const port = 8801;

app.use(express.json());
app.use('/uploads', express.static('uploads'));
app.use('/users', userRoutes);
app.use('/products', productRoutes);

app.use(session({
  secret: 'your_secret_key', 
  resave: false,
  saveUninitialized: false,
  cookie: { secure: false, httpOnly: true }
}));


app.use((err, req, res, next) => {
  console.error(err); // Log error
  res.status(500).json({
    error: 'Internal Server Error',
    message: err.message,
  });
});

app.listen(port, () => {
  console.log(`Server is running on http://localhost:${port}`);
});