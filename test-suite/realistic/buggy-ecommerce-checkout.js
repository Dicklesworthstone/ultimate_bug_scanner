// ============================================================================
// REALISTIC SCENARIO: E-COMMERCE CHECKOUT (BUGGY CODE)
// Expected: 35+ issues across security, concurrency, validation, performance
// This simulates a real e-commerce checkout flow with multiple critical bugs
// ============================================================================

const express = require("express");
const router = express.Router();

// Global state - BAD!
var cart = {}; // BUG: Using var + global mutable state
var inventory = {};
const processingOrders = []; // Memory leak

// BUG: Hardcoded credentials
const PAYMENT_API_KEY = "sk_live_payment_key_12345";
const STRIPE_SECRET = "sk_test_abc123";

// BUG: No input validation, SQL injection
router.post("/cart/add", (req, res) => {
  const productId = req.body.productId;
  const quantity = req.body.quantity;

  // BUG: No authentication check
  const userId = req.cookies.userId; // Trusting client!

  // BUG: SQL injection
  const query = `INSERT INTO cart (user_id, product_id, quantity) VALUES (${userId}, ${productId}, ${quantity})`;
  db.query(query);

  // BUG: Race condition - inventory check and decrement not atomic
  const product = inventory[productId];
  if (product.stock >= quantity) {
    product.stock -= quantity; // Not atomic!
    res.json({ success: true });
  } else {
    res.json({ error: "Out of stock" });
  }
});

// BUG: Price calculation on client side
router.post("/cart/update-price", (req, res) => {
  const itemId = req.body.itemId;
  const newPrice = req.body.price; // CLIENT CAN SET PRICE!

  // BUG: Direct price manipulation
  cart[itemId].price = newPrice;
  res.json({ success: true });
});

// BUG: No transaction, multiple database operations without rollback
router.post("/checkout", async (req, res) => {
  const userId = req.body.userId; // No auth token verification

  // BUG: Retrieving price from client
  const total = req.body.total; // CLIENT CALCULATES TOTAL!

  // BUG: No validation of cart contents
  const cartItems = req.body.items;

  // BUG: Logging sensitive data
  console.log("Processing payment:", req.body.creditCard);
  console.log("CVV:", req.body.cvv);

  // BUG: Multiple queries without transaction
  await db.query(
    `UPDATE inventory SET stock = stock - ${cartItems[0].quantity} WHERE id = ${cartItems[0].id}`,
  );
  await db.query(`INSERT INTO orders (user_id, total) VALUES (${userId}, ${total})`);
  const order = await db.query(
    `SELECT * FROM orders WHERE user_id = ${userId} ORDER BY id DESC LIMIT 1`,
  );

  // BUG: Processing payment after inventory update (should be before!)
  const payment = await processPayment({
    amount: total,
    card: req.body.creditCard,
  });

  if (!payment.success) {
    // BUG: No rollback! Inventory already decremented
    res.json({ error: "Payment failed" });
    return;
  }

  // BUG: Race condition - multiple checkouts
  processingOrders.push(order); // Grows forever

  res.json({ orderId: order.id, success: true });
});

// BUG: Trusting client-side coupon validation
router.post("/apply-coupon", (req, res) => {
  const coupon = req.body.couponCode;
  const discount = req.body.discountAmount; // CLIENT SETS DISCOUNT!

  // BUG: No server-side validation
  cart.discount = discount;

  res.json({ success: true, discount });
});

// BUG: No authentication, anyone can view any order
router.get("/order/:orderId", (req, res) => {
  const query = `SELECT * FROM orders WHERE id = ${req.params.orderId}`;
  db.query(query, (err, order) => {
    // BUG: Exposing sensitive data
    res.json({
      order,
      creditCard: order.credit_card_number,
      cvv: order.cvv,
    });
  });
});

// BUG: TOCTOU (Time-of-check Time-of-use)
router.post("/reserve-product", async (req, res) => {
  const productId = req.body.productId;
  const quantity = req.body.quantity;

  // Check stock
  const product = await db.query(`SELECT stock FROM products WHERE id = ${productId}`);

  if (product.stock >= quantity) {
    // BUG: Race window - another request could reserve same stock
    await delay(100); // Simulate processing

    // Update stock
    await db.query(`UPDATE products SET stock = stock - ${quantity} WHERE id = ${productId}`);
    res.json({ success: true });
  } else {
    res.json({ error: "Insufficient stock" });
  }
});

// BUG: Weak session management
router.post("/create-session", (req, res) => {
  const userId = req.body.userId;

  // BUG: Predictable session ID
  const sessionId = `${userId}-${Date.now()}`;

  // BUG: Storing session in global variable
  cart[sessionId] = { userId, items: [] };

  res.json({ sessionId });
});

// BUG: No HTTPS enforcement, sending sensitive data
router.post("/save-payment-method", (req, res) => {
  const userId = req.body.userId;
  const creditCard = req.body.creditCard;

  // BUG: Storing credit card in plain text
  db.query(`UPDATE users SET credit_card = '${creditCard}' WHERE id = ${userId}`);

  res.json({ success: true });
});

// BUG: Infinite loop potential
router.get("/calculate-tax", (req, res) => {
  const total = parseFloat(req.query.total);
  let tax = 0;

  // BUG: Division by zero if total is 0
  while (tax < total / 0) {
    // Infinite loop!
    tax += 0.08 * total;
  }

  res.json({ tax });
});

// BUG: Callback hell + no error handling
router.post("/process-refund", (req, res) => {
  const orderId = req.body.orderId;

  db.query(`SELECT * FROM orders WHERE id = ${orderId}`, (err1, order) => {
    db.query(`SELECT * FROM payments WHERE order_id = ${orderId}`, (err2, payment) => {
      refundPayment(payment.id, (err3, refund) => {
        db.query(`UPDATE orders SET status = 'refunded' WHERE id = ${orderId}`, (err4, result) => {
          db.query(
            `UPDATE inventory SET stock = stock + ${order.quantity} WHERE product_id = ${order.product_id}`,
            (err5, updated) => {
              res.json({ success: true });
            },
          );
        });
      });
    });
  });
  // No error handling anywhere!
});

// BUG: Mass assignment vulnerability
router.post("/update-order", (req, res) => {
  const orderId = req.body.orderId;

  // BUG: User can modify any field, including price, status, etc.
  const updates = req.body;

  const fields = Object.keys(updates)
    .map((key) => `${key} = '${updates[key]}'`)
    .join(", ");
  db.query(`UPDATE orders SET ${fields} WHERE id = ${orderId}`);

  res.json({ success: true });
});

// BUG: Insufficient rate limiting
router.post("/gift-card-check", (req, res) => {
  const code = req.body.code;

  // BUG: No rate limiting - allows brute force of gift card codes
  db.query(`SELECT balance FROM gift_cards WHERE code = '${code}'`, (err, card) => {
    if (card) {
      res.json({ balance: card.balance });
    } else {
      res.json({ error: "Invalid code" });
    }
  });
});

// BUG: Decimal precision issues with money
router.post("/split-payment", (req, res) => {
  const total = 100.1;
  const splitCount = 3;

  // BUG: Floating point arithmetic
  const amountPerPerson = total / splitCount; // 33.36666666666667

  // BUG: Loses precision
  const payments = Array(splitCount).fill(amountPerPerson);

  res.json({ payments, total: payments.reduce((a, b) => a + b, 0) });
  // Total won't equal 100.10!
});

// BUG: XSS in order confirmation
router.get("/order-confirmation/:orderId", (req, res) => {
  const orderId = req.params.orderId;

  db.query(`SELECT * FROM orders WHERE id = ${orderId}`, (err, order) => {
    // BUG: Reflects user input without sanitization
    const html = `
      <html>
        <body>
          <h1>Order Confirmation</h1>
          <p>Thank you, ${order.customer_name}!</p>
          <p>Shipping to: ${order.shipping_address}</p>
          <p>Special instructions: ${order.notes}</p>
        </body>
      </html>
    `;

    res.send(html); // XSS if customer_name or notes contain scripts
  });
});

// BUG: No idempotency key
router.post("/charge", async (req, res) => {
  const amount = req.body.amount;
  const cardToken = req.body.cardToken;

  // BUG: If request is retried, customer is charged multiple times
  const charge = await stripe.charges.create({
    amount,
    currency: "usd",
    source: cardToken,
  });

  res.json({ chargeId: charge.id });
});

// BUG: Inconsistent inventory across services
const inventoryCache = {}; // Separate from inventory object

router.get("/check-availability/:productId", (req, res) => {
  const productId = req.params.productId;

  // BUG: Returns cached value that may be stale
  if (inventoryCache[productId]) {
    res.json({ available: inventoryCache[productId].stock > 0 });
  } else {
    // Fetch from DB
    db.query(`SELECT stock FROM products WHERE id = ${productId}`, (err, product) => {
      inventoryCache[productId] = product; // Cache forever
      res.json({ available: product.stock > 0 });
    });
  }
});

module.exports = router;
