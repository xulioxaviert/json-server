const jsonServer = require('json-server');

const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');
const server = jsonServer.create();
const router = jsonServer.router('db.json');
const middlewares = jsonServer.defaults();
const cors = require('cors');
const rateLimit = require('express-rate-limit');

// Configuración de variables de entorno
require('dotenv').config();
const JWT_SECRET = process.env.JWT_SECRET || 'fallback_secret_key';
const PORT = process.env.PORT || 3000;

server.use(middlewares);
server.use(jsonServer.bodyParser);
server.use(cors());

// Configurar rate limiting
const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutos
  max: 5, // limitar cada IP a 5 solicitudes por ventana
});

// Ruta para iniciar sesión
server.post('/login', loginLimiter, async (req, res) => {
  const { username, password } = req.body;

  if (!username || !password) {
    res.status(400).json({ error: 'Username and password are required' });
    return;
  }

  const userCollection = router.db.get('login');
  if (!userCollection) {
    res.status(500).json({ error: 'Login collection not found' });
    return;
  }

  const user = userCollection.find({ username }).value();

  if (user && (await bcrypt.compare(password, user.password))) {
    const token = jwt.sign({ id: user.id }, JWT_SECRET, { expiresIn: '1h' });
    res.json({ token });
  } else {
    res.status(401).json({ error: 'Invalid credentials' });
  }
});

// Middleware para verificar el token
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (token == null)
    return res.status(401).json({ error: 'No token provided' });

  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) return res.status(403).json({ error: 'Invalid token' });
    req.user = user;
    next();
  });
};

// Rutas públicas
const publicRoutes = ['/login', '/register'];

server.use((req, res, next) => {
  if (publicRoutes.includes(req.path)) {
    return next();
  }
  authenticateToken(req, res, next);
});

// Usar el router
server.use(router);

// Manejo de errores
server.use((err, req, res, next) => {
  console.error(err.stack);
  res.status(500).json({ error: 'Something went wrong!' });
});

server.listen(PORT, () => {
  console.log(`JSON Server is running on port ${PORT}`);
});
