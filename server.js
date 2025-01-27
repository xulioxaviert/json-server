const jsonServer = require('json-server');
const jwt = require('jsonwebtoken');

const server = jsonServer.create();
const router = jsonServer.router('db.json');
const middlewares = jsonServer.defaults();

const SECRET_KEY = 'tu_clave_secreta';
const expiresIn = '1h';

server.use(middlewares);
server.use(jsonServer.bodyParser);

// Endpoint de autenticación
server.post('/auth/login', (req, res) => {
  const { email, password } = req.body;

  // Aquí deberías verificar las credenciales contra tu base de datos
  if (isAuthenticated({ email, password })) {
    const token = jwt.sign({ email }, SECRET_KEY, { expiresIn });
    res.json({ token });
  } else {
    res.status(401).json({ message: 'Email o contraseña incorrectos' });
  }
});

// Middleware para proteger rutas
server.use((req, res, next) => {
  if (req.headers.authorization) {
    const token = req.headers.authorization.split(' ')[1];
    try {
      jwt.verify(token, SECRET_KEY);
      next();
    } catch (err) {
      res.status(401).json({ message: 'Token inválido' });
    }
  } else {
    res.status(401).json({ message: 'No se proporcionó token' });
  }
});

server.use(router);

server.listen(3000, () => {
  console.log('JSON Server está corriendo en el puerto 3000');
});

// Función para verificar credenciales (ejemplo)
function isAuthenticated({ email, password }) {
  // Implementa tu lógica de autenticación aquí
  return email === 'usuario@ejemplo.com' && password === 'contraseña';
}
