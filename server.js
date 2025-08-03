require('dotenv').config();
const express = require('express');
const cors = require('cors');
const { PrismaClient } = require('@prisma/client');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const path = require('path');

// Initialize Prisma Client
const prisma = new PrismaClient();

// Validate environment variables
if (!process.env.JWT_SECRET) {
  console.error('❌ Fatal Error: JWT_SECRET not configured in environment variables');
  console.log('💡 Create a .env file with JWT_SECRET=your_random_secret_key');
  process.exit(1);
}

// Initialize Express app
const app = express();

// ========== ONLY CHANGE: Added CORS middleware ==========
app.use(cors({
  origin: [
    'http://localhost:5173',      // Your React dev server
    'http://127.0.0.1:5173',      // Alternative localhost
    'https://github.com/LinetOsorelapiyolinet/Social-communication.git' // Your production frontend URL (REPLACE THIS)
  ],
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization']
}));
// ========== END OF CHANGE ==========

app.use(express.json());

// Serve static files from public folder if you have frontend assets
app.use(express.static(path.join(__dirname, 'public')));

// Favicon redirect (added here)
app.get('/favicon.ico', (req, res) => {
  res.redirect('/images/logo.png'); // Your existing image
});

// Root route
app.get('/', (req, res) => {
  res.json({
    message: 'Welcome to the API',
    endpoints: {
      auth: {
        login: 'POST /api/auth/login',
        register: 'POST /api/auth/register',
        verify: 'GET /api/auth/verify'
      },
      posts: {
        getPosts: 'GET /api/posts',
        createPost: 'POST /api/posts',
        likePost: 'POST /api/posts/:postId/like'
      },
      health: 'GET /api/health'
    }
  });
});

// Health check endpoint
app.get('/api/health', (req, res) => {
  res.json({ 
    status: 'healthy',
    message: 'Server is running',
    timestamp: new Date().toISOString()
  });
});

// Authentication middleware
const authenticate = async (req, res, next) => {
  try {
    const authHeader = req.headers.authorization;
    if (!authHeader) {
      return res.status(401).json({ error: 'Authorization header missing' });
    }

    const token = authHeader.split(' ')[1];
    if (!token) {
      return res.status(401).json({ error: 'Token missing' });
    }

    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    req.userId = decoded.userId;
    next();
  } catch (error) {
    console.error('Authentication error:', error.message);
    return res.status(401).json({ error: 'Invalid or expired token' });
  }
};

// Login endpoint
app.post('/api/auth/login', async (req, res) => {
  const { email, password } = req.body;

  if (!email || !password) {
    return res.status(400).json({ error: 'Email and password are required' });
  }

  try {
    const user = await prisma.user.findUnique({ 
      where: { email },
      select: { id: true, email: true, username: true, password: true }
    });

    if (!user) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    const passwordMatch = await bcrypt.compare(password, user.password);
    if (!passwordMatch) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    const token = jwt.sign(
      { userId: user.id },
      process.env.JWT_SECRET,
      { expiresIn: '1h' }
    );

    res.json({ 
      data: {
        token,
        userId: user.id,
        user: {
          id: user.id,
          email: user.email,
          username: user.username
        }
      }
    });
  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Registration endpoint
app.post('/api/auth/register', async (req, res) => {
  const { email, username, password } = req.body;

  if (!email || !username || !password) {
    return res.status(400).json({ error: 'All fields are required' });
  }

  try {
    const existingUser = await prisma.user.findFirst({
      where: { OR: [{ email }, { username }] }
    });

    if (existingUser) {
      const field = existingUser.email === email ? 'email' : 'username';
      return res.status(400).json({ error: `${field} already exists` });
    }

    const hashedPassword = await bcrypt.hash(password, 10);
    const newUser = await prisma.user.create({
      data: {
        email,
        username,
        password: hashedPassword
      },
      select: {
        id: true,
        email: true,
        username: true,
        createdAt: true
      }
    });

    const token = jwt.sign(
      { userId: newUser.id },
      process.env.JWT_SECRET,
      { expiresIn: '1h' }
    );

    res.status(201).json({ 
      data: {
        token,
        userId: newUser.id,
        user: newUser
      }
    });
  } catch (error) {
    console.error('Registration error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Token verification endpoint
app.get('/api/auth/verify', authenticate, async (req, res) => {
  try {
    const user = await prisma.user.findUnique({
      where: { id: req.userId },
      select: { id: true, email: true, username: true }
    });

    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }

    res.json({ 
      data: {
        isValid: true,
        user 
      }
    });
  } catch (error) {
    console.error('Verification error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Posts endpoints
app.get('/api/posts', authenticate, async (req, res) => {
  try {
    const posts = await prisma.post.findMany({
      include: {
        author: { select: { id: true, username: true } },
        likes: { select: { userId: true } }
      },
      orderBy: { createdAt: 'desc' }
    });

    const postsWithLikes = posts.map(post => ({
      id: post.id,
      content: post.content,
      createdAt: post.createdAt,
      author: post.author,
      likeCount: post.likes.length,
      isLiked: post.likes.some(like => like.userId === req.userId)
    }));

    res.json({ data: postsWithLikes });
  } catch (error) {
    console.error('Get posts error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

app.post('/api/posts', authenticate, async (req, res) => {
  const { content } = req.body;

  if (!content || content.trim().length === 0) {
    return res.status(400).json({ error: 'Post content cannot be empty' });
  }

  try {
    const post = await prisma.post.create({
      data: {
        content: content.trim(),
        authorId: req.userId
      },
      include: {
        author: { select: { id: true, username: true } }
      }
    });

    res.status(201).json({ 
      data: {
        ...post,
        likeCount: 0,
        isLiked: false
      }
    });
  } catch (error) {
    console.error('Create post error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Like endpoint
app.post('/api/posts/:postId/like', authenticate, async (req, res) => {
  const { postId } = req.params;
  const userId = req.userId;

  try {
    const postIdNum = parseInt(postId);
    if (isNaN(postIdNum)) {
      return res.status(400).json({ error: 'Invalid post ID' });
    }

    const existingLike = await prisma.like.findFirst({
      where: { postId: postIdNum, userId }
    });

    if (existingLike) {
      await prisma.like.delete({ where: { id: existingLike.id } });
      const likeCount = await prisma.like.count({ where: { postId: postIdNum } });
      return res.json({ 
        data: { 
          liked: false, 
          likeCount 
        } 
      });
    }

    await prisma.like.create({ data: { postId: postIdNum, userId } });
    const likeCount = await prisma.like.count({ where: { postId: postIdNum } });
    res.json({ 
      data: { 
        liked: true, 
        likeCount 
      } 
    });
  } catch (error) {
    console.error('Like error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Error handling middleware
app.use((err, req, res, next) => {
  console.error('Unhandled error:', err);
  res.status(500).json({ error: 'Internal server error' });
});

// Start server
const PORT = process.env.PORT || 5001;

async function startServer() {
  try {
    await prisma.$connect();
    console.log('✅ Database connected');
    
    app.listen(PORT, () => {
      console.log(`🚀 Server running on http://localhost:${PORT}`);
    });
  } catch (error) {
    console.error('❌ Server startup failed:', error);
    process.exit(1);
  }
}

// Graceful shutdown
process.on('SIGINT', async () => {
  await prisma.$disconnect();
  process.exit(0);
});

process.on('SIGTERM', async () => {
  await prisma.$disconnect();
  process.exit(0);
});

startServer();