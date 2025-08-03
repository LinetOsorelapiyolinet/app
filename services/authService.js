const prisma = require('../config/db');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const authConfig = require('../config/auth');

module.exports = {
  async registerUser(userData) {
    const { email, password, name } = userData;
    
    const existingUser = await prisma.user.findUnique({ where: { email } });
    if (existingUser) {
      throw new Error('Email already in use');
    }
    
    const hashedPassword = await bcrypt.hash(password, authConfig.bcryptSaltRounds);
    
    return await prisma.user.create({
      data: {
        email,
        password: hashedPassword,
        name
      },
      select: {
        id: true,
        email: true,
        name: true
      }
    });
  },
  
  async loginUser(credentials) {
    const { email, password } = credentials;
    
    const user = await prisma.user.findUnique({ where: { email } });
    if (!user) {
      throw new Error('Invalid credentials');
    }
    
    const isPasswordValid = await bcrypt.compare(password, user.password);
    if (!isPasswordValid) {
      throw new Error('Invalid credentials');
    }
    
    return jwt.sign({ userId: user.id }, authConfig.jwtSecret, { 
      expiresIn: authConfig.jwtExpiration 
    });
  }
};