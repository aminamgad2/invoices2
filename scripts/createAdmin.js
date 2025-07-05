import mongoose from 'mongoose';
import User from '../models/User.js';
import dotenv from 'dotenv';

dotenv.config();

mongoose.connect(process.env.MONGODB_URI || 'mongodb://localhost:27017/arabic-invoice-system')
  .then(async () => {
    console.log('MongoDB connected');
    
    // Check if admin already exists
    const existingAdmin = await User.findOne({ role: 'admin' });
    if (existingAdmin) {
      console.log('Admin user already exists');
      process.exit(0);
    }
    
    // Create admin user
    const admin = new User({
      username: 'admin',
      password: 'admin123',
      role: 'admin',
      permissions: {
        canCreateCompanies: true,
        canCreateInvoices: true,
        canManageClients: true,
        canViewReports: true
      }
    });
    
    await admin.save();
    console.log('Admin user created successfully');
    console.log('Username: admin');
    console.log('Password: admin123');
    
    process.exit(0);
  })
  .catch(err => {
    console.error('MongoDB connection error:', err);
    process.exit(1);
  });