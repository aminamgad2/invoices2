import express from 'express';
import Client from '../models/Client.js';
import { checkPermission } from '../middleware/auth.js';

const router = express.Router();

// List clients
router.get('/', async (req, res) => {
  try {
    const clients = await Client.find().populate('createdBy', 'username').sort({ createdAt: -1 });
    res.render('clients/index', { clients });
  } catch (error) {
    req.flash('error', 'حدث خطأ أثناء تحميل العملاء');
    res.render('clients/index', { clients: [] });
  }
});

// New client form
router.get('/new', checkPermission('canManageClients'), (req, res) => {
  res.render('clients/new');
});

// Create client
router.post('/', checkPermission('canManageClients'), async (req, res) => {
  try {
    const { fullName, mobileNumber, notes, commissionRate } = req.body;
    
    const client = new Client({
      fullName,
      mobileNumber,
      notes,
      commissionRate: parseFloat(commissionRate) || 0,
      createdBy: req.session.user.id
    });
    
    await client.save();
    req.flash('success', 'تم إضافة العميل بنجاح');
    res.redirect('/clients');
  } catch (error) {
    req.flash('error', 'حدث خطأ أثناء إضافة العميل');
    res.redirect('/clients/new');
  }
});

// Edit client form
router.get('/:id/edit', checkPermission('canManageClients'), async (req, res) => {
  try {
    const client = await Client.findById(req.params.id);
    if (!client) {
      req.flash('error', 'العميل غير موجود');
      return res.redirect('/clients');
    }
    res.render('clients/edit', { client });
  } catch (error) {
    req.flash('error', 'حدث خطأ أثناء تحميل بيانات العميل');
    res.redirect('/clients');
  }
});

// Update client
router.put('/:id', checkPermission('canManageClients'), async (req, res) => {
  try {
    const { fullName, mobileNumber, notes, commissionRate } = req.body;
    
    await Client.findByIdAndUpdate(req.params.id, {
      fullName,
      mobileNumber,
      notes,
      commissionRate: parseFloat(commissionRate) || 0
    });
    
    req.flash('success', 'تم تحديث بيانات العميل بنجاح');
    res.redirect('/clients');
  } catch (error) {
    req.flash('error', 'حدث خطأ أثناء تحديث بيانات العميل');
    res.redirect('/clients');
  }
});

// Delete client
router.delete('/:id', checkPermission('canManageClients'), async (req, res) => {
  try {
    await Client.findByIdAndDelete(req.params.id);
    req.flash('success', 'تم حذف العميل بنجاح');
    res.redirect('/clients');
  } catch (error) {
    req.flash('error', 'حدث خطأ أثناء حذف العميل');
    res.redirect('/clients');
  }
});

export default router;