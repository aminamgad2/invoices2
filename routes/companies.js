import express from 'express';
import Company from '../models/Company.js';
import { checkPermission } from '../middleware/auth.js';

const router = express.Router();

// List companies
router.get('/', async (req, res) => {
  try {
    const companies = await Company.find().populate('createdBy', 'username').sort({ createdAt: -1 });
    res.render('companies/index', { companies });
  } catch (error) {
    req.flash('error', 'حدث خطأ أثناء تحميل الشركات');
    res.render('companies/index', { companies: [] });
  }
});

// New company form
router.get('/new', checkPermission('canCreateCompanies'), (req, res) => {
  res.render('companies/new');
});

// Create company
router.post('/', checkPermission('canCreateCompanies'), async (req, res) => {
  try {
    const { name, commissionRate } = req.body;
    
    const company = new Company({
      name,
      commissionRate: parseFloat(commissionRate) || 0,
      createdBy: req.session.user.id
    });
    
    await company.save();
    req.flash('success', 'تم إضافة الشركة بنجاح');
    res.redirect('/companies');
  } catch (error) {
    req.flash('error', 'حدث خطأ أثناء إضافة الشركة');
    res.redirect('/companies/new');
  }
});

// Edit company form
router.get('/:id/edit', checkPermission('canCreateCompanies'), async (req, res) => {
  try {
    const company = await Company.findById(req.params.id);
    if (!company) {
      req.flash('error', 'الشركة غير موجودة');
      return res.redirect('/companies');
    }
    res.render('companies/edit', { company });
  } catch (error) {
    req.flash('error', 'حدث خطأ أثناء تحميل بيانات الشركة');
    res.redirect('/companies');
  }
});

// Update company
router.put('/:id', checkPermission('canCreateCompanies'), async (req, res) => {
  try {
    const { name, commissionRate } = req.body;
    
    await Company.findByIdAndUpdate(req.params.id, {
      name,
      commissionRate: parseFloat(commissionRate) || 0
    });
    
    req.flash('success', 'تم تحديث بيانات الشركة بنجاح');
    res.redirect('/companies');
  } catch (error) {
    req.flash('error', 'حدث خطأ أثناء تحديث بيانات الشركة');
    res.redirect('/companies');
  }
});

// Delete company
router.delete('/:id', checkPermission('canCreateCompanies'), async (req, res) => {
  try {
    await Company.findByIdAndDelete(req.params.id);
    req.flash('success', 'تم حذف الشركة بنجاح');
    res.redirect('/companies');
  } catch (error) {
    req.flash('error', 'حدث خطأ أثناء حذف الشركة');
    res.redirect('/companies');
  }
});

export default router;