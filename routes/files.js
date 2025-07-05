import express from 'express';
import File from '../models/File.js';
import Company from '../models/Company.js';
import { upload } from '../middleware/upload.js';

const router = express.Router();

// List files
router.get('/', async (req, res) => {
  try {
    const files = await File.find()
      .populate('company', 'name')
      .populate('createdBy', 'username')
      .sort({ createdAt: -1 });
    res.render('files/index', { files });
  } catch (error) {
    req.flash('error', 'حدث خطأ أثناء تحميل الملفات');
    res.render('files/index', { files: [] });
  }
});

// New file form
router.get('/new', async (req, res) => {
  try {
    const companies = await Company.find().sort({ name: 1 });
    res.render('files/new', { companies });
  } catch (error) {
    req.flash('error', 'حدث خطأ أثناء تحميل الشركات');
    res.redirect('/files');
  }
});

// Create file
router.post('/', upload.single('pdf'), async (req, res) => {
  try {
    if (!req.file) {
      req.flash('error', 'يجب اختيار ملف PDF');
      return res.redirect('/files/new');
    }
    
    const { fileName, company, status, notes } = req.body;
    
    const file = new File({
      fileName,
      company,
      status,
      notes,
      pdfPath: req.file.filename,
      createdBy: req.session.user.id
    });
    
    await file.save();
    req.flash('success', 'تم إضافة الملف بنجاح');
    res.redirect('/files');
  } catch (error) {
    req.flash('error', 'حدث خطأ أثناء إضافة الملف');
    res.redirect('/files/new');
  }
});

// Edit file form
router.get('/:id/edit', async (req, res) => {
  try {
    const file = await File.findById(req.params.id);
    const companies = await Company.find().sort({ name: 1 });
    
    if (!file) {
      req.flash('error', 'الملف غير موجود');
      return res.redirect('/files');
    }
    
    res.render('files/edit', { file, companies });
  } catch (error) {
    req.flash('error', 'حدث خطأ أثناء تحميل بيانات الملف');
    res.redirect('/files');
  }
});

// Update file
router.put('/:id', async (req, res) => {
  try {
    const { fileName, company, status, notes } = req.body;
    
    await File.findByIdAndUpdate(req.params.id, {
      fileName,
      company,
      status,
      notes
    });
    
    req.flash('success', 'تم تحديث بيانات الملف بنجاح');
    res.redirect('/files');
  } catch (error) {
    req.flash('error', 'حدث خطأ أثناء تحديث بيانات الملف');
    res.redirect('/files');
  }
});

// Delete file
router.delete('/:id', async (req, res) => {
  try {
    await File.findByIdAndDelete(req.params.id);
    req.flash('success', 'تم حذف الملف بنجاح');
    res.redirect('/files');
  } catch (error) {
    req.flash('error', 'حدث خطأ أثناء حذف الملف');
    res.redirect('/files');
  }
});

export default router;