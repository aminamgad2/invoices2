export const requireAuth = (req, res, next) => {
  if (!req.session.user) {
    req.flash('error', 'يجب تسجيل الدخول للوصول إلى هذه الصفحة');
    return res.redirect('/auth/login');
  }
  next();
};

export const requireAdmin = (req, res, next) => {
  if (!req.session.user || req.session.user.role !== 'admin') {
    req.flash('error', 'ليس لديك صلاحية للوصول إلى هذه الصفحة');
    return res.redirect('/dashboard');
  }
  next();
};

// Legacy permission check for backward compatibility
export const checkPermission = (permission) => {
  return (req, res, next) => {
    if (req.session.user.role === 'admin') {
      return next();
    }
    
    if (!req.session.user.permissions[permission]) {
      req.flash('error', 'ليس لديك صلاحية لتنفيذ هذا الإجراء');
      return res.redirect('/dashboard');
    }
    next();
  };
};

// New fine-grained permission check
export const requirePermission = (module, action) => {
  return async (req, res, next) => {
    try {
      if (req.session.user.role === 'admin') {
        return next();
      }

      // Import User model dynamically to avoid circular dependency
      const { default: User } = await import('../models/User.js');
      const user = await User.findById(req.session.user.id);
      
      if (!user) {
        req.flash('error', 'المستخدم غير موجود');
        return res.redirect('/auth/login');
      }

      const hasPermission = await user.hasPermission(module, action);
      
      if (!hasPermission) {
        req.flash('error', 'ليس لديك صلاحية لتنفيذ هذا الإجراء');
        return res.redirect('/dashboard');
      }

      next();
    } catch (error) {
      console.error('Permission check error:', error);
      req.flash('error', 'حدث خطأ أثناء التحقق من الصلاحيات');
      return res.redirect('/dashboard');
    }
  };
};

// Helper middleware to load user permissions into session
export const loadUserPermissions = async (req, res, next) => {
  if (req.session.user && req.session.user.role !== 'admin') {
    try {
      const { default: User } = await import('../models/User.js');
      const user = await User.findById(req.session.user.id);
      
      if (user) {
        const permissions = await user.getAllPermissions();
        req.session.user.detailedPermissions = permissions;
      }
    } catch (error) {
      console.error('Error loading user permissions:', error);
    }
  }
  next();
};