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

// Check if user has any permission for a module (view_own or view_all)
export const requireModuleAccess = (module) => {
  return async (req, res, next) => {
    try {
      if (req.session.user.role === 'admin') {
        return next();
      }

      const { default: User } = await import('../models/User.js');
      const user = await User.findById(req.session.user.id);
      
      if (!user) {
        req.flash('error', 'المستخدم غير موجود');
        return res.redirect('/auth/login');
      }

      const hasViewOwn = await user.hasPermission(module, 'view_own');
      const hasViewAll = await user.hasPermission(module, 'view_all');
      
      if (!hasViewOwn && !hasViewAll) {
        req.flash('error', 'ليس لديك صلاحية للوصول إلى هذا القسم');
        return res.redirect('/dashboard');
      }

      // Store permission level in request for use in routes
      req.userPermissionLevel = {
        canViewOwn: hasViewOwn,
        canViewAll: hasViewAll,
        canCreate: await user.hasPermission(module, 'create'),
        canUpdate: await user.hasPermission(module, 'update'),
        canDelete: await user.hasPermission(module, 'delete')
      };

      next();
    } catch (error) {
      console.error('Module access check error:', error);
      req.flash('error', 'حدث خطأ أثناء التحقق من الصلاحيات');
      return res.redirect('/dashboard');
    }
  };
};