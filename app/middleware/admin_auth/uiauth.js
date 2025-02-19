const jwt = require('jsonwebtoken');

const AdminuiAuth = (req, res, next) => {
    try {
        const token = req.cookies?.admin_auth;
        if (!token) {
            req.flash('err',"You can't access that page without login")
            return res.redirect(generateUrl('login')); // Redirect to login page if user is not authenticated
        }
        jwt.verify(token, process.env.ADMIN_API_KEY, (err, decoded) => {
            if (err) {
                return res.status(403).json({ message: 'Invalid or expired token. Please login again.' });
            }
            req.user = decoded;
            next();
        });
    } catch (error) {
        console.error('Error in JWT authentication middleware:', error);
        return res.status(500).json({ message: 'Internal server error.' });
    }
};

module.exports = { AdminuiAuth };