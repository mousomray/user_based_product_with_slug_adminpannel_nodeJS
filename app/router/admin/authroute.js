const express = require('express');
const uploadImage = require('../../helper/imagehandler') // Image area
const routeLabel = require('route-label');
const authController = require('../../module/auth/controller/controller');
const { AdminuiAuth } = require('../../middleware/admin_auth/uiauth'); 
const router = express.Router();
const namedRouter = routeLabel(router);

namedRouter.get('register', '/admin/register', authController.registerGet)
namedRouter.post('registercreate', '/admin/registercreate', uploadImage.single('image'), authController.registerPost)
namedRouter.get('otpverify', '/admin/otpverify', authController.otpVerifyGet)
namedRouter.post('otpverifycreate', '/admin/otpverifycreate', authController.otpVerifyPost)
namedRouter.get('login', '/admin/login', authController.loginGet)
namedRouter.post('logincreate', '/admin/logincreate', authController.loginPost)
namedRouter.get('logout', '/admin/logout', authController.logout)

module.exports = router; 