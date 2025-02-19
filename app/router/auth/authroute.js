const express = require('express');
const routeLabel = require('route-label');
const authApiController = require('../../webservice/apiAuthController');
const uploadImage = require('../../helper/imagehandler') // Image area
const { UserAuth } = require('../../middleware/user_auth/auth');

// Initiallize the express router for router object
const router = express.Router();
const namedRouter = routeLabel(router);

namedRouter.post('signup', '/signup',uploadImage.single('image'), authApiController.register) 
namedRouter.post('verifyotp', '/verifyotp', authApiController.verifyOtp)
namedRouter.post('signin', '/signin', authApiController.login)
namedRouter.get('dashboard', '/dashboard', UserAuth, authApiController.dashboard)

module.exports = router; 