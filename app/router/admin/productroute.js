const express = require('express');
const routeLabel = require('route-label');
const productController = require('../../module/product/controller/controller');
const { AdminuiAuth } = require('../../middleware/admin_auth/uiauth'); // For UI auth

// Initiallize the express router for router object
const router = express.Router();
const namedRouter = routeLabel(router);

namedRouter.get('allproducts', '/admin/allproducts', AdminuiAuth, productController.showproduct)


module.exports = router; 