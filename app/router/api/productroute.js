const express = require('express');
const routeLabel = require('route-label');
const uploadImage = require('../../helper/imagehandler') // Image area
const productController = require('../../webservice/productApiController');
const { UserAuth } = require('../../middleware/user_auth/auth')

// Initiallize the express router for router object
const router = express.Router();
const namedRouter = routeLabel(router);

namedRouter.post('createproduct', '/createproduct', UserAuth, uploadImage.single('image'), productController.addProduct)
namedRouter.get('allproduct', '/productlist', UserAuth, productController.showproduct)
namedRouter.get('singleproduct', '/singleproduct/:slug', UserAuth, productController.singleProduct)


module.exports = router;   