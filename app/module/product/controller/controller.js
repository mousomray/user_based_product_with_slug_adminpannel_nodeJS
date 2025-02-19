const ProductRepo = require('../repository/productrepo')

const path = require('path');
const fs = require('fs');

class productAdminController {


    // Get product list 
    async showproduct(req, res) {
        try {
            const products = await ProductRepo.showProductWithUser();
            res.render('product/productlist', { products, user: req.user });
        } catch (error) {
            console.error(error);
            res.status(500).json({ message: "Error retrieving products" });
        }
    }

}

module.exports = new productAdminController();