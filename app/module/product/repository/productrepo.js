const ProductModel = require('../model/product');
const mongoose = require('mongoose');

class ProductRepo {

    // Add product function
    async createProduct(productData) {
        return ProductModel.create(productData)
    }

    // Show product for specific user
    async showProduct(userId) {
        return ProductModel.aggregate([
            {
                $match: { userId: new mongoose.Types.ObjectId(userId) }
            }
        ])
    }

    // Show all product with user for admin 
    async showProductWithUser() {
        return ProductModel.aggregate([
            {
                $lookup: {
                    from: 'users',
                    localField: 'userId',
                    foreignField: '_id',
                    as: 'userdetails'
                }
            },
            { $unwind: '$userdetails' }
        ])
    }

    // Single product by slug
    async singleProduct(slug, userId) {
        return ProductModel.aggregate([
            {
                $match: { slug: slug, userId: new mongoose.Types.ObjectId(userId) }
            }
        ])
    }

}

module.exports = new ProductRepo(); 
