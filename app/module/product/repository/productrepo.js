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
            },
            {
                $lookup: {
                    from: 'users',
                    localField: 'userId',
                    foreignField: '_id',
                    as: 'userdetails'
                }
            },
            {
                $unwind: {
                    path: '$userdetails',
                    preserveNullAndEmptyArrays: true
                }
            },
            {
                $project: {
                    _id: 1,
                    title: 1,
                    slug: 1,
                    description: 1,
                    image: 1,
                    price: 1,
                    'userdetails.first_name': 1,
                    'userdetails.last_name': 1,
                    'userdetails.email': 1
                }
            }
        ]);

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
            },
            {
                $lookup: {
                    from: 'users',
                    localField: 'userId',
                    foreignField: '_id',
                    as: 'userdetails'
                }
            },
            {
                $unwind: {
                    path: '$userdetails',
                    preserveNullAndEmptyArrays: true
                }
            },
            {
                $project: {
                    _id: 1,
                    title: 1,
                    slug: 1,
                    description: 1,
                    image: 1,
                    price: 1,
                    'userdetails.first_name': 1,
                    'userdetails.last_name': 1,
                    'userdetails.email': 1
                }
            }
        ])
    }

}

module.exports = new ProductRepo(); 
