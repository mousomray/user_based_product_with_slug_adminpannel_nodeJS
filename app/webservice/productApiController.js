const ProductRepo = require('../module/product/repository/productrepo')


class productApiController {

    // Add Product 
    async addProduct(req, res) {
        try {
            const userId = req.user._id
            // Image Path Validation
            if (!req.file) {
                return res.status(400).json({
                    message: "Validation error",
                    errors: ["Product image is required"]
                });
            }
            const productData = { ...req.body, image: req.file.path, userId: userId };
            const product = await ProductRepo.createProduct(productData);
            res.status(201).json({
                success: true,
                message: "Product is created",
                product
            });
        } catch (error) {
            const statusCode = error.name === 'ValidationError' ? 400 : 500;
            const message = error.name === 'ValidationError'
                ? { message: "Validation error", errors: Object.values(error.errors).map(err => err.message) }
                : { message: "An unexpected error occurred" };
            console.error(error);
            res.status(statusCode).json(message);
        }
    }

    // Show product 
    async showproduct(req, res) {
        try {
            const userId = req.user._id
            const products = await ProductRepo.showProduct(userId)
            res.status(200).json({ message: "Product list fetched", products })
        } catch (error) {
            console.log("Error fetching product...", error);
        }
    }

    // SIngle product
    async singleProduct(req, res) {
        try {
            const slug = req.params.slug
            const userId = req.user._id
            const product = await ProductRepo.singleProduct(slug, userId)
            res.status(200).json({ message: "Single product fetched", product })
        } catch (error) {
            console.log("Error fetching single product...", error);
        }
    }


}

module.exports = new productApiController();








