const mongoose = require('mongoose');
const Schema = mongoose.Schema;

const ProductSchema = new Schema({
    title: {
        type: String,
        required: "Title is required",
        minlength: [3, 'Title must be at least 3 characters']
    },
    slug: {
        type: String,
        unique: [true, 'Slug should be unique'],
        lowercase: [true, 'Slug must be lowercase'],
        required: [true, 'Slug is required'],
    },
    description: {
        type: String,
        required: "Description is required",
        minlength: [10, 'Description must be at least 10 characters']
    },
    price: {
        type: Number,
        required: "Price is Required"
    },
    image: {
        type: String,
        required: "Enter image it is Required"
    },
    userId: {
        type: mongoose.Schema.Types.ObjectId,
        ref: 'user',
        required: "User Id is Required"
    },
}, { timestamps: true });

const ProductModel = mongoose.model('product', ProductSchema);

module.exports = ProductModel;