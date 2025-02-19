const UserModel = require('../model/user');
const EmailVerifyModel = require('../model/otpverify')

class AuthRepo {

    // Find by email for Register
    async findByEmail(email) {
        return await UserModel.findOne({ email });
    }

    // Find by ID
    async findById(userId) {
        return await UserModel.findById(userId);
    }

    // Find by userId and Hashpassword
    async findByIdHashpassword(userId, hashedPassword) {
        return await UserModel.findByIdAndUpdate(userId, {
            $set: { password: hashedPassword }
        }, { new: true });
    }

    // Create user 
    async createUser(userData) {
        return UserModel.create(userData);
    }

    // Find useID and otp for email verify 
    async findByUserIdOtp(userId, otp) {
        return await EmailVerifyModel.findOne({ userId, otp });
    }

    // Delete email verification document  
    async deleteVerifyDocument(userId) {
        return await EmailVerifyModel.deleteMany({ userId });
    }

}

module.exports = new AuthRepo(); 
