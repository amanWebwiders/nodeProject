const User = require('../models/User');

class UserRepository {
  async create(data) {
    return await User.create(data);
  }

  async findById(id) {
    return await User.findById(id);
  }

  async findByEmail(email) {
    return await User.findOne({ email });
  }

  async findAll() {
    return await User.find();
  }

  async updateById(id, updateData) {
    return await User.findByIdAndUpdate(id, updateData, { new: true });
  }

  async deleteById(id) {
    return await User.findByIdAndDelete(id);
  }
}

module.exports = new UserRepository();