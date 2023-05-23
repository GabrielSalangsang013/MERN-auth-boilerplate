const mongoose = require('mongoose')
const Schema = mongoose.Schema

const userSchema = new Schema({
  username: {
    type: String,
    required: true
  },
  password: {
    type: String,
    required: true
  },
  profile: [{
    type: Schema.Types.ObjectId,
    ref: 'Profile'
  }]
}, { timestamps: true })

module.exports = mongoose.model('User', userSchema)