const mongoose = require('mongoose')
const Schema = mongoose.Schema

const profileSchema = new Schema({
    fullName: {
        type: String,
        required: true
    },
    profilePicture: {
        type: String,
        required: true
    },
    user_id: {
        type: Schema.Types.ObjectId,
        ref: 'User'
    }
})

module.exports = mongoose.model('Profile', profileSchema)