const mongoose = require('mongoose');
const Schema = mongoose.Schema;
const { escape } = require('he');

const profileSchema = new Schema({
  fullName: {
    type: String,
    trim: true,
    required: [true, 'Full Name is required'],
    maxlength: [50, 'Full Name must not exceed 50 characters'],
    match: [/^[A-Za-z.\s]+$/, 'Full Name must contain letters and dots only'],
    validate: [
      {
        validator: function(value) {
          const sanitizedValue = escape(value);
          return sanitizedValue === value;
        },
        message: 'Full Name contains potentially unsafe characters or invalid characters',
      },
    ],
  },
  profilePicture: {
      type: String,
      required: true,
      default: "https://res.cloudinary.com/dgo6vnzjl/image/upload/c_fill,q_50,w_150/v1685085963/default_male_avatar_xkpekq.webp"
  },
  user_id: {
      type: Schema.Types.ObjectId,
      ref: 'User'
  }
});

module.exports = mongoose.model('Profile', profileSchema);