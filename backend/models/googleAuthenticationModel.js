const mongoose = require('mongoose');
const Schema = mongoose.Schema;

const googleAuthenticationSchema = new Schema({
  secret: {
    type: String,
    required: true
  },
  encoding: {
    type: String,
    required: true
  },
  qr_code: {
    type: String,
    required: true
  },
  otpauth_url: {
    type: String,
    required: true
  },
  isScanned: {
    type: 'boolean',
    required: true,
    default: false
  },
  user_id: {
    type: Schema.Types.ObjectId,
    ref: 'User'
  }
});

module.exports = mongoose.model('GoogleAuthentication', googleAuthenticationSchema);