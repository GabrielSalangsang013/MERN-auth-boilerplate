const mongoose = require('mongoose');
const Schema = mongoose.Schema;

const csrfTokenSecretSchema = new Schema({
    secret: {
      type: String,
      required: true
    },
    user_id: {
        type: Schema.Types.ObjectId,
        ref: 'User'
    }
});

module.exports = mongoose.model('CSRFTokenSecret', csrfTokenSecretSchema);