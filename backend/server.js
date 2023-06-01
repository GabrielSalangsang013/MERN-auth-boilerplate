require('dotenv').config();
const express = require('express');
const app = express();
const mongoose = require('mongoose');
const cors = require('cors');
const PORT = process.env.PORT || 4000;
const v1AuthenticationRouter = require('./routes/v1AuthenticationRouter');
const cookieParser = require('cookie-parser');
const mongoSanitize = require('express-mongo-sanitize'); // FOR NOSQL INJECTION PROTECTION IN REGISTER AND LOGIN PURPOSES

mongoose.set('strictQuery', false);
app.use(express.json());
app.use(mongoSanitize()); // USER INPUT SANITIZATION AGAINST NOSQL QUERY INJECTION ATTACKS
app.use(cookieParser());
app.use(
  cors({
      origin: ['http://localhost:3000'],
      methods: ['GET', 'POST'],
      credentials: true,
  })
);

app.use('/api/v1/authentication', v1AuthenticationRouter);

mongoose.connect(process.env.MONGO_DB_URI, {
    useNewUrlParser: true,
    useUnifiedTopology: true,
})
.then(() => {
    app.listen(PORT, () => {
        console.log(`File: server.js - Listening on ${PORT}`);
    });
})
.catch((err) => {
    console.log(`File: server.js - ${err}`);
    mongoose.disconnect();
});
