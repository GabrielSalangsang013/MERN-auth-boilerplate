require('dotenv').config();
const path = require("path");
const express = require('express');
const app = express();
const mongoose = require('mongoose');
const cors = require('cors');
const cookieParser = require('cookie-parser');
const mongoSanitize = require('express-mongo-sanitize');
const helmet = require('helmet');

// ------------ ROUTERS --------------------
const v1AuthenticationRouter = require('./routes/v1AuthenticationRouter');
// ------------ ROUTERS --------------------

// ------------ MIDDLEWARES --------------------
const errorHandler = require('./middlewares/errorHandler');
// ------------ MIDDLEWARES --------------------

mongoose.set('strictQuery', false);
app.use(helmet({
    dnsPrefetchControl: {
        allow: false,
    },
    frameguard: {
        action: "deny",
    },
    hidePoweredBy: true,
    noSniff: true,
    referrerPolicy: {
        policy: ["origin"]
    },
    xssFilter: true,
    hsts: {
        maxAge: 31536000, // 1 year in seconds
        includeSubDomains: true,
        preload: true
    },
    contentSecurityPolicy: {
        directives: {
          defaultSrc: ["'self'"],
          scriptSrc: ["'self'", "'unsafe-inline'"],
          styleSrc: ["'self'", "'unsafe-inline'"],
          imgSrc: ["'self'"],
          connectSrc: ["'self'"],
          fontSrc: ["'self'"],
          objectSrc: ["'none'"],
          mediaSrc: ["'none'"],
          frameSrc: ["'none'"]
        }
    },
    featurePolicy: {
        features: {
          fullscreen: ["'self'"],
          camera: ["'self'"],
          microphone: ["'self'"]
        }
    }
}));
app.use(express.json());
app.use(mongoSanitize());
app.use(cookieParser());
app.use(
  cors({
      origin: [process.env.REACT_URL],
      methods: ['GET', 'POST'],
      credentials: true
  })
);

app.use('/api/v1/authentication', v1AuthenticationRouter);

// -------------------------- DEPLOYMENT ------------------------------
if (process.env.NODE_ENV === "PRODUCTION") {
    app.use(express.static(path.join(__dirname, "../frontend/build")));
    app.get("*", (req, res) => {
      return res.sendFile(
        path.resolve(__dirname, "client", "build", "index.html")
      );
    });
};
// -------------------------- DEPLOYMENT ------------------------------

app.use(errorHandler);

mongoose.connect(process.env.MONGO_DB_URI, {
    useNewUrlParser: true,
    useUnifiedTopology: true,
})
.then(() => {
    app.listen(process.env.PORT, () => {
        console.log(`File: server.js - Listening on ${process.env.PORT}`);
    });
})
.catch((error) => {
    console.log(`File: server.js - ${error}`);
    mongoose.disconnect();
});
