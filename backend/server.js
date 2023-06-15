require('dotenv').config();
const path = require("path");
const express = require('express');
const app = express();
const mongoose = require('mongoose');
const cors = require('cors');
const cookieParser = require('cookie-parser');
const mongoSanitize = require('express-mongo-sanitize');
const helmet = require('helmet');
const cluster = require('cluster');
const os = require('os');
const numCPUs = os.cpus().length;

// ------------ ROUTERS --------------------
const v1AuthenticationRouter = require('./routes/v1AuthenticationRouter');
// ------------ ROUTERS --------------------

// ------------ MIDDLEWARES --------------------
const errorHandler = require('./middlewares/errorHandler');
// ------------ MIDDLEWARES --------------------

mongoose.set('strictQuery', false);
app.use(helmet({
    /* `dnsPrefetchControl` is a configuration option provided by the `helmet` package in Node.js. It
    controls whether or not the browser should perform DNS prefetching for the website's resources.
    DNS prefetching is a technique used by modern browsers to speed up the loading of web pages by
    resolving domain names before the user clicks on a link. In this code, `dnsPrefetchControl` is
    set to `allow: false`, which means that the browser should not perform DNS prefetching for the
    website's resources. This can help to improve the website's security by preventing the browser
    from making unnecessary DNS requests. */
    dnsPrefetchControl: {
        allow: false,
    },
    /* `frameguard` is a middleware function provided by the `helmet` package in Node.js. It adds an
    X-Frame-Options header to the HTTP response, which helps to prevent clickjacking attacks by
    limiting the ways in which a page can be embedded within an iframe. In this specific code,
    `frameguard` is set to `action: "deny"`, which means that the page cannot be embedded in an
    iframe at all. */
    frameguard: {
        action: "deny",
    },
    /* `hidePoweredBy: true` is a configuration option provided by the `helmet` package in Node.js. It
    adds an `X-Powered-By` header to the HTTP response, which by default contains information about
    the technology used to power the web application. By setting `hidePoweredBy` to `true`, the
    `X-Powered-By` header is removed from the HTTP response, which can help to improve the website's
    security by making it harder for attackers to identify the technology used to power the web
    application. */
    hidePoweredBy: true,
    /* `noSniff: true` is a configuration option provided by the `helmet` package in Node.js. It adds
    an `X-Content-Type-Options` header to the HTTP response, which helps to prevent MIME type
    sniffing attacks. MIME type sniffing is a technique used by some browsers to try to determine
    the type of a file based on its contents, rather than relying on the MIME type specified in the
    HTTP response. This can be a security risk, as it can allow attackers to execute malicious code
    by tricking the browser into interpreting a file as a different type than it actually is. By
    setting `noSniff` to `true`, the `X-Content-Type-Options` header is added to the HTTP response
    with the value `nosniff`, which instructs the browser to always use the MIME type specified in
    the HTTP response, rather than trying to guess the type based on the file contents. */
    noSniff: true,
    /* `referrerPolicy` is a configuration option provided by the `helmet` package in Node.js. It sets
    the value of the `Referrer-Policy` header in the HTTP response, which controls how much
    information the browser should include in the `Referer` header when making requests to other
    websites. */
    referrerPolicy: {
        policy: ["origin"]
    },
    /* `xssFilter: true` is a configuration option provided by the `helmet` package in Node.js. It adds
    an `X-XSS-Protection` header to the HTTP response, which helps to prevent cross-site scripting
    (XSS) attacks. XSS attacks are a type of security vulnerability that allows attackers to inject
    malicious code into web pages viewed by other users. By setting `xssFilter` to `true`, the
    `X-XSS-Protection` header is added to the HTTP response with the value `1; mode=block`, which
    instructs the browser to enable its built-in XSS protection mechanism. */
    xssFilter: true,
    /* `hsts` stands for HTTP Strict Transport Security. It is a security feature that instructs the
    browser to only communicate with the server over HTTPS, even if the user types in an HTTP URL. */
    hsts: {
        maxAge: 31536000, // 1 year in seconds
        includeSubDomains: true,
        preload: true
    },
    /* `contentSecurityPolicy` is a configuration option provided by the `helmet` package in Node.js.
    It sets the value of the `Content-Security-Policy` header in the HTTP response, which helps to
    prevent cross-site scripting (XSS) attacks, clickjacking attacks, and other code injection
    attacks. */
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
    /* `featurePolicy` is a configuration option provided by the `helmet` package in Node.js. It sets
    the value of the `Feature-Policy` header in the HTTP response, which allows the website to
    control which browser features and APIs can be used by the website's content. In this specific
    code, `featurePolicy` is setting policies for the `fullscreen`, `camera`, and `microphone`
    features, allowing them to be used only by the website itself (`'self'`). This can help to
    improve the website's security by preventing malicious code from accessing sensitive features
    and APIs. */
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
      methods: ['GET', 'POST', 'PUT', 'DELETE'],
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

if(cluster.isMaster) {
    for(let i = 0; i < numCPUs; i++) {
        cluster.fork();
    }
}else {
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
}