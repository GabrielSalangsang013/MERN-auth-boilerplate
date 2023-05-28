require('dotenv').config();
let frontendConfig;

if (process.env.NODE_ENV === "PRODUCTION") {
    frontendConfig = {
        uri: process.env.REACT_URL_PRODUCTION,
    };
} else if(process.env.NODE_ENV === "DEVELOPMENT") {
    frontendConfig = {
        uri: process.env.REACT_URL_DEVELOPMENT,
    };
} else {
    frontendConfig = {
        uri: process.env.REACT_URL_DEVELOPMENT,
    };
}

module.exports = frontendConfig;