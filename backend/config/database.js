require('dotenv').config();
let databaseConfig;

if (process.env.NODE_ENV === "PRODUCTION") {
    databaseConfig = {
      uri: process.env.MONGO_DB_URI_PRODUCTION,
    };
} else if(process.env.NODE_ENV === "DEVELOPMENT") {
    databaseConfig = {
      uri: process.env.MONGO_DB_URI_DEVELOPMENT,
    };
} else {
    databaseConfig = {
      uri: process.env.MONGO_DB_URI_DEVELOPMENT,
    };
}

module.exports = databaseConfig;