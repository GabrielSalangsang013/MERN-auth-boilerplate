const ErrorResponse = require("../utils/ErrorResponse"); // UTILITY
const errorCodes = require('../constants/v1AuthenticationErrorCodes'); // CONSTANTS

const errorHandler = (error, req, res, next) => {
    // THIS IS ERROR FROM THE MONGOOSE MODEL VALIDATION USER INPUT
    if (error.name === "ValidationError") {
        const message = Object.values(err.errors).map((val) => val.message);
        error = new ErrorResponse(400, message, errorCodes.MONGOOSE_VALIDATION_ERROR);
    }

    return res.status(error.statusCode || 500).json({
        message: error.message || "There is something problem on the server. Please try again later.",
        errorCode: error.errorCode || errorCodes.SERVER_ERROR
    });
}

module.exports = errorHandler;