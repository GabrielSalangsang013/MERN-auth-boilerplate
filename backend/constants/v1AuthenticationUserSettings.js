// WHEN SUCCESS LOGIN, ALL DATA YOU DON'T WANT TO STORE IN JWT TOKEN - ONLY FOR AUTHENTICATED USER
exports.dataToRemoveToStoreInJWTToken = [
    "username",
    "email",
    "password",
    "profile",
    "csrfTokenSecret",
    "forgotPassword",
    "updatedAt",
    "__v",
]

// WHEN USER IS ACCESSING DATA, ALL DATA YOU DON'T WANT TO STORE IN REQ.USER - ONLY FOR AUTHENTICATED USER
exports.dataToRemoveToStoreInRequestDotUser = [
    "password",
    "csrfTokenSecret",
    "forgotPassword",
    "updatedAt",
    "__v",
]