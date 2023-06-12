// WHEN SUCCESSFULLY LOGIN, WHAT DATA NEEDS TO BE REMOVED THAT WILL GOING TO BE STORED IN ACCESS JWT TOKEN?
// IMPORTANT! DON'T FORGET TO DELETE PASSWORD AND CSRF TOKEN SECRET
exports.dataToRemoveInsideUserJWTToken = [
    "username",
    "email",
    "password",
    "profile",
    "googleAuthentication",
    "csrfTokenSecret",
    "forgotPassword",
    "verificationCodeLogin",
    "isSSO",
    "updatedAt",
    "__v",
]

// WHEN USER IS ALREADY AUTHENTICATED, WHAT DATA NEEDS TO BE REMOVED THAT STORED IN REQ.USER?
// IMPORTANT! DON'T FORGET TO DELETE PASSWORD AND CSRF TOKEN SECRET
exports.dataToRemoveRequestUser = [
    "password",
    "csrfTokenSecret",
    "forgotPassword",
    "verificationCodeLogin",
    "isSSO",
    "updatedAt",
    "__v",
]