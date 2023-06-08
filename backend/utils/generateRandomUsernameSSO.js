function generateRandomUsernameSSO() {
    const validChars = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_';
    const minLength = 4;
    const maxLength = 20;
  
    let username = '';
    const usernameLength = Math.floor(Math.random() * (maxLength - minLength + 1)) + minLength;
  
    for (let i = 0; i < usernameLength; i++) {
      const randomIndex = Math.floor(Math.random() * validChars.length);
      username += validChars.charAt(randomIndex);
    }
  
    return username;
}

module.exports = generateRandomUsernameSSO;