const fs = require('fs');
const path = require('path');

const logFile = path.join(__dirname, 'server.log');

const logToFile = (msg) => {
    const timestamp = new Date().toISOString();
    const formattedMsg = `[${timestamp}] ${msg}\n`;
    console.log(msg);
    fs.appendFileSync(logFile, formattedMsg);
};

module.exports = { logToFile };
