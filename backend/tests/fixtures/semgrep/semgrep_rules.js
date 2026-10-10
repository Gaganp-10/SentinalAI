const child_process = require('child_process');

function testEval(userInput) {
    // ruleid: js-eval
    eval(userInput);
    // ok: js-eval
    JSON.parse(userInput);
}

// ruleid: js-hardcoded-secret
const password = "super_secret_password_123";
// ok: js-hardcoded-secret
const username = "alice";

function testExec(cmd) {
    // ruleid: js-child-process-exec
    child_process.exec(cmd);
}
