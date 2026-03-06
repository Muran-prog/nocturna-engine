// Intentionally vulnerable JavaScript fixture for Semgrep demo/tests.
function executeUserInput(userInput) {
  return eval(userInput);
}

module.exports = { executeUserInput };

