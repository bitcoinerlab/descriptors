// Copyright (c) 2023 Jose-Luis Landabaso - https://bitcoinerlab.com
// Distributed under the MIT software license

// Generate fixtures from Bitcoin Core tests.
const fs = require('fs');
const path = require('path');

const parseTests = str => {
  const argsRegex = /(?:Check|CheckUnparsable)\((.*)\)/;
  const match = str.match(argsRegex);
  if (!match) return { expressions: [], scripts: [] };
  const argsString = match[1];
  let currentArg = '';
  let inString = false;
  let bracesLevel = 0;
  const expressions = [];
  let scripts;
  let expressionsDone = false;
  for (let i = 0; i < argsString.length; i++) {
    if (argsString[i] === '{') {
      bracesLevel++;
    }
    if (argsString[i] === '}') {
      bracesLevel--;
    }
    if (argsString[i] === '"') {
      inString = !inString;
    }
    if (
      (argsString[i] === ',' || argsString[i] === ')') &&
      !inString &&
      bracesLevel === 0
    ) {
      if (currentArg === '') {
        throw new Error('Missing argument');
      }

      if (currentArg.trim()[0] === '"') {
        if (expressionsDone === false) {
          expressions.push(currentArg.trim().slice(1, -1));
        }
      } else {
        expressionsDone = true;
      }

      if (currentArg.trim()[0] === '{' && scripts === undefined) {
        scripts = currentArg
          .trim()
          .slice(1, -1)
          .split(',')
          .map(script => script.trim().slice(2, -2));
      }

      currentArg = '';
    } else {
      currentArg += argsString[i];
    }
  }
  if (str.match(/HARDENED/)) {
    //When using the flag HARDENED, first expression in the tests always includes
    //xprv or private keys
    return { expressions: [expressions[0]], scripts };
  } else {
    //remove duplicated expressions
    return { expressions: [...new Set(expressions)], scripts };
  }
};

const isSupported = parsed => {
  let supported = true;
  parsed.expressions.forEach(expression => {
    if (expression.match(/tr\(/)) supported = false;
    if (expression.match(/^multi\(/)) supported = false; //Top-level multi not supported; It must be within sh or wsh
    if (expression.match(/combo\(/)) supported = false;
    if (expression.match(/sortedmulti\(/)) supported = false;
    if (expression.match(/raw\(/)) supported = false;
  });
  return supported;
};

// File name
const fileName = 'descriptor_tests.cpp';

// File path
const filePath = path.join(__dirname, fileName);

const valid = [];
const invalid = [];

// Use the 'utf8' encoding when reading the file
fs.readFile(filePath, 'utf8', (err, data) => {
  if (err) throw err;

  // Split the data by newline character
  const lines = data.split('\n');

  // Use for-of loop to iterate over the lines
  for (const line of lines) {
    const parsed = parseTests(line);
    if (parsed.expressions.length) {
      //console.log({
      //  expressions: parsed.expressions,
      //  scripts: parsed.scripts,
      //  supported: isSupported(parsed),
      //  line
      //});
      if (isSupported(parsed)) {
        if (parsed.scripts && parsed.scripts.length) {
          //valid
          parsed.scripts.forEach((script, index) => {
            parsed.expressions.forEach(expression => {
              if (parsed.scripts.length > 1 && expression.indexOf('*') === -1) {
                throw new Error(
                  'More than one script for a non range descriptor'
                );
              }
              const fixture = {};
              fixture.expression = expression;
              fixture.script = script;
              if (expression.indexOf('*') !== -1) {
                fixture.index = index;
              }
              if (expression.indexOf('#') === -1) {
                fixture.checksumRequired = false;
              }
              valid.push(fixture);
            });
          });
        } else {
          //invalid
          parsed.expressions.forEach(expression => {
            const fixture = {};
            fixture.expression = expression;
            if (expression.indexOf('#') === -1) {
              fixture.checksumRequired = false;
            }
            invalid.push(fixture);
          });
        }
      }
    }
  }
  const fixtures = { valid, invalid };
  const contents = `// Copyright (c) 2023 Jose-Luis Landabaso - https://bitcoinerlab.com
// Distributed under the MIT software license

//This file is generated automatically. Do not edit it!

export const fixtures = ${JSON.stringify(fixtures, null, 2)};`;
  const fullPath = path.join(__dirname, './fixtures', 'bitcoinCore.js');
  fs.writeFile(fullPath, contents, err => {
    if (err) throw err;
    console.log('Bitcoin Core fixtures file created.');
  });
});
