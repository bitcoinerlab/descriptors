// Copyright (c) 2023 Jose-Luis Landabaso - https://bitcoinerlab.com
// Distributed under the MIT software license

// Generate fixtures from Bitcoin Core tests.
const fs = require('fs');
const { argv } = require('yargs')
  .option('i', {
    alias: 'input',
    description: 'Input file path',
    type: 'string'
  })
  .option('o', {
    alias: 'output',
    description: 'Output file path',
    type: 'string'
  })
  .help()
  .alias('help', 'h');

const { input, output } = argv;

if (!input) {
  console.error("Input file not specified. Use '-i' to specify.");
  process.exit(1);
}

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
    if (expression.match(/tr\(.*,.*\)/)) supported = false; // tr(KEY) supported. Disable when 2 param (contains a comma)
    if (expression.match(/^multi\(/)) supported = false; //Top-level multi not supported; It must be within sh or wsh
    if (expression.match(/combo\(/)) supported = false;
    if (expression.match(/^sortedmulti\(/)) supported = false; //Top-level sortedmulti not supported; It must be within sh or wsh
    if (expression.match(/raw\(/)) supported = false;
  });
  return supported;
};

const valid = [];
const invalid = [];

// Use the 'utf8' encoding when reading the file
fs.readFile(input, 'utf8', (err, data) => {
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
              fixture.descriptor = expression;
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
            fixture.descriptor = expression;
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
  if (output) {
    fs.writeFile(output, contents, err => {
      if (err) throw err;
      console.log('Bitcoin Core fixtures file created.');
    });
  } else {
    console.log(contents);
  }
});
