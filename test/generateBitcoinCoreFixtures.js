// Copyright (c) 2023 Jose-Luis Landabaso - https://bitcoinerlab.com
// Distributed under the MIT software license

// Generate fixtures from Bitcoin Core tests.
const fs = require('fs');
const path = require('path');

const parseTests = str => {
  const argsRegex = /(?:Check|CheckUnparsable)\((.*)\)/;
  const match = str.match(argsRegex);
  if (!match) return { descs: [], scripts: [] };
  const argsString = match[1];
  let currentArg = '';
  let inString = false;
  let bracesLevel = 0;
  const descs = [];
  let scripts;
  let descsDone = false;
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
        if (descsDone === false) {
          descs.push(currentArg.trim().slice(1, -1));
        }
      } else {
        descsDone = true;
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
  //remove duplicated descs
  return { descs: [...new Set(descs)], scripts };
};

const isSupported = parsed => {
  let supported = true;
  parsed.descs.forEach(desc => {
    if (desc.match(/tr\(/)) supported = false;
    if (desc.match(/^multi\(/)) supported = false; //Top-level multi not supported; It must be within sh or wsh
    if (desc.match(/combo\(/)) supported = false;
    if (desc.match(/sortedmulti\(/)) supported = false;
    if (desc.match(/raw\(/)) supported = false;
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
    if (parsed.descs.length) {
      //console.log({
      //  descs: parsed.descs,
      //  scripts: parsed.scripts,
      //  supported: isSupported(parsed),
      //  line
      //});
      if (isSupported(parsed)) {
        if (parsed.scripts && parsed.scripts.length) {
          //valid
          parsed.scripts.forEach((script, index) => {
            parsed.descs.forEach(desc => {
              if (parsed.scripts.length > 1 && desc.indexOf('*') === -1) {
                throw new Error(
                  'More than one script for a non range descriptor'
                );
              }
              const fixture = {};
              fixture.desc = desc;
              fixture.script = script;
              if (desc.indexOf('*') !== -1) {
                fixture.index = index;
              }
              if (desc.indexOf('#') === -1) {
                fixture.checksumRequired = false;
              }
              valid.push(fixture);
            });
          });
        } else {
          //invalid
          parsed.descs.forEach(desc => {
            const fixture = {};
            fixture.desc = desc;
            if (desc.indexOf('#') === -1) {
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
