#!/usr/bin/env node

const program = require('commander')
const fs = require('fs-extra');
const { parse } = require('json2csv');
const pkg = require('./package.json')

let stdin = ''

program
  .version(pkg.version)
  .option('-i, --input [input]', 'input file')
  .option('-f, --fatal-exit-code', 'exit with code 1 if vulnerabilities were found')
  .action(async (cmd, env) => {
    try {
      let data;
      if (cmd.input) {
        data = await fs.readJson(cmd.input)
      } else if (stdin) {
        data = JSON.parse(stdin)
      } else {
        console.log('No input')
        return process.exit(1)
      }

      let finalData = [];
      if (data && Object.keys(data.vulnerabilities).length) {
        for (let key in data.vulnerabilities) {
          if (data.vulnerabilities.hasOwnProperty(key) && data.vulnerabilities[key].via && data.vulnerabilities[key].via.length > 0) {
            for (let i = 0; i < data.vulnerabilities[key].via.length; i++) {
              let row = {
                ["Package Name"]: data.vulnerabilities[key].name,
                ["Severity"]: data.vulnerabilities[key].severity,
              };

              if (typeof data.vulnerabilities[key].via[i] === 'string') {
                row['Vulnerability Found in'] = data.vulnerabilities[key].via[i];
                row['Vulnerability'] = '';
                row['Adivisory'] = '';
              } else {
                row['Vulnerability Found in'] = data.vulnerabilities[key].via[i].name;
                row['Vulnerability'] = data.vulnerabilities[key].via[i].title;
                row['Adivisory'] = data.vulnerabilities[key].via[i].url;
              }
              
              finalData.push(row);
            }

          }
        }
      }

      await generateCSV(finalData, cmd.fatalExitCode)
    } catch (err) {
      console.log('Failed to parse NPM Audit JSON!', err)
      return process.exit(1);
    }
  })

async function generateCSV(data, fatalExitCode) {
  const fields = ['Package Name', 'Severity', 'Vulnerability', 'Vulnerability Found in', 'Adivisory'];
  const opts = { fields };

  try {
    const csv = parse(data, opts);
    await fs.writeFile('./npm-audit.csv', csv, 'utf8');
    return process.exit(fatalExitCode && data.length > 0 ? 1 : 0);
  } catch (err) {
    console.error(err);
    return process.exit(1);
  }
}

if (process.stdin.isTTY) {
  program.parse(process.argv)
} else {
  process.stdin.on('readable', function () {
    const chunk = this.read()
    if (chunk !== null) {
      stdin += chunk
    }
  })
  process.stdin.on('end', function () {
    program.parse(process.argv)
  })
}