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
			if (data && Object.keys(data.advisories).length) {
				for (let key in data.advisories) {
					if (data.advisories.hasOwnProperty(key)) {
						let packageName = data.advisories[key].findings[0].paths[0].split('>')[0];

						finalData.push({
							["Severity"]: data.advisories[key].severity,
							["Vulnerability"]: data.advisories[key].title,
							["Package Name"]: data.advisories[key].module_name,
							["Vulnerability Found in"]: packageName,
							["Path"]: data.advisories[key].findings[0].paths[0],
							["How to fix"]: data.advisories[key].recommendation,
							["Adivisory"]: data.advisories[key].url,
							["References"]: data.advisories[key].references
						});
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
	const fields = ['Severity', 'Vulnerability', 'Package Name', 'Vulnerability Found in', 'Path', 'Vulnerability Details', 'How to fix', 'Adivisory', 'References'];
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