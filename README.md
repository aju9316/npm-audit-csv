# npm-audit-csv 
utility to export npm audit results in csv format

## installation
```
npm install -g npm-audit-csv
```

## usage
```
$ npm audit --json | npm-audit-csv
```
By default the report will be saved to `npm-audit.csv`

If you'd like the generator to exit with non-zero exit code when vulnerabilities are found, you can add the --fatal-exit-code option:

```
$ npm audit --json | npm-audit-html --fatal-exit-code
```

## acknowledgements
This project was inspired by [npm-audit-html](https://www.npmjs.com/package/npm-audit-html)

## license
[MIT](https://github.com/aju9316/npm-audit-csv/blob/master/LICENSE)
