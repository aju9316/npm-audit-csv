# npm-audit-csv 
utility to export npm audit results in csv format

### ⭐ Works with updated npm audit  output

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
$ npm audit --json | npm-audit-csv --fatal-exit-code
```

## license
[MIT](https://github.com/aju9316/npm-audit-csv/blob/master/LICENSE)