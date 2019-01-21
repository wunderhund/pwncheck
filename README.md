# pwncheck
Python3 script for submitting e-mail addresses to the haveibeenpwned API (https://haveibeenpwned.com/API/v2)

The script takes a single e-mail address or an newline-delimited text file as input. The input file should contain only e-mail addresses, one per line, as arguments.

```
usage: pwncheck.py [-h] [-v] [-i INFILE] [-o OUTFILE] [-d] [email]

positional arguments:
  email                 E-mail address for single query

optional arguments:
  -h, --help            show this help message and exit
  -v, --verbose         Verbose output (JSON)
  -i INFILE, --infile INFILE
                        Input file with e-mail addresses
  -o OUTFILE, --outfile OUTFILE
                        CSV output file
  -d, --debug           Print debug messages
```

## Examples
```
./pwncheck.py a@aa.com
./pwncheck.py -i emails.txt
./pwncheck.py -i emails.txt -o breaches.csv
./pwncheck.py -i emails.txt -o breaches.csv a@aaa.com