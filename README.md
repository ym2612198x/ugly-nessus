# ugly-nessus

usage: ugly-nessus.py [-h] -i INPUT -o OUTPUT [-I] [-d] [-v] [-x] [-C] [-O]

Export vulnerabilities from a Nessus .csv report file.

Options:
```
  -i INPUT, --input INPUT     Input filename  
  -o OUTPUT, --output OUTPUT  Output filename
  -I, --info                  Include INFO items
  -O, --poutput               Include plugin output
  -d, --desc                  Include plugin description
  -x, --ip                    Include extra info for hosts (ip address or "No FQDN found")
  -C, --cve                   Include CVE column in output
  -v, --verbose               Verbose output
```
