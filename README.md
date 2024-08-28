# ugly-nessus

usage: ugly-nessus.py [-h] -i INPUT -o OUTPUT [-I] [-d] [-v]

Export vulnerabilities from a Nessus .csv report file, and maybe also a .nessus file.

Options:
```

  -i INPUT, --input INPUT
                        Input filename
  -o OUTPUT, --output OUTPUT
                        Output filename
  -I, --info            Include INFO items
  -O, --poutput         Include plugin output
  -d, --desc            Include plugin description
  -D DOMAIN, --domain DOMAIN
                        Append this value to incomplete FQDNs (ie. machine1 becomes machine1.domain.local)
  -x, --ip              Include extra info for hosts (ip address or "No FQDN found")
  -v, --verbose         Verbose output

```
