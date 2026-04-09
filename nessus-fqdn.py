import csv
import re
import argparse

csv.field_size_limit(1000000)

arg_parser = argparse.ArgumentParser(description='Extract IP -> FQDN mappings from a Nessus CSV.')
arg_parser.add_argument('-i', '--input', required=True, help='Input Nessus CSV file')
arg_parser.add_argument('-o', '--output', help='Output file (default: stdout)')
arg_parser.add_argument('-v', '--verbose', action='store_true', help='Verbose output')
args = arg_parser.parse_args()


def vprint(text):
    if args.verbose:
        print(text)


plugin_parsers = {
    "42410": lambda out: out.split("gathered :")[1].split(" = Computer name")[0].split("\n")[-1].strip().lower(),
    "12053": lambda out: out.split("resolves as ")[1].strip().lower().rstrip("."),
    "108761": lambda out: out.split("DNS Computer Name:")[1].split("\n")[0].strip().lower(),
    "35371": lambda out: out.replace("\n","").split(" :")[1].strip().lower(),
    "12218": lambda out: out.split("mDNS hostname")[1].split(":")[1].split("\n")[0].strip().lower().rstrip("."),
    "10785": lambda out: (
        out.split("DNS Computer Name:")[1].split("\n")[0].strip().lower()
        if "DNS Computer Name:" in out else
        out.split("NetBIOS Computer Name:")[1].split("\n")[0].strip().lower()
        if "NetBIOS Computer Name" in out else
        out.split("The remote SMB Domain Name is : ")[1].split("\n")[0].strip().lower()
    ),
    "10150": lambda out: out.split("gathered :")[1].split(" = Computer name")[0].split("\n")[-1].strip().lower(),
    "46180": lambda out: out.split("- ")[1].strip().lower(),
    "45410": lambda out: out.split(":")[1].split("\n")[0].strip().lower(),
    "10800": lambda out: out.split("sysName")[1].split(":")[1].split("\n")[0].strip().lower(),
    "42981": lambda out: out.split("Subject          : CN=")[1].split("\n")[0].strip().lower(),
    "83298": lambda out: out.split("Subject   : CN=")[1].split("\n")[0].strip().lower(),
    "66717": lambda out: out.split("mDNS hostname       : ")[1].split("\n")[0].strip().lower(),
    "10674": lambda out: out.split("ServerName   : ")[1].split("\n")[0].strip().lower()
}

PLUGIN_PRIORITY = ["42410","12053","108761","35371","12218","10150","46180","45410","10800","10785","42981","83298","66717","10674"]
ip_pattern = re.compile(r'\d{1,3}(\.\d{1,3}){3}')


def get_fqdns(csv_filename):
    host_plugins = {}

    with open(csv_filename, "r", encoding="utf-8") as f:
        reader = csv.reader(f)
        header = next(reader)
        idx = {name: i for i, name in enumerate(header)}

        for row in reader:
            host = row[idx["Host"]]
            plugin_id = row[idx["Plugin ID"]]
            plugin_output = row[idx["Plugin Output"]]
            host_plugins.setdefault(host, {})[plugin_id] = plugin_output

    fqdn_dict = {}

    for host, plugins in host_plugins.items():
        if not ip_pattern.fullmatch(host):
            vprint(f"[+] {host} is already an FQDN")
            fqdn_dict[host] = host.upper()
            continue

        fqdn_found = False
        for plugin_id in PLUGIN_PRIORITY:
            if plugin_id in plugins:
                vprint(f"[*] {host}: trying plugin {plugin_id}")
                try:
                    fqdn = plugin_parsers[plugin_id](plugins[plugin_id])
                    fqdn_dict[host] = fqdn.upper()
                    fqdn_found = True
                    vprint(f"[+] {host} -> {fqdn.upper()}")
                    break
                except Exception as e:
                    vprint(f"[-] Plugin {plugin_id} failed for {host}: {e}")

        if not fqdn_found:
            fqdn_dict[host] = "No FQDN identified"
            vprint(f"[-] No FQDN identified for {host}")

    return fqdn_dict


fqdn_dict = get_fqdns(args.input)
lines = [f"{ip}\t{fqdn}" for ip, fqdn in sorted(fqdn_dict.items())]

if args.output:
    with open(args.output, "w") as f:
        f.write("\n".join(lines) + "\n")
    print(f"Written to {args.output}")
else:
    print("\n".join(lines))
                            
