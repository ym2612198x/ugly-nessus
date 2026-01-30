import csv
import re
import argparse
import os
import io
import sys


# colours
RST = '\033[0;39m'
INFO = '\033[36m'
BAD = '\033[31m'
GOOD = '\033[34m'
DETAIL = '\033[33m'
GREY = '\033[90m'
OTHER = '\033[38;5;208m'


# just csv things
csv.field_size_limit(1000000)


# skipped findings list
skipped_findings = {
    "Nessus Scan Information",
    "Traceroute Information",
    "Common Platform Enumeration (CPE)",
    "ICMP Timestamp Request Remote Date Disclosure",
    "OS Identification Failed",
    "Open Port Re-check",
    "Do not scan printers",
    "Device Type",
    "DCE Services Enumeration",
    "Service Detection (GET request)"
}


# args
arg_parser = argparse.ArgumentParser(description='Export vulnerabilities from a Nessus .csv report file.')
arg_parser.add_argument('-i', '--input', required=True, help='Input filename')
arg_parser.add_argument('-o', '--output', required=True, help='Output filename')
arg_parser.add_argument('-I', '--info', help='Include INFO items', action='store_true')
arg_parser.add_argument('-O', '--poutput', help='Include plugin output', action='store_true')
arg_parser.add_argument('-d', '--desc', help='Include plugin description', action='store_true')
arg_parser.add_argument('-x', '--ip', help='Include extra info for hosts (ip address or "No FQDN found")', action='store_true')
arg_parser.add_argument('-C', '--cve', help='Include CVE column in output', action='store_true')
arg_parser.add_argument('-v', '--verbose', help='Verbose output', action='store_true')
args = arg_parser.parse_args()
nessus_file = args.input
output_file = args.output


def vprint(text):

    if args.verbose:
        print(text)


def vinput():
    
    if args.verbose:
        input("Press a key to continue: ")


def banner(input_file, output_file): # domain

    print(f"""{BAD}
         __   __  _______  ___      __   __         __    _  _______  _______  _______  __   __  _______ 
        |  | |  ||       ||   |    |  | |  |       |  |  | ||       ||       ||       ||  | |  ||       |
        |  | |  ||    ___||   |    |  |_|  | ____  |   |_| ||    ___||  _____||  _____||  | |  ||  _____|
        |  |_|  ||   | __ |   |    |       ||____| |       ||   |___ | |_____ | |_____ |  |_|  || |_____ 
        |       ||   ||  ||   |___ |_     _|       |  _    ||    ___||_____  ||_____  ||       ||_____  |
        |       ||   |_| ||       |  |   |         | | |   ||   |___  _____| | _____| ||       | _____| |
        |_______||_______||_______|  |___|         |_|  |__||_______||_______||_______||_______||_______|
        {RST} v4.0 (v&c 2.0)

        
        {INFO}[*] In file:\t{DETAIL}{input_file}{RST}
        {INFO}[*] Out file:\t{DETAIL}{output_file}{RST}
        {INFO}[*] Info:\t{DETAIL}{args.info}{RST}
        {INFO}[*] Desc:\t{DETAIL}{args.desc}{RST}
        {INFO}[*] Extra:\t{DETAIL}{args.ip}{RST}
        {INFO}[*] Output:\t{DETAIL}{args.poutput}{RST}
        {INFO}[*] CVE(s):\t{DETAIL}{args.cve}{RST}
        {INFO}[*] Verbose:\t{DETAIL}{args.verbose}{RST}

        """)


def get_fqdns_from_csv_file(csv_input_filename):

    # search the csv for fqdns and hostnames to match with ip addresses
    print(f"{INFO}[*] Searching for FQDNs in Nessus CSV file...{RST}")

    # plugin parsing functions - these are the only ones ive identified that reveal a hostname
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

    # dict to store fqdns
    fqdn_dict = {}

    with open(csv_input_filename, "r", encoding="utf-8") as csv_input_file:
        reader = csv.reader(csv_input_file)
        header = next(reader)
        header_idx = {name: idx for idx, name in enumerate(header)}

        # flatten host -> plugin_id: output
        host_plugins = {}
        for row in reader:
            host = row[header_idx["Host"]]
            plugin_id = row[header_idx["Plugin ID"]]
            plugin_output = row[header_idx["Plugin Output"]]
            host_plugins.setdefault(host, {})[plugin_id] = plugin_output

    # ip regex
    ip_pattern = re.compile(r'\d{1,3}(\.\d{1,3}){3}')

    for host, plugins in host_plugins.items():
        vprint(f"{INFO}\n[*] Host: {DETAIL}{host}{RST}")

        if host in fqdn_dict and fqdn_dict[host] != "No FQDN identified":
            vprint(f"[+] {host} is already in fqdn dict: {DETAIL}{fqdn_dict[host]}{RST}")
            continue

        if not ip_pattern.fullmatch(host):
            vprint(f"[+] {host} is already an fqdn, no need to search")
            fqdn_dict[host] = host.upper()
            continue
        else:
            vprint(f"[*] {host} is an IP")

        fqdn_found = False
        # try plugins in priority order
        for plugin_id in ["42410", "12053","108761","35371","12218","10150","46180","45410","10800","10785", "42981", "83298", "66717", "10674"]:
            if plugin_id in plugins:
                plugin_output = plugins[plugin_id]
                vprint(f"[*] Trying to get FQDN from plugin {plugin_id}...")
                try:
                    fqdn = plugin_parsers[plugin_id](plugin_output)
                except Exception as e:
                    vprint(f"{BAD}[-] Failed to parse plugin {plugin_id} output: {e}{RST}")
                    vprint(f"{INFO}[*] Raw plugin output:{RST}{BAD}{plugin_output}{RST}")
                else:
                    fqdn_dict[host] = fqdn.upper()
                    fqdn_found = True
                    vprint(f"[+] Added {host} to fqdn dict: {fqdn}")
                    break

        if not fqdn_found:
            fqdn_dict[host] = "No FQDN identified"
            vprint(f"{BAD}[-] No FQDN identified for: {DETAIL}{host}{RST}")

    # get percentage of fqdns identified
    total = len(fqdn_dict)
    not_eq = sum(1 for x in fqdn_dict.values() if x != "No FQDN identified")
    percent = round((not_eq / total) * 100, 1) if total else 0

    return fqdn_dict, percent


def get_csv_value(row, rows_index_dict, field_name, default="", replace_newlines=False):
    try:
        val = row[rows_index_dict[field_name]]
        if replace_newlines:
            val = val.replace("\n", " ").replace("\t", " ")
        return val
    except Exception as e:
        vprint(f"{BAD}[-] Error reading {field_name}: {DETAIL}{e}{RST}")
        return default


def get_all_findings_from_csv_data(csv_data):

    print(f"{INFO}[*] Retrieving findings...{RST}")
    # used to return the number of hosts and findings at the finish line
    host_set = set()

    # here we get list of all findings then trim it down later based on user options
    # eg if they want to remove info items
    all_findings_list = []

    # dictionary that will contain the index of the rows we need
    rows_index_dict = {}

    # dictionary of findings and affected hosts+ports
    findings_and_affected_hosts_dict = {}

    # list of the findings we've seen before
    # each iteration where we see a new finding
    # we add it to this list
    findings_seen_before = []

    # get the header row to find our indexes
    header = next(csv_data)
    rows_we_need = ["Risk", "Host", "Port", "Name", "Description", "Plugin Output", "CVE"]

    # loop through to make sure we have all the required rows
    # add them to our rows index dict
    # just exit if we cant find the row, good enough
    vprint(f"{OTHER}[*] ROW CHECK")
    for header_row in rows_we_need:
        if header_row in header:
            # eg row_index = header.index("Risk")
            # row_index == 0
            row_index = header.index(header_row)
            vprint(f"{OTHER}[+] Found {DETAIL}{header_row}{RST} {OTHER}at column: {DETAIL}{str(row_index)}{RST}")
            # eg rows_index_dict["Risk"] = 0
            rows_index_dict[header_row] = row_index
        else:
            vprint(f"{BAD}[-] Couldn't find row: {DETAIL}{header_row}{RST}")
            quit()
    vprint(f"")

    # now we have the rows we need
    # we can get data from the rows
    vprint(f"{OTHER}[*] Getting findings data{RST}")
    severity_map = {
        "None": "5 - Info",
        "Low": "4 - Low",
        "Medium": "3 - Medium",
        "High": "2 - High",
        "Critical": "1 - Critical"
    }

    for csv_data_row in csv_data:
        # finding cve
        finding_cve = csv_data_row[rows_index_dict['CVE']] if 'CVE' in rows_index_dict else ""

        # finding severity
        finding_severity = csv_data_row[rows_index_dict["Risk"]]
        finding_severity = severity_map.get(finding_severity, finding_severity)

        # finding description
        finding_desc = csv_data_row[rows_index_dict['Description']] or ""
        finding_desc = finding_desc.replace("\n", " ").replace("\t", " ")

        # host
        finding_host = csv_data_row[rows_index_dict['Host']] or ""
        host_set.add(finding_host)

        # plugin output
        finding_output = csv_data_row[rows_index_dict['Plugin Output']] or ""

        # port
        finding_port = csv_data_row[rows_index_dict['Port']] or ""
        finding_host_and_port = f"{finding_host}:{finding_port}"

        # finding name
        finding_name = csv_data_row[rows_index_dict["Name"]] or ""
        all_findings_list.append(finding_name)
        entry = findings_and_affected_hosts_dict.setdefault(finding_name, {
            "affected": [],
            "description": finding_desc,
            "severity": finding_severity,
            "output": finding_output,
            "cve": []  # now a list to store multiple CVEs
        })

        # add CVE if not already present
        if finding_cve and finding_cve not in entry["cve"]:
            entry["cve"].append(finding_cve)

        # add host/port if not already present
        if finding_host_and_port not in entry["affected"]:
            entry["affected"].append(finding_host_and_port)
 
    unique_findings_and_affected_hosts_dict = dict(sorted(findings_and_affected_hosts_dict.items(), key=lambda item: (item[1]["severity"], item[0].lower())))

    return unique_findings_and_affected_hosts_dict, host_set, all_findings_list


def trim_findings(findings_and_affected_dict, fqdn_dict): # domain

    print(f"{INFO}[*] Trimming findings...{RST}")

    # dict to return when we've finished
    trimmed_findings_and_affected_hosts_dict = {}

    for finding, value in findings_and_affected_dict.items():
        if finding in skipped_findings:
            vprint(f"{GOOD}[*] {DETAIL}{finding} {GOOD}is in skipped findings, not adding{RST}")
            continue
        if not args.info and value["severity"] == "5 - Info":
            vprint(f"{OTHER} Removing item with severity: {DETAIL}{value['severity']}{RST}")
            continue
        trimmed_findings_and_affected_hosts_dict[finding] = value

    for key, value in trimmed_findings_and_affected_hosts_dict.items():      
        # loop through list of affected hosts and ports
        for i in range(len(value["affected"])):
            finding_host_and_port = value["affected"][i]
            host, port = finding_host_and_port.split(":")

            new_value = fqdn_dict.get(host, "No FQDN identified")

            if new_value == "No FQDN identified":
                value["affected"][i] = f"{host}:{port} (No FQDN identified)"
            else:
                # if args.domain:
                #     value["affected"][i] = f"{new_value}.{domain}:{port} ({host})"
                # else:
                value["affected"][i] = f"{new_value}:{port} ({host})"
 
    print("\n")
    for value in trimmed_findings_and_affected_hosts_dict.values():
        value["affected"].sort()
    return trimmed_findings_and_affected_hosts_dict    


def print_findings(trimmed_findings):

    # these are finding severity counters
    # used in the summary
    info = 0
    low = 0
    med = 0
    high = 0
    crit = 0

    print("")
    for x,y in trimmed_findings.items():
        # get name
        name = x
        # get severity
        severity = y['severity']
        if severity == '5 - Info':
            info += 1
        elif severity == '4 - Low':
            low += 1
        elif severity == '3 - Medium':
            med += 1
        elif severity == '2 - High':
            high += 1
        elif severity == '1 - Critical':
            crit += 1
        print(f"{INFO}[*] Severity:\t\t{DETAIL}{severity}{RST}")
        print(f"{INFO}[*] Name:\t\t{DETAIL}{name}{RST}")
        if args.cve and y["cve"]:
            # join multiple CVEs with commas
            print(f"{INFO}[*] CVE(s):\t\t{DETAIL}{', '.join(y['cve'])}{RST}")
        if args.desc:
            # newline looks better than tab
            print(f"{INFO}[*] Desc:\n{GREY}{y['description']}{RST}")
        # print output, recreate newlines
        # sorry
        if args.poutput:
            print(f"{INFO}[*] Output:")
            output = y["output"]
            output = output.replace("!@#", "\n")
            output = output.strip()
            print(f"{GREY}{output}{RST}")
            print("")

        #print affected
        affected = y["affected"]
        print(f"{GOOD}[*] Affected Hosts:\t{RST}{DETAIL}{len(affected)}{RST}")
        for host in affected:
            if " (" in host:
                fqdn = host.split(" (")[0]
                if fqdn.endswith(":0"):
                    fqdn = fqdn[:-2]
                if args.ip:
                    ip = host.split(" (")[1]
                    ip = ip.split(")")[0]
                    print(f"{OTHER}{fqdn} {GREY}({ip}){RST}")
                else:
                    print(f"{OTHER}{fqdn}{RST}") 
            else:
                if host.endswith(":0"):
                    host = host[:-2]
                print(f"{OTHER}{host}{RST}")
        print("\n")

    # return the counters
    return info, low, med, high, crit


def write_findings(trimmed_findings):

    output_file = os.path.expanduser(args.output)
    
    with open(output_file, "w") as f:
        for x,y in trimmed_findings.items():
            f.write(f"[*] Severity:\t\t{y['severity']}\n")
            f.write(f"[*] Name:\t\t{x}\n")
            if args.cve and y["cve"]:
                # join multiple CVEs with commas
                f.write(f"[*] CVE(s):\t\t{', '.join(y['cve'])}\n")
            if args.desc:
                f.write(f"[*] Desc:\n{y['description']}\n")
            if args.poutput:
                f.write(f"[*] Output:\n")
                output = y["output"]
                output = output.replace("!@#", "\n")
                output = output.strip()
                f.write(f"{output}\n")
            affected = y["affected"]
            f.write(f"[*] Affected Hosts:\t{len(affected)}\n")
            for host in affected:
                if " (" in host:
                    fqdn = host.split(" (")[0]
                    if fqdn.endswith(":0"):
                        fqdn = fqdn[:-2]
                    if args.ip:
                        ip = host.split(" (")[1]
                        ip = ip.split(")")[0]
                        f.write(f"{fqdn} ({ip})\n")
                    else:
                        f.write(f"{fqdn}\n")
                else:
                    if host.endswith(":0"):
                        host = host[:-2]
                    f.write(f"{host}\n")
            f.write("\n")


def summary(amt_of_hosts, amt_of_findings_including_skipped, amt_of_findings, info, low, med, high, crit, percent):

    print("")
    print(f"{INFO}[*] Total hosts:\t{DETAIL}{amt_of_hosts}{RST}")
    print(f"{INFO}[*] Total findings:\t{DETAIL}{amt_of_findings_including_skipped}{RST}")
    print(f"{INFO}[*] Post-trim findings:\t{DETAIL}{amt_of_findings}{RST}")
    print(f"{INFO}[*] FQDNs identified:\t{DETAIL}{percent}%{RST}")
    print("")
    print(f"{GREY}[*] Info:\t\t{DETAIL}{info}{RST}")
    print(f"{GOOD}[*] Low:\t\t{DETAIL}{low}{RST}")
    print(f"{DETAIL}[*] Medium:\t\t{DETAIL}{med}{RST}")
    print(f"{BAD}[*] High:\t\t{DETAIL}{high}{RST}")
    print(f"{OTHER}[*] Critical:\t\t{DETAIL}{crit}{RST}")
    print("")


# main
banner(nessus_file, output_file) # domain

# find out what type of file we have
extension = os.path.splitext(nessus_file)[1]

# if not csv
if extension != ".csv":
    print(f"{BAD}[-] Invalid file type: {DETAIL}{nessus_file}{RST}")
    quit(-1)

# run the fqdn getter function
fqdn_dict, percent = get_fqdns_from_csv_file(nessus_file)
# sort the dict
sorted_fqdn_dict = dict(sorted(fqdn_dict.items()))
# then get the csv data
with open(nessus_file, newline='', encoding='utf-8') as f:
    csv_data = csv.reader(f)

    # get all of the findings and details from the csv data
    findings_and_affected_hosts_dict, host_set, all_findings_list = get_all_findings_from_csv_data(csv_data)


    # trim out the ones we dont need and stuff based on user prefs
    # then sort it
    trimmed_findings = trim_findings(findings_and_affected_hosts_dict, sorted_fqdn_dict) # domain

    # get amount of findings for summary
    amt_of_findings = len(trimmed_findings) 


    # print the trimmed findings and return the amount
    # of findings for each risk level
    info, low, med, high, crit = print_findings(trimmed_findings)


    # write to file
    write_findings(trimmed_findings)


    # get amount of hosts and findings for summary
    y = list(set(all_findings_list))
    amt_of_hosts = str(len(host_set))
    amt_of_findings_including_skipped = str(len(y))


    # print the summary
    summary(amt_of_hosts, amt_of_findings_including_skipped, amt_of_findings, info, low, med, high, crit, percent)
