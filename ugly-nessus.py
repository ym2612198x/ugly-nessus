import csv
import re
import argparse
import os
import io
import xml.etree.ElementTree as etree


# colours
RST = '\033[0;39m'
INFO = '\033[36m'
BAD = '\033[31m'
GOOD = '\033[34m'
DETAIL = '\033[33m'
GREY = '\033[90m'
OTHER = '\033[38;5;208m'


csv.field_size_limit(1000000)


skipped_findings = [
    "Nessus Scan Information",
    "Traceroute Information",
    "Common Platform Enumeration (CPE)",
    "ICMP Timestamp Request Remote Date Disclosure",
    "OS Identification Failed",
    "Open Port Re-check",
    "Do not scan printers",
    "ICMP Timestamp Request Remote Date Disclosure",
    "Device Type",
    "DCE Services Enumeration",
    "Service Detection (GET request)"
    ]



# args
arg_parser = argparse.ArgumentParser(description='Export vulnerabilities from a Nessus .nessus or .csv file.')
arg_parser.add_argument('-i', '--input', required=True, help='Input filename')
arg_parser.add_argument('-o', '--output', required=True, help='Output filename')
arg_parser.add_argument('-I', '--info', help='Include INFO items', action='store_true')
arg_parser.add_argument('-O', '--poutput', help='Include plugin output', action='store_true')
arg_parser.add_argument('-d', '--desc', help='Include plugin description', action='store_true')
arg_parser.add_argument('-D', '--domain', help='Append this value to incomplete FQDNs (ie. machine1 becomes machine1.domain.local)')
arg_parser.add_argument('-x', '--ip', help='Include extra info for hosts (ip address or "No FQDN found")', action='store_true')
arg_parser.add_argument('-v', '--verbose', help='Verbose output', action='store_true')
args = arg_parser.parse_args()
nessus_file = args.input
output_file = args.output
domain = args.domain


def vprint(text):

    if args.verbose:
        print(text)


def vinput():
    
    if args.verbose:
        input("Press a key to continue: ")


def banner(input_file, output_file, domain):

    print(f"""{BAD}
         __   __  _______  ___      __   __         __    _  _______  _______  _______  __   __  _______ 
        |  | |  ||       ||   |    |  | |  |       |  |  | ||       ||       ||       ||  | |  ||       |
        |  | |  ||    ___||   |    |  |_|  | ____  |   |_| ||    ___||  _____||  _____||  | |  ||  _____|
        |  |_|  ||   | __ |   |    |       ||____| |       ||   |___ | |_____ | |_____ |  |_|  || |_____ 
        |       ||   ||  ||   |___ |_     _|       |  _    ||    ___||_____  ||_____  ||       ||_____  |
        |       ||   |_| ||       |  |   |         | | |   ||   |___  _____| | _____| ||       | _____| |
        |_______||_______||_______|  |___|         |_|  |__||_______||_______||_______||_______||_______|
        {RST} v3.2c (via vie dnsdump.exe stars align rpc dcc)

        
        {INFO}[*] In file:\t{DETAIL}{input_file}{RST}
        {INFO}[*] Out file:\t{DETAIL}{output_file}{RST}
        {INFO}[*] Info:\t{DETAIL}{args.info}{RST}
        {INFO}[*] Desc:\t{DETAIL}{args.desc}{RST}
        {INFO}[*] Extra:\t{DETAIL}{args.ip}{RST}
        {INFO}[*] Output:\t{DETAIL}{args.poutput}{RST}
        {INFO}[*] Verbose:\t{DETAIL}{args.verbose}{RST}
        {INFO}[*] Domain:\t{DETAIL}{domain}{RST}

        """)


def get_fqdns_from_csv_file(csv_input_filename):

    # this function tries to find fqdns for each host
    print(f"{INFO}[*] Searching for FQDNs in Nessus CSV file...{RST}")
    with open(csv_input_filename, "r", encoding="utf-8") as csv_input_file:
        reader = csv.reader(csv_input_file)
        num_rows = sum(1 for row in reader)
        # vprint(f"{INFO}Number of rows in input file: {DETAIL}{num_rows}{RST}")
        # go back to start after row count
        csv_input_file.seek(0)
        # dict to store header indexes
        # ie "Plugin ID = 1"
        header_dict = {}
        # dict to store hosts and fqdns
        fqdn_dict = {}
        # found variable
        found = False
        # get header
        header = next(reader)
        for index, title in enumerate(header):
            header_dict[title] = index

        # we need to find all the plugin ids that each host has
        # so need to run through the rows and collect plugin ids until the host row no longer matches our host
        host_and_assoc_plugins_dict = {}
        for row in reader:
            host = row[header_dict["Host"]]
            plugin_id = row[header_dict["Plugin ID"]]
            plugin_output = row[header_dict["Plugin Output"]]
            # temp dict
            foo = {}
            try:
                # if an entry for host already exists
                # append the plugin id
                foo[plugin_id] = plugin_output
                host_and_assoc_plugins_dict[host].append(foo)
            except:
                # if it doesnt, create it
                # then append plugin id
                host_and_assoc_plugins_dict[host] = []
                host_and_assoc_plugins_dict[host].append(foo)


        # now loop through the dictionary we created
        for host, plugins_info in host_and_assoc_plugins_dict.items():
            found = False
            vprint(f"{INFO}\n[*] Host: {DETAIL}{host}{RST}")
            # check if already has a none empty fqdn dict entry
            # if its in just go to next row
            if host in fqdn_dict.keys() and fqdn_dict[host] != "No FQDN identified":
                vprint(f"[+] {host} is already in fqdn dict: {DETAIL}{fqdn_dict[host]}{RST}")
                # back to start of loop
                continue
            else:
                vprint(f"[-] {host} is not in fqdn_dict")

            # check if we have an ip or an fqdn
            # if we have an fqdn already we dont need to search
            ip_pattern = r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}'
            ip_regex_match = re.fullmatch(ip_pattern, host)
            if not ip_regex_match:
                vprint(f"[+] {host} is already an fqdn, no need to search")
                # add it to fqdn dict as itself
                fqdn_dict[host] = host
                # back to start of loop
                continue
            else:
                vprint(f"[*] {host} is an IP")

            plugin_id_list = []
            for plugin_info in plugins_info:
                found = False
                for key, value in plugin_info.items():
                    plugin_id_list.append(key)

            plugin_id = "12053"
            vprint(f"[*] First choice: Host Fully Qualified Domain Name (FQDN) Resolution ({plugin_id})")
            # vprint(f"[*] Is {plugin_id} in plugin id list?")
            for x in plugin_id_list:
                # vprint(f"[?] {plugin_id} == {x}?")
                if plugin_id != x:
                    pass
                    # vprint("[-] No")
                else:
                    # vprint("[+] Yes")
                    for a in plugins_info:
                        for b, c in a.items():
                            if b ==  plugin_id:
                                plugin_output = c
                                break
                    vprint(f"[*] Trying to get FQDN from {plugin_id}...")
                    # vprint(plugin_output)
                    try:
                        plugin_output = plugin_output.split("resolves as ")[1]
                        plugin_output = plugin_output.strip()
                        plugin_output = plugin_output.lower()
                        plugin_output = plugin_output[:-1]
                        vprint(f"[+] Added {host} to fqdn dict: {plugin_output}")
                        found = True
                        fqdn_dict[host] = plugin_output
                    except:
                        print(f"{BAD}[-] Failure: {DETAIL}{plugin_id}{RST}")
                        print(f"{INFO}[*] Raw plugin output:{RST}")
                        print(f"{BAD}{plugin_output}{RST}")
                        input(f"{INFO}[*] Press a key to continue{RST}")
                    else:
                        # If the plugin was found and fqdn_dict was updated, exit the loop
                        vprint("[+] FQDN found")
                        break
            if found:
                vprint("[+] Found is true so moving to next host")
                continue

            plugin_id = "108761"
            vprint(f"[*] Second choice: MSSQL Host Information in NTLM SSP ({plugin_id})")
            # vprint(f"[*] Is {plugin_id} in plugin id list?")
            for x in plugin_id_list:
                # vprint(f"[?] {plugin_id} == {x}?")
                if plugin_id != x:
                    # vprint("[-] No")
                    pass
                else:
                    # vprint("[+] Yes")
                    for a in plugins_info:
                        for b, c in a.items():
                            if b ==  plugin_id:
                                plugin_output = c
                                break
                    vprint(f"[*] Trying to get FQDN from {plugin_id}...")
                    # vprint(plugin_output)
                    try:
                        plugin_output = plugin_output.split("DNS Computer Name:")[1]
                        plugin_output = plugin_output.split("\n")[0]
                        plugin_output = plugin_output.strip()
                        plugin_output = plugin_output.lower()
                        vprint(f"added {host} to fqdn dict: {plugin_output}")
                        found = True
                        fqdn_dict[host] = plugin_output
                    except:
                        print(f"{BAD}[-] Failure: {DETAIL}{plugin_id}{RST}")
                        print(f"{INFO}[*] Raw plugin output:{RST}")
                        print(f"{BAD}{plugin_output}{RST}")
                        input(f"{INFO}[*] Press a key to continue{RST}")
                    else:
                        # If the plugin was found and fqdn_dict was updated, exit the loop
                        vprint("[+] FQDN found")
                        break
            if found:
                vprint("[+] Found is true so moving to next host")
                continue

            plugin_id = "35371"
            vprint(f"[*] Third choice: DNS Server hostname.bind Map Hostname Disclosure ({plugin_id})")
            # vprint(f"[*] Is {plugin_id} in plugin id list?")
            for x in plugin_id_list:
                # vprint(f"[?] {plugin_id} == {x}?")
                if plugin_id != x:
                    # vprint("[-] No")
                    pass
                else:
                    # vprint("[+] Yes")
                    for a in plugins_info:
                        for b, c in a.items():
                            if b ==  plugin_id:
                                plugin_output = c
                                break
                    vprint(f"[*] Trying to get FQDN from {plugin_id}...")
                    # vprint(plugin_output)
                    try:
                        plugin_output = plugin_output.replace("\n","")
                        plugin_output = plugin_output.split(" :")[1]
                        plugin_output = plugin_output.strip()
                        plugin_output = plugin_output.lower()
                        vprint(f"added {host} to fqdn dict: {plugin_output}")
                        found = True
                        fqdn_dict[host] = plugin_output
                    except:
                        print(f"{BAD}[-] Failure: {DETAIL}{plugin_id}{RST}")
                        print(f"{INFO}[*] Raw plugin output:{RST}")
                        print(f"{BAD}{plugin_output}{RST}")
                        input(f"{INFO}[*] Press a key to continue{RST}")
                    else:
                        # If the plugin was found and fqdn_dict was updated, exit the loop
                        vprint("[+] FQDN found")
                        break
            if found:
                vprint("[+] Found is true so moving to next host")
                continue

            plugin_id = "12218"
            vprint(f"[*] Fourth choice: mDNS Detection ({plugin_id})")
            # vprint(f"[*] Is {plugin_id} in plugin id list?")
            for x in plugin_id_list:
                # vprint(f"[?] {plugin_id} == {x}?")
                if plugin_id != x:
                    # vprint("[-] No")
                    pass
                else:
                    # vprint("[+] Yes")
                    for a in plugins_info:
                        for b, c in a.items():
                            if b ==  plugin_id:
                                plugin_output = c
                                break
                    vprint(f"[*] Trying to get FQDN from {plugin_id}...")
                    # vprint(plugin_output)
                    try:
                        plugin_output = plugin_output.split("mDNS hostname")[1]
                        plugin_output = plugin_output.split(":")[1]
                        plugin_output = plugin_output.split("\n")[0]
                        plugin_output = plugin_output.strip()
                        plugin_output = plugin_output.lower()
                        plugin_output = plugin_output[:-1]
                        vprint(f"added {host} to fqdn dict: {plugin_output}")
                        found = True
                        fqdn_dict[host] = plugin_output
                    except:
                        print(f"{BAD}[-] Failure: {DETAIL}{plugin_id}{RST}")
                        print(f"{INFO}[*] Raw plugin output:{RST}")
                        print(f"{BAD}{plugin_output}{RST}")
                        input(f"{INFO}[*] Press a key to continue{RST}")
                    else:
                        # If the plugin was found and fqdn_dict was updated, exit the loop
                        vprint("[+] FQDN found")
                        break
            if found:
                vprint("[+] Found is true so moving to next host")
                continue

            plugin_id = "10785"
            vprint(f"[*] Fifth choice: Microsoft Windows SMB NativeLanManager Remote System Information Disclosure ({plugin_id})")        
            # vprint(f"[*] Is {plugin_id} in plugin id list?")
            for x in plugin_id_list:
                # vprint(f"[?] {plugin_id} == {x}?")
                if plugin_id != x:
                    pass
                    # vprint("[-] No")
                else:
                    # vprint("[+] Yes")
                    for a in plugins_info:
                        for b, c in a.items():
                            if b ==  plugin_id:
                                plugin_output = c
                                break
                    vprint(f"[*] Trying to get FQDN from {plugin_id}...")
                    # vprint(plugin_output)
                    try:
                        if "DNS Computer Name:" in plugin_output:
                            plugin_output = plugin_output.split("DNS Computer Name:")[1]
                            plugin_output = plugin_output.split("\n")[0]
                            plugin_output = plugin_output.strip()
                            plugin_output = plugin_output.lower()
                            vprint(f"added {host} to fqdn dict: {plugin_output}")
                            found = True
                            fqdn_dict[host] = plugin_output
                        elif "NetBIOS Computer Name" in plugin_output:
                            plugin_output = plugin_output.split("NetBIOS Computer Name:")[1]
                            plugin_output = plugin_output.split("\n")[0]
                            plugin_output = plugin_output.strip()
                            plugin_output = plugin_output.lower()
                            vprint(f"added {host} to fqdn dict: {plugin_output}")
                            found = True
                            fqdn_dict[host] = plugin_output
                        elif "The remote SMB Domain Name is" in plugin_output:
                            plugin_output = plugin_output.split("The remote SMB Domain Name is : ")[1]
                            plugin_output = plugin_output.split("\n")[0]
                            plugin_output = plugin_output.strip()
                            plugin_output = plugin_output.lower()
                            vprint(f"added {host} to fqdn dict: {plugin_output}")
                            found = True
                            fqdn_dict[host] = plugin_output
                    except:
                        print(f"{BAD}[-] Failure: {DETAIL}{plugin_id}{RST}")
                        print(f"{INFO}[*] Raw plugin output:{RST}")
                        print(f"{BAD}{plugin_output}{RST}")
                        input(f"{INFO}[*] Press a key to continue{RST}")
                    else:
                        # If the plugin was found and fqdn_dict was updated, exit the loop
                        vprint("[+] FQDN found")
                        break
            if found:
                vprint("[+] Found is true so moving to next host")
                continue

            plugin_id = "10150"
            vprint(f"[*] Sixth choice: Windows NetBIOS / SMB Remote Host Information Disclosure ({plugin_id})") 
            # vprint(f"[*] Is {plugin_id} in plugin id list?")
            for x in plugin_id_list:
                # vprint(f"[?] {plugin_id} == {x}?")
                if plugin_id != x:
                    # vprint("[-] No")
                    pass
                else:
                    # vprint("[+] Yes")
                    for a in plugins_info:
                        for b, c in a.items():
                            if b ==  plugin_id:
                                plugin_output = c
                                break
                    vprint(f"[*] Trying to get FQDN from {plugin_id}...")
                    # vprint(plugin_output)
                    try:
                        plugin_output = plugin_output.split("gathered :")[1]
                        plugin_output = plugin_output.split(" = Computer name")[0]
                        plugin_output = plugin_output.split("\n")[-1]
                        plugin_output = plugin_output.strip()
                        plugin_output = plugin_output.lower()
                        vprint(f"added {host} to fqdn dict: {plugin_output}")
                        found = True
                        fqdn_dict[host] = plugin_output
                    except:
                        print(f"{BAD}[-] Failure: {DETAIL}{plugin_id}{RST}")
                        print(f"{INFO}[*] Raw plugin output:{RST}")
                        print(f"{BAD}{plugin_output}{RST}")
                        input(f"{INFO}[*] Press a key to continue{RST}")
                    else:
                        # If the plugin was found and fqdn_dict was updated, exit the loop
                        vprint("[+] FQDN found")
                        break
            if found:
                vprint("[+] Found is true so moving to next host")
                continue

            plugin_id = "46180"
            vprint(f"[*] Sixth choice: Additional DNS Hostnames ({plugin_id})") 
            # vprint(f"[*] Is {plugin_id} in plugin id list?")
            for x in plugin_id_list:
                # vprint(f"[?] {plugin_id} == {x}?")
                if plugin_id != x:
                    # vprint("[-] No")
                    pass
                else:
                    # vprint("[+] Yes")
                    for a in plugins_info:
                        for b, c in a.items():
                            if b ==  plugin_id:
                                plugin_output = c
                                break
                    vprint(f"[*] Trying to get FQDN from {plugin_id}...")
                    # vprint(plugin_output)
                    try:
                        plugin_output = plugin_output.split("- ")[1]
                        plugin_output = plugin_output.strip()
                        plugin_output = plugin_output.lower()
                        vprint(f"added {host} to fqdn dict: {plugin_output}")
                        found = True
                        fqdn_dict[host] = plugin_output
                    except:
                        print(f"{BAD}[-] Failure: {DETAIL}{plugin_id}{RST}")
                        print(f"{INFO}[*] Raw plugin output:{RST}")
                        print(f"{BAD}{plugin_output}{RST}")
                        input(f"{INFO}[*] Press a key to continue{RST}")
                    else:
                        # If the plugin was found and fqdn_dict was updated, exit the loop
                        vprint("[+] FQDN found")
                        break
            if found:
                vprint("[+] Found is true so moving to next host")
                continue

            plugin_id = "45410"
            vprint(f"[*] Seventh choice: SSL Certificate 'commonName' Mismatch ({plugin_id})") 
            # vprint(f"[*] Is {plugin_id} in plugin id list?")
            for x in plugin_id_list:
                # vprint(f"[?] {plugin_id} == {x}?")
                if plugin_id != x:
                    # vprint("[-] No")
                    pass
                else:
                    # vprint("[+] Yes")
                    for a in plugins_info:
                        for b, c in a.items():
                            if b ==  plugin_id:
                                plugin_output = c
                                break
                    vprint(f"[*] Trying to get FQDN from {plugin_id}...")
                    # vprint(plugin_output)
                    try:
                        plugin_output = plugin_output.split(":")[1]
                        plugin_output = plugin_output.split("\n")[0]
                        plugin_output = plugin_output.strip()
                        plugin_output = plugin_output.lower()
                        # vprint(f"added {host} to fqdn dict: {plugin_output}")
                        found = True
                        fqdn_dict[host] = plugin_output
                    except:
                        print(f"{BAD}[-] Failure: {DETAIL}{plugin_id}{RST}")
                        print(f"{INFO}[*] Raw plugin output:{RST}")
                        print(f"{BAD}{plugin_output}{RST}")
                        input(f"{INFO}[*] Press a key to continue{RST}")
                    else:
                        # If the plugin was found and fqdn_dict was updated, exit the loop
                        vprint("[+] FQDN found")
                        break
            if found:
                vprint("[+] Found is true so moving to next host")
                continue

            plugin_id = "10800"
            vprint(f"[*] Eigth choice: SNMP Query System Information Disclosure ({plugin_id})") 
            # vprint(f"[*] Is {plugin_id} in plugin id list?")
            for x in plugin_id_list:
                # vprint(f"[?] {plugin_id} == {x}?")
                if plugin_id != x:
                    # vprint("[-] No")
                    pass
                else:
                    # vprint("[+] Yes")
                    for a in plugins_info:
                        for b, c in a.items():
                            if b ==  plugin_id:
                                plugin_output = c
                                break
                    vprint(f"[*] Trying to get FQDN from {plugin_id}...")
                    # vprint(plugin_output)
                    try:
                        plugin_output = plugin_output.split("sysName")[1]
                        plugin_output = plugin_output.split(":")[1]
                        plugin_output = plugin_output.split("\n")[0]
                        plugin_output = plugin_output.strip()
                        plugin_output = plugin_output.lower()
                        vprint(f"{GOOD}[+] Added {DETAIL}{host}{GOOD} to fqdn dict: {DETAIL}{plugin_output}{RST}")
                        found = True
                        fqdn_dict[host] = plugin_output
                    except:
                        print(f"{BAD}[-] Failure: {DETAIL}{plugin_id}{RST}")
                        print(f"{INFO}[*] Raw plugin output:{RST}")
                        print(f"{BAD}{plugin_output}{RST}")
                        input(f"{INFO}[*] Press a key to continue{RST}")
                    else:
                        # If the plugin was found and fqdn_dict was updated, exit the loop
                        vprint("{GOOD}[+] FQDN found{RST}")
                        break
            if found:
                vprint("{GOOD}[+] Found is true so moving to next host{RST}")
                continue

            # if we reach here, no fqdn was found, so set key to "No FQDN identified"
            # back to start of main loop
            if not found:
                fqdn_dict[host] = f"No FQDN identified"
                vprint("")
                vprint(f"{BAD}[-] No FQDN identified for: {DETAIL}{host}{RST}")
                vprint(f"[*] Moving to next host")

    # print fancy percentage thing
    total = len(fqdn_dict)
    not_eq = 0
    for item in fqdn_dict.values():
        if item != "No FQDN identified":
            not_eq +=1
    if not_eq != 0:
        percent = (not_eq / total) * 100
        percent = round(percent, 1)
    else:
        percent = 0

    return fqdn_dict, percent


def get_fqdns_from_nessus_file(nessus_file):

    print(f"{INFO}[*] Searching for FQDNs in Nessus XML file...{RST}")
    fqdn_dict = {}
    # open nessus file and parse the xml
    tree = etree.parse(nessus_file)
    root = tree.getroot()
    report_hosts = root.findall('.//ReportHost')
    # this loop is for getting fqdn names for the hosts
    index = 0
    # vprint(f"{INFO}[*] Searching for FQDNs{RST}")
    while index < len(report_hosts):
        # vprint(len(report_hosts))
        # vprint(f"{OTHER}[*] Start of main loop{RST}")
        # vprint(f"{OTHER}[*] Index: {index}/{len(report_hosts)-1}{RST}")
        report_host = report_hosts[index]
        host_name = report_host.get("name")
        ip_pattern = r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}'
        ip_regex_match = re.fullmatch(ip_pattern, host_name)
        if ip_regex_match:
            # vprint(f"{OTHER}[+] Report host:\t{DETAIL}{host_name}{OTHER} (IP){RST}")
            found = False
            host_properties = report_host.find("HostProperties")
            child_element_list = []
            # make a list of attribs so we can search for relevant ones
            for child_element in host_properties:
                # vprint(f"\t{child_element.attrib['name']}")
                child_element_list.append(child_element.attrib["name"])
            if "host-fqdn" in child_element_list:
                # vprint(f"{OTHER}[*] Checking host-fqdn{RST}")
                for child in host_properties:
                    if child.attrib["name"] == "host-fqdn":
                        host_fqdn = child.text.lower()
                        break
                fqdn_dict[host_name] = host_fqdn
                # vprint(f"{GOOD}[+] FOUND: FQDN for {DETAIL}{host_name}{GOOD} - {DETAIL}{host_fqdn}{GOOD} using {DETAIL}host-fqdn{RST}")
                # vprint("[*] Breaking")
                index += 1
                found = True
                continue
            if "netbios-name" in child_element_list:
                # vprint(f"[*] Checking netbios-name")
                for child in host_properties:
                    if child.attrib["name"] == "netbios-name":
                        host_fqdn = child.text.lower()
                        break
                fqdn_dict[host_name] = host_fqdn
                # vprint(f"{GOOD}[+] FOUND: FQDN for {DETAIL}{host_name}{GOOD} - {DETAIL}{host_fqdn}{GOOD} using {DETAIL}netbios-name{RST}")
                # vprint("[*] Breaking")
                index += 1
                found = True
                continue

            # we reach here if no fqdn was found using hostproperties
            # now we loop through specific plugin output
            # vprint(f"{BAD}[-] FQDN not found in HostProperties{RST}")
            plugin_items = report_host.findall("ReportItem")
            for plugin in plugin_items:
                # vprint(f"{OTHER}[*] Start of plugin loop{RST}")
                # vprint(f"[*] Hostname: {host_name}")
                # vprint(f"{OTHER}[*] Index: {index}/{len(report_hosts)-1}{RST}")
                found = False
                host_fqdn = ""
                plugin_name = plugin.get("pluginName").replace("\n","")
                plugin_id = plugin.get("pluginID")
                # vprint(f"\t{plugin_name} - {plugin_id}")
                if plugin_id == "35371":
                    # DNS Server hostname.bind Map Hostname Disclosure - done
                    finding_output = plugin.findall('plugin_output')[0].text
                    try:
                        finding_output = finding_output.replace("\n","")
                        finding_output = finding_output.lower()
                        host_fqdn = finding_output.split(" :")[1]
                        if len(host_fqdn) != 0:
                            # vprint(f"{GOOD}[+] FOUND: FQDN for {DETAIL}{host_name}{GOOD} - {DETAIL}{host_fqdn}{GOOD} using {DETAIL}{plugin_name}{RST}")
                            fqdn_dict[host_name] = host_fqdn
                            found = True
                            index += 1
                            # vprint("[*] Breaking")
                            break
                        else:
                            # vprint(f"{BAD}[-] Error:{DETAIL} FQDN length {len(host_fqdn)} - {plugin_name}{RST}")
                            # vprint(finding_output)
                            pass
                    except Exception as e:
                        # vprint(f"{BAD}[-] Error:{DETAIL} {e} - {plugin_name}{RST}")
                        # vprint(finding_output)
                        pass

                if plugin_id == "12218":
                    # mDNS Detection - done
                    finding_output = plugin.findall('plugin_output')[0].text
                    try:
                        for line in finding_output.split("\n"):
                            if "mDNS hostname" in line:
                                line = line.split(":")[1]
                                line = line.strip()
                                line = line.lower()
                                break
                        host_fqdn = line
                        if len(host_fqdn) != 0:
                            # vprint(f"{GOOD}[+] FOUND: FQDN for {DETAIL}{host_name}{GOOD} - {DETAIL}{host_fqdn}{GOOD} using {DETAIL}{plugin_name}{RST}")
                            fqdn_dict[host_name] = host_fqdn
                            found = True
                            index += 1
                            # vprint("[*] Breaking")
                            break
                        else:
                            # vprint(f"{BAD}[-] Error:{DETAIL} FQDN length {len(host_fqdn)} - {plugin_name}{RST}")
                            # vprint(finding_output)
                            pass
                    except Exception as e:
                        # vprint(f"{BAD}[-] Error:{DETAIL} {e} - {plugin_name}{RST}")
                        # vprint(finding_output)
                        pass

                if plugin_id == "10785":
                    # Microsoft Windows SMB NativeLanManager Remote System Information Disclosure - done
                    finding_output = plugin.findall('plugin_output')[0].text
                    try:
                        if "DNS Computer Name" in finding_output:
                            finding_output = finding_output.split("DNS Computer Name: ")[1]
                        elif "NetBIOS Computer Name" in finding_output:
                            finding_output = finding_output.split("NetBIOS Computer Name:")[1]
                        elif "The remote SMB Domain Name is" in finding_output:
                            finding_output = finding_output.split("The remote SMB Domain Name is : ")[1]
                        host_fqdn = finding_output.split("\n")[0].lower()
                        if len(host_fqdn) != 0:
                            # vprint(f"{GOOD}[+] FOUND: FQDN for {DETAIL}{host_name}{GOOD} - {DETAIL}{host_fqdn}{GOOD} using {DETAIL}{plugin_name}{RST}")
                            fqdn_dict[host_name] = host_fqdn
                            found = True
                            index += 1
                            # vprint("[*] Breaking")
                            break
                        else:
                            # vprint(f"{BAD}[-] Error:{DETAIL} FQDN length {len(host_fqdn)} - {plugin_name}{RST}")
                            # vprint(finding_output)
                            pass
                    except Exception as e:
                        # vprint(f"{BAD}[-] Error:{DETAIL} {e} - {plugin_name}{RST}")
                        # vprint(finding_output)
                        pass

                if plugin_id == "10150":
                    # Windows NetBIOS / SMB Remote Host Information Disclosure - done
                    finding_output = plugin.findall('plugin_output')[0].text
                    try:
                        for line in finding_output.split("\n"):
                            if " = Computer name" in line:
                                line = line.split(" = Computer name")[0]
                                line = line.strip()
                                line = line.lower()
                                # break out of line loop
                                break
                        host_fqdn = line
                        if len(host_fqdn) != 0:
                            # vprint(f"{GOOD}[+] FOUND: FQDN for {DETAIL}{host_name}{GOOD} - {DETAIL}{host_fqdn}{GOOD} using {DETAIL}{plugin_name}{RST}")
                            fqdn_dict[host_name] = host_fqdn
                            found = True
                            index += 1
                            # vprint("[*] Breaking")
                            break
                        else:
                            # vprint(f"{BAD}[-] Error:{DETAIL} FQDN length {len(host_fqdn)} - {plugin_name}{RST}")
                            # vprint(finding_output)
                            pass
                    except Exception as e:
                        # vprint(f"{BAD}[-] Error:{DETAIL} {e} - {plugin_name}{RST}")
                        # vprint(finding_output)
                        pass

                if plugin_id == "46180":
                    # Additional DNS Hostnames - done
                    finding_output = plugin.findall('plugin_output')[0].text
                    try:
                        finding_output = finding_output.replace("\n", "")
                        finding_output = finding_output.split("- ")[1].lower()
                        host_fqdn = finding_output.strip()
                        if len(host_fqdn) != 0:
                            # vprint(f"{GOOD}[+] FOUND: FQDN for {DETAIL}{host_name}{GOOD} - {DETAIL}{host_fqdn}{GOOD} using {DETAIL}{plugin_name}{RST}")
                            fqdn_dict[host_name] = host_fqdn
                            found = True
                            index += 1
                            # vprint("[*] Breaking")
                            break
                        else:
                            # vprint(f"{BAD}[-] Error:{DETAIL} FQDN length {len(host_fqdn)} - {plugin_name}{RST}")
                            # vprint(finding_output)
                            pass
                    except Exception as e:
                        # vprint(f"{BAD}[-] Error:{DETAIL} {e} - {plugin_name}{RST}")
                        # vprint(finding_output)
                        pass

                if plugin_id == "10800":
                    # SNMP Query System Information Disclosure - done
                    finding_output = plugin.findall('plugin_output')[0].text
                    try:
                        for line in finding_output.split("\n"):
                            if "sysName" in line:
                                line = line.split(": ")[1]
                                line = line.lower()
                                line = line.strip()
                                break
                        host_fqdn = line
                        if len(host_fqdn) != 0:
                            # vprint(f"{GOOD}[+] FOUND: FQDN for {DETAIL}{host_name}{GOOD} - {DETAIL}{host_fqdn}{GOOD} using {DETAIL}{plugin_name}{RST}")
                            fqdn_dict[host_name] = host_fqdn
                            found = True
                            index += 1
                            # vprint("[*] Breaking")
                            break
                        else:
                            # vprint(f"{BAD}[-] Error:{DETAIL} FQDN length {len(host_fqdn)} - {plugin_name}{RST}")
                            # vprint(finding_output)
                            pass
                    except Exception as e:
                        # vprint(f"{BAD}[-] Error:{DETAIL} {e} - {plugin_name}{RST}")
                        # vprint(finding_output)
                        pass
    
            # if we cant find an fqdn, just set it to ip
            if not found:
                # vprint(f"{BAD}[-] No FQDN found for {DETAIL}{host_name}{RST}")
                fqdn_dict[host_name] = "No FQDN identified"
                #input()
                index += 1
                continue

        # if the hostname is already an fqdn, just add itself as an entry
        else:
            # vprint(f"{OTHER}[+] Report host:\t{DETAIL}{host_name}{OTHER} (FQDN){RST}")
            fqdn_dict[host_name] = host_name
            index += 1
            continue

        # vprint(f"Host: {host_name}\t - FQDN: {fqdn_dict[host_name]}")
    
    # print fancy percentage thing
    total = len(fqdn_dict)
    not_eq = 0
    for item in fqdn_dict.values():
        if item != "No FQDN identified":
            not_eq +=1
    percent = (not_eq / total) * 100
    percent = round(percent, 1)
    #print(f"{INFO}[*] Percentage of FQDNs identified: {DETAIL}{round(percent, 1)}%{RST}")

    return fqdn_dict, percent


def create_csv_data_from_nessus_file(nessus_file):

    print(f"{INFO}[*] Converting XML to CSV...{RST}")
    soon_to_be_csv_list = []

    header = f"Risk,Host,Port,Name,Description,Plugin Output"
    soon_to_be_csv_list.append(header)

    # open nessus file and parse the xml
    tree = etree.parse(nessus_file)
    root = tree.getroot()
    report_hosts = root.findall('.//ReportHost')

    # this loop is for getting all findings for all hosts
    for report_host in report_hosts:
        affected_host = report_host.attrib["name"]
        ## vprint("------------------------------------------")
        ## vprint(f"[*] Getting findings for:\t{affected_host}")
        # now, find and loop through all the findings for this host
        report_items = report_host.findall("ReportItem[@pluginName]")
        for report_item in report_items:
            # get the finding name
            finding_name = report_item.get('pluginName')

            # get the finding description
            finding_description = ""
            try:
                finding_description = report_item.findall('description')[0].text
                # replace newlines and tabs with spaces
                finding_description = finding_description.replace("\n", " ")
                finding_description = finding_description.replace("\t", " ")
            except:
                pass

            # get the finding output
            finding_output = ""
            try:
                finding_output = report_item.findall('plugin_output')[0].text
                # a dodgy line to remove newlines for .csv format
                finding_output = finding_output.replace("\n","!@#")
                finding_output = finding_output.replace("\t", " ")
            except:
                pass

            # get the finding port (the port on the host which is affected by this finding)
            finding_port = ""
            try:
                finding_port = report_item.get('port')
            except:
                pass

            # get the finding severity
            finding_severity = ""
            try:
                # finding_severity = report_item.findall('risk_factor')[0].text
                finding_severity = report_item.get('severity')
                if finding_severity == "0":
                    finding_severity = "None"
                elif finding_severity == "1":
                    finding_severity = "Low"
                elif finding_severity == "2":
                    finding_severity = "Medium"
                elif finding_severity == "3":
                    finding_severity = "High"
                elif finding_severity == "4":
                    finding_severity = "Critical"
            except:
                pass

            # compile and append our soon to be csv line
            soon_to_be_csv = f'"{finding_severity}","{affected_host}","{finding_port}","{finding_name}","{finding_description}","{finding_output}"'
            soon_to_be_csv_list.append(soon_to_be_csv)

    # >:(
    csv_data = '\n'.join(soon_to_be_csv_list)
    f = io.StringIO(csv_data)
    reader = csv.reader(f)

    # return csv data
    return reader


def get_all_findings_from_csv_data(csv_data):

    print(f"{INFO}[*] Retrieving findings...{RST}")
    # used to return the number of hosts and findings at the finish line
    host_list = []

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
    rows_we_need = ["Risk", "Host", "Port", "Name", "Description", "Plugin Output"]

    # loop through to make sure we have all the required rows
    # add them to our rows index dict
    # just exit if we cant find the row, good enough
    # vprint(f"{OTHER}[*] ROW CHECK")
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
    # vprint(f"{OTHER}[*] Getting findings data{RST}")
    for csv_data_row in csv_data:
        # vprint(f"{OTHER}[*] Row!{RST}")
        # get finding severity
        finding_severity = ""
        try:
            finding_severity = csv_data_row[rows_index_dict["Risk"]]
            # change severity to the phrasing we need
            if finding_severity == "None":
                finding_severity = "5 - Info"
            elif finding_severity == "Low":
                finding_severity = "4 - Low"
            elif finding_severity == "Medium":
                finding_severity = "3 - Medium"
            elif finding_severity == "High":
                finding_severity = "2 - High"
            elif finding_severity == "Critical":
                finding_severity = "1 - Critical"
        except Exception as e:
            vprint(f"{BAD}[-] Error: {DETAIL}{e}{RST}")
            quit()
        
        # get the description
        finding_desc = ""
        try:
            finding_desc = csv_data_row[rows_index_dict['Description']].replace("\n", " ")
        except Exception as e:
            vprint(f"{BAD}[-] Error: {DETAIL}{e}{RST}")
            quit()

        # get the host
        finding_host = ""
        try:
            finding_host = csv_data_row[rows_index_dict['Host']]
            # add host to host list
            host_list.append(finding_host)
        except Exception as e:
            vprint(f"{BAD}[-] Error: {DETAIL}{e}{RST}")
            quit()

        # get the output
        try:
            finding_output = csv_data_row[rows_index_dict['Plugin Output']]
        except Exception as e:
            vprint(f"{BAD}[-] Error: {DETAIL}{e}{RST}")
            quit()
                                          
        # make a string of the affected host and port
        # so now we have a string like "192.168.0.1:445"
        # we use that to check that against the findings "affected" list
        finding_port = csv_data_row[rows_index_dict['Port']]
        finding_host_and_port = f"{finding_host}:{finding_port}"
    
        # get finding name
        finding_name = csv_data_row[rows_index_dict["Name"]]
        all_findings_list.append(finding_name)

        # this bit checks if the finding name is already in our 'seen before findings' list
        # if we've seen this finding before
        if finding_name in findings_seen_before:
            vprint(f"{GOOD}[*] SEEN BEFORE: {DETAIL}{finding_name}{GOOD} - seen before{RST}") 
            # now we check if the host and port from above is already in this findings 'affected' list
            vprint(f"{INFO}\t[*] Checking if {DETAIL}{finding_host_and_port} {INFO}is in affected list for {DETAIL}{finding_name}{RST}")
            # if it hasnt been added to the finding's affected list
            # we add it
            if finding_host_and_port not in findings_and_affected_hosts_dict[finding_name]["affected"]:
                vprint(f"\t\t{INFO}[*] NO: {DETAIL}{finding_host_and_port} {INFO}is not in affected list, will add it{RST}")
                findings_and_affected_hosts_dict[finding_name]["affected"].append(finding_host_and_port)
            # if it has been added already
            # do nothing
            else:
                vprint(f"\t\t{GOOD}[*] YES: {DETAIL}{finding_host_and_port} {INFO} is already in affected list, not adding it{RST}") 
                pass
                  
        # if we havent seen this finding before
        # create the finding then
        # created the empty "affected" list within the finding dictionary
        # add the host and port to its affected list
        else:
            vprint(f"{INFO}[*] NEVER SEEN: {DETAIL}{finding_name}{INFO} - adding it to found list{RST}")
            findings_seen_before.append(finding_name)
            # we've never seen this finding before, therefore the associated host and port
            # hasn't been added to the affected list yet
            # so we add it
            # create empty entry for finding in findings dict
            findings_and_affected_hosts_dict[finding_name] = {}
            # create empty affected list
            findings_and_affected_hosts_dict[finding_name]["affected"] = []
            finding_host_and_port = f"{finding_host}:{finding_port}"
            # add host and port to affected list
            findings_and_affected_hosts_dict[finding_name]["affected"].append(finding_host_and_port)
            vprint(f"\t{INFO}[*] {DETAIL}{finding_host_and_port} {INFO}will be first item in affected list{RST}")

        # complete the rest of the dictionary
        findings_and_affected_hosts_dict[finding_name]["description"] = finding_desc
        findings_and_affected_hosts_dict[finding_name]["severity"] = finding_severity
        findings_and_affected_hosts_dict[finding_name]["output"] = finding_output

    # create a unique list of findings sorted by severity as first order
    # then finding name as second order
    unique_findings_and_affected_hosts_dict = dict(sorted(findings_and_affected_hosts_dict.items(), key=lambda item: (item[1]["severity"], item[0].lower())))

    return unique_findings_and_affected_hosts_dict, host_list, all_findings_list


def trim_findings(findings_and_affected_dict, fqdn_dict, domain):

    print(f"{INFO}[*] Trimming findings...{RST}")

    # temp dict for shuffling things around
    temp_working_dict = {}

    # dict to return when we've finished
    trimmed_findings_and_affected_hosts_dict = {}

    # first, cut out items in our skipped findings list
    for finding, value in findings_and_affected_dict.items():
        if finding not in skipped_findings:
            trimmed_findings_and_affected_hosts_dict[finding] = value
        else:
            vprint(f"{GOOD}[*] {DETAIL}{finding} {GOOD}is in skipped findings, not adding{RST}")
            pass
    
    # now, cut out "info" items if -x hasn't been chosen
    if args.info:
        vprint(f"{INFO}[*] Info items are being included{RST}")
        pass
    else:
        for key, value in trimmed_findings_and_affected_hosts_dict.items():
            if value["severity"] == "5 - Info":
                vprint(f"{OTHER} Removing item with severity: {DETAIL}{value['severity']}{RST}")
                pass
            else:
                temp_working_dict[key] = value
        trimmed_findings_and_affected_hosts_dict = temp_working_dict

    for key, value in trimmed_findings_and_affected_hosts_dict.items():      
        # loop through list of affected hosts and ports
        for i in range(len(value["affected"])):
            finding_host_and_port = value["affected"][i]
            host = finding_host_and_port.split(":")[0]
            vprint(f"[*] Affected host: {host}")
            port = finding_host_and_port.split(":")[1]
            # if the host has an entry in the fqdn dict
            # replace the ip value with the fqdn
            for x, y in fqdn_dict.items():
                found = False
                new_value = ""
                if host == x:
                    vprint(f"[*] Found: {x} - {y}")
                    #input()
                    new_value = fqdn_dict[host]
                    vprint(f"{GOOD}[+] Found {DETAIL}{host}{GOOD} in fqdn dict - {DETAIL}{new_value}{RST}")
                    # update the list with the new value
                    # if the new value is 'No FQDN identified', it means we couldnt find an FQDN
                    if new_value == "No FQDN identified":
                        vprint("[*] No FQDN was identified")
                        vprint("")
                        value["affected"][i] = f"{host}:{port} (No FQDN identified)"
                    else:
                        vprint("FQDN was identified")
                        if args.domain:
                            value["affected"][i] = f"{new_value}.{domain}:{port} ({host})"
                        else:
                            value["affected"][i] = f"{new_value}:{port} ({host})"   
                        vprint("")                
                    found = True
                    break
            # i dont know what happens when we get here...
            if not found:
                value["affected"][i] = f"{host}:{port} (No FQDN identified)"
        # sorted affected hosts alphabetically
        value['affected'] = sorted(value['affected'])

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
        print(f"{INFO}[*] Severity:\t{DETAIL}{severity}{RST}")
        print(f"{INFO}[*] Name:\t{DETAIL}{name}{RST}")
        if args.desc:
            description = y['description']
            # newline looks better than tab
            print(f"{INFO}[*] Desc:\n{GREY}{description}{RST}")
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
        affected.sort()
        print(f"{GOOD}[*] Affected Hosts:{RST} {GREY}({len(affected)}){RST}")
        for host in affected:
            if " (" in host:
                fqdn = host.split(" (")[0]
                if args.ip:
                    ip = host.split(" (")[1]
                    ip = ip.split(")")[0]
                    print(f"{OTHER}{fqdn} {GREY}({ip}){RST}")
                else:
                    print(f"{OTHER}{fqdn}{RST}") 
            else:
                print(f"{OTHER}{host}{RST}")
        print("\n")

    # return the counters
    return info, low, med, high, crit


def write_findings(trimmed_findings):

    # fancy stuff if "~" is in the output file line
    output_file = args.output
    if output_file.startswith("~"):
        home_dir = os.path.expanduser("~")
        output_file = home_dir + output_file[1:]
    
    f = open(output_file, "w")
    for x,y in trimmed_findings.items():
        f.write(f"[*] Severity:\t{y['severity']}\n")
        f.write(f"[*] Name:\t{x}\n")
        if args.desc:
            f.write(f"[*] Desc:\n{y['description']}\n")
        if args.poutput:
            f.write(f"[*] Output:\n")
            output = y["output"]
            output = output.replace("!@#", "\n")
            output = output.strip()
            f.write(f"{output}\n")
        affected = y["affected"]
        affected.sort()
        f.write(f"[*] Affected Hosts: {len(affected)}\n")
        for host in affected:
            if " (" in host:
                fqdn = host.split(" (")[0]
                if args.ip:
                    ip = host.split(" (")[1]
                    ip = ip.split(")")[0]
                    f.write(f"{fqdn} ({ip})\n")
                else:
                    f.write(f"{fqdn}\n")
            else:
                f.write(f"{host}\n")
        f.write("\n")
    f.close()


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
banner(nessus_file, output_file, domain)

# find out what type of file we have
extension = os.path.splitext(nessus_file)[1]

# if csv
if extension == ".csv":
    # run the fqdn getter function
    fqdn_dict, percent = get_fqdns_from_csv_file(nessus_file)
    # sort the dict
    sorted_fqdn_dict = dict(sorted(fqdn_dict.items()))
    # then get the csv data
    f = open(nessus_file, newline='', encoding='utf-8')
    csv_data = csv.reader(f)

# if nessus xml
elif extension == ".nessus":
    # run the fqdn getter function
    fqdn_dict, percent = get_fqdns_from_nessus_file(nessus_file)
    # sort the dict
    sorted_fqdn_dict = dict(sorted(fqdn_dict.items()))
    # convert nessus XML data into csv
    csv_data = create_csv_data_from_nessus_file(nessus_file)
# if neither
else:
    print(f"{BAD}[-] Invalid file type: {DETAIL}{nessus_file}{RST}")
    quit(-1)


# get all of the findings and details from the csv data
findings_and_affected_hosts_dict, host_list, all_findings_list = get_all_findings_from_csv_data(csv_data)


# trim out the ones we dont need and stuff based on user prefs
trimmed_findings = trim_findings(findings_and_affected_hosts_dict, sorted_fqdn_dict, domain)


# get amount of findings for summary
amt_of_findings = len(trimmed_findings) 


# print the trimmed findings and return the amount
# of findings for each risk level
info, low, med, high, crit = print_findings(trimmed_findings)


# write to file
write_findings(trimmed_findings)


# get amount of hosts and findings for summary
x = list(set(host_list))
y = list(set(all_findings_list))
amt_of_hosts = str(len(x))
amt_of_findings_including_skipped = str(len(y))


# print the summary
summary(amt_of_hosts, amt_of_findings_including_skipped, amt_of_findings, info, low, med, high, crit, percent)
