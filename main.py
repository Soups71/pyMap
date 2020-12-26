# Dependencies for this file
import scapy.all as scapy
import argparse
from natsort import natsorted
from host import Host


# Function to parse arguments
# Return: string, int, int, bool, string
def get_args():
    parser = argparse.ArgumentParser()
    parser.add_argument('-t', '--target', dest='target', help='Target IP Address/Adresses')
    parser.add_argument('-p', '--ports', dest='ports', help='Range of ports to scan. Format of args: 1-80')
    parser.add_argument('-o', '--output', dest='output', help='Target IP Address/Adresses')
    parser.add_argument('-v', '--verbose', dest='verbose', action='store_true', help='Print out results as you go')
    parser.set_defaults(verbose=False)
    options = parser.parse_args()
    verbose = options.verbose
    filename = ""
    # Check if filename is provided to write to
    if options.output:
        filename = options.output
    # Check if target was provided
    if not options.target:
        parser.error("[-] Please specify an IP Address or Addresses, use --help for more info.")

    # This parses for the ports provided
    if not options.ports:
        print("Only running host discorvery. To specify ports to scan please use port options.")
        start_port = 0
        end_port = 0
    else:
        if "-" not in options.ports:
            parser.error("[-] Please specify range using format as: -p 1-80")
        if not options.ports[:options.ports.index("-")].isdigit():
            parser.error("[-] Port numbers must be integers, above 0, and below 65535")
        else:
            if int(options.ports[:options.ports.index("-")]) <1 or int(options.ports[:options.ports.index("-")]) >65535:
                parser.error("[-] Port numbers must be integers, above 0, and below 65535")
            else:
                start_port = int(options.ports[:options.ports.index("-")])

        if not options.ports[options.ports.index("-")+1:].isdigit():
            parser.error("[-] Port numbers must be integers, above 0, and below 65535")
        else:
            if int(options.ports[options.ports.index("-")+1:]) <1 or int(options.ports[options.ports.index("-")+1:]) >65535:
                parser.error("[-] Port numbers must be integers, above 0, and below 65535")
            else:
                end_port = int(options.ports[options.ports.index("-")+1:])

    return options.target, start_port, end_port, verbose, filename


# Runs scans of the subnet provided
# Return: Dictionary
def scan(ip):
    # Set up apr frame for request
    arp_req_frame = scapy.ARP(pdst=ip)
    # Set up so frame is broadcast
    broadcast_ether_frame = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    broadcast_ether_arp_req_frame = broadcast_ether_frame / arp_req_frame
    # List of hosts that responded
    answered_list = scapy.srp(broadcast_ether_arp_req_frame, timeout=1, verbose=False)[0]
    result = []
    for i in range(0, len(answered_list)):
        client_dict = {"ip": answered_list[i][1].psrc, "mac": answered_list[i][1].hwsrc}
        result.append(client_dict)

    return result


# Prints results
# Returns: NOTHING
def display_result(result):
    natsorted(result)
    print("-----------------------------------\nIP Address\tMAC Address\n-----------------------------------")
    for i in result:
        print("{}\t{}".format(i["ip"], i["mac"]))


# Sorts host by integer value
# Returns: Dictionary, List of Host objects
def sort_ip(results):
    hosts = []
    ips = [i['ip'] for i in results]
    # Sorts IPs numerically
    ips = natsorted(ips)
    sorted_results = []
    for ip in ips:
        j = 0
        while(j<len(results)):
            if results[j]['ip'] == ip:
                sorted_results.append(results[j])
                break
            j+=1
    for host in sorted_results:
        hosts.append(Host(host['ip'], host['mac']))
    return sorted_results, hosts


if __name__ == "__main__":
    target_subnet, start, end, verbose, file= get_args()
    scanned_output = scan(target_subnet)
    sorted_output, hosts = sort_ip(scanned_output)
    if(verbose):
        display_result(sorted_output)
    if start != 0 and end != 0:
        i = 0
        while(i<len(hosts)):
            if(verbose):
                print(f"Host {i+1} out of {len(hosts)} scanned. ({round(((i+1)/(len(hosts)))*100)}%)")
            hosts[i].scan_ports(start, end+1, verbose)
            i+=1

    # Write to file if output file was given
    if file != "":
        try:
            with open(file, "w+") as writer:
                for host in hosts:
                    writer.write(f"Scan of {host.ip}: ")
                    writer.write(f"\tPORT:\tSTATE:")
                    for port in host.ports:
                        writer.write(f"\t{port}\tOPEN")
        except:
            print("Could not write to file successfully!!!")