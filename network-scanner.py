#  Copyright (c) 2019. Ciphyr
#  Email: ciphyr[at]protonmail.com
#
#  Licensed under the Apache License, Version 2.0 (the "License");
#  You may not use this file except in compliance with the License.
#  You may obtain a copy of the License at
#
#  http://www.apache.org/licenses/LICENSE-2.0
#
#  Unless required by applicable law or agreed to in writing, software
#  distributed under the License is distributed on an "AS IS" BASIS,
#  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#  See the License for the specific language governing permissions and
#  limitations under the License.

import scapy.all as scapy
import optparse

#Future improvments
#List OS, list MAC vendor, list user assigned device name

def get_cmd_args():
    parser = optparse.OptionParser()
    parser.add_option("-t", "--target", dest="target", help="Target IP address or IP range")
    options, arguements = parser.parse_args()

    if not options.target:
        parser.error("Please specify a target IP or IP range, --help for usage info")

    return options

def scan(targetIP):
    arp_request = scapy.ARP(pdst = targetIP)
    #hwst = ff:ff:ff:ff:ff:ff ?
    broadcast = scapy.Ether(dst = "ff:ff:ff:ff:ff:ff")
    arp_broadcast_request = broadcast/arp_request

    responses_list = scapy.srp(arp_broadcast_request, timeout = 1, verbose = False)[0]

    clients_list = []

    for i in responses_list:
        client_dict = {"ip" : i[1].psrc, "mac" : i[1].hwsrc}
        clients_list.append(client_dict)
    return clients_list

def print_result(results_list):
    print("IP\t\tMAC Address")
    print("----------------------------------")

    for client in results_list:
        print(client["ip"] + "\t" + client["mac"])

options = get_cmd_args()
print_result(scan(options.target))
