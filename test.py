

import pyshark
import os
import matplotlib.pyplot as plt
import json
import numpy as np
import seaborn as sns
from string import Template

dir_context = ["/ethernet", "/ethernet_web", "/shared_connection", "/wifi_eduroam"]
path_pwd = os.getcwd() 

files = []
for dir in dir_context:
    path = os.path.realpath(path_pwd + dir)
    dir_list = os.listdir(path)
    dir_list = [dir + "/" + f for f in dir_list if os.path.isfile(path_pwd + dir + '/' + f)]
    files = files + dir_list


def get_packets_per_minute(files):

    scenarios = {}

    for filename in files:
        scenario = filename.split("-")[1]
        if not scenario in scenarios:
            scenarios[scenario] = 0

        name = path_pwd + filename
        cap = pyshark.FileCapture(name)
        cap.load_packets()
        packet_amount = len(cap)
        time_delta = cap[packet_amount-1].sniff_time - cap[0].sniff_time
        seconds = time_delta.total_seconds()
        minutes = seconds / 60
        
        scenarios[scenario] += packet_amount / minutes
        
        print("Done " + str(packet_amount) + " " + filename)
    
    for key in scenarios:
        scenarios[key] = scenarios[key] / (2*len(dir_context))

    # Write to file
    with open("_outputs/packets_per_minute.txt", "w") as f:
        for key in scenarios:
            f.write(key + " : " + str(scenarios[key]) + "\n")
    
    return scenarios

def repartition_udp(files):

    scenarios = {}

    for filename in files:
        scenario = filename.split("-")[1]
        if (scenario == "message" or scenario == "file" or scenario == "connect"):
            continue
        dic = {}
        if not scenario in scenarios:
            scenarios[scenario] = dic

        name = path_pwd + filename
        cap = pyshark.FileCapture(name)
        cap.load_packets()
        for pkt in cap: 
            temp = pkt.highest_layer if pkt.highest_layer != "DATA" else "UDP"
            dic[temp] = dic.get(temp, 0) + 1
           
        print("Done " + filename)

    # Write to file
    with open("_outputs/repartition.json", "w") as f:
        f.write(json.dumps(scenarios, indent=4))
    
    return scenarios

def get_dns_names(files):
    domains = {}

    for filename in files:

        name = path_pwd + filename
        cap = pyshark.FileCapture(name)
        cap.load_packets()
        for pkt in cap: 
            if (pkt.highest_layer == "DNS"):
                domains[pkt.dns.qry_name] = domains.get(pkt.dns.qry_name, 0) + 1
           
        print("Done " + filename)

    return domains


def plot_packets_per_minute(filename):
    # Read the file
    with open(filename, "r") as f:
        lines = f.readlines()
        scenarios = {}
        for line in lines:
            line = line.split(" : ")
            scenarios[line[0]] = float(line[1])
    x = scenarios.keys()
    y = scenarios.values()

    # Create the bar chart
    plt.bar(x, y)

    # Add labels and title
    plt.xlabel('Scénario')
    plt.ylabel('Paquets par minute')
    plt.title('Paquets par minute par scénario')

    # Show the plot
    plt.savefig("_outputs/packets_per_minute.pdf")
    plt.show()


    
def reverse_dic(filename):
    with open(filename, "r") as f:
        dict = json.loads(f.read())

    protocols = set()
    for key in dict:
        for prot in dict[key]:
            protocols.add(prot)

    
    for key in dict:
        somme = 0
        for prot in dict[key]:
            somme += dict[key][prot]
        for prot in dict[key]:
            dict[key][prot] = dict[key][prot] / somme

    new_dic = {}
    for key in dict:
        for prot in protocols:
            if not prot in new_dic:
                new_dic[prot] = []
            if prot in dict[key]:
                new_dic[prot].append(dict[key][prot])
            else:
                new_dic[prot].append(0)

    array = []
    colors = sns.color_palette('hls', len(protocols)).as_hex()
    for (i, key) in enumerate(new_dic):
        temp_key = key
        if key == "_WS.MALFORMED":
            temp_key = "Others"
        array.append({"label" : temp_key, "data" : new_dic[key], "borderWidth" : 1, "backgroundColor": colors[i]})

    with open("_outputs/datasets.json", "w") as f:
        f.write(json.dumps(array, indent=4))

def fill_template():
    with open("_outputs/datasets.json", "r") as file:
        with open("template.html", "r") as file2:
            with open("graph.html", "w") as file3:
                str = file2.read()
                temp = Template(str)
                str = temp.substitute(data=file.read())
                file3.write(str)



#repartition_udp(files)
#get_packets_per_minute(files)
#plot_packets_per_minute("_outputs/packets_per_minute.txt")
#reverse_dic("_outputs/repartition.json")
#fill_template()
d = get_dns_names(files))
#d = {'rotterdam2503.discord.media': 16, 'discord.com': 232, 'gateway.discord.gg': 16, 'status.discord.com': 16, 'cdn.discordapp.com': 80, 'discord-attachments-uploads-prd.storage.googleapis.com': 48, 'rotterdam7413.discord.media': 16, 'rotterdam3955.discord.media': 16, 'rotterdam11002.discord.media': 16, 'rotterdam3257.discord.media': 16, 'connectivity-check.ubuntu.com': 8, 'rotterdam6078.discord.media': 28, 'ocsp.pki.goog': 8, 'rotterdam9095.discord.media': 24, 'rotterdam2332.discord.media': 24, 'rotterdam3897.discord.media': 24, 'rotterdam4472.discord.media': 22, 'api.openweathermap.org': 6, 'rotterdam11006.discord.media': 10, 'locprod2-elb-us-west-2.prod.mozaws.net': 8, 'discordapp.com': 28, 'rotterdam1071.discord.media': 8, 'rotterdam7231.discord.media': 8, 'rotterdam254.discord.media': 8, 'rotterdam4782.discord.media': 8, 'rotterdam7223.discord.media': 12, 'fedoraproject.org': 4, 'location.services.mozilla.com': 4, 'rotterdam7428.discord.media': 12, 'rotterdam4251.discord.media': 12, 'rotterdam2007.discord.media': 12, 'rotterdam6818.discord.media': 12, 'media.discordapp.net': 8}
print(json.dumps(d, indent=4))