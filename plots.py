import pyshark
import os
import matplotlib.pyplot as plt

dir_context = ["/ethernet", "/ethernet_web", "/shared_connection", "/wifi_eduroam"]
path_pwd = "/home/aperence/Documents/Analyse-d-application-reseau-Discord"
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
        scenarios[key] = scenarios[key] / len(dir_context)
    
    return scenarios

scenarios = get_packets_per_minute(files)
print(scenarios)