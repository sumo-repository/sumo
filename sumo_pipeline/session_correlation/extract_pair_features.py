import logging
import sys
import os
from os import listdir
from os.path import isdir
import numpy as np
import tqdm
import pickle
import random as rd
import collections
from scipy.stats import kurtosis, skew
from scapy.all import *


DATA_FOLDER = 'OSTest/'
dataset_name = 'OSTest'
topPath = "extracted_features/"
clientPath = topPath + "client_{}/".format(dataset_name)
hsPath = topPath + "onion_server_{}/".format(dataset_name)

count = 0
countBothWays = 0

pairsFolders = {}
alexaFolders = {}

onionAddressData = {}


def RoundToNearest(n, m):
    r = n % m
    return n + m - r if r + r >= m else n - r


def extract_client_data(data_folder):
    print("###############################################")
    print("# Extracting features from client .pcaps")
    print("###############################################")
    for capture_folder in os.listdir(data_folder + "TrafficCapturesClient/"):
        if '._' in capture_folder:
            continue
        if(".DS_Store" in capture_folder):
            continue

        capturePath = data_folder + 'TrafficCapturesClient/' + capture_folder+ '/'
        # Because we need to take into account possible different names with "-new"
        capture_folder_split = capture_folder.split("captures-")
        client_node = capture_folder_split[1]
        if len(capture_folder_split) > 2:
            client_node += capture_folder_split[2]
        client_ip = '172.'

        extract_traffic_features(capturePath, client_ip, "client")
    print()


def extract_onion_server_data(data_folder):
    print("###############################################")
    print("# Extracting features from onion servers .pcaps")
    print("###############################################")
    for onion_server_folder in os.listdir(data_folder + "TrafficCapturesOnion/"):
        if '._' in onion_server_folder:
            continue
        if(".DS_Store" in onion_server_folder):
            continue

        onion_ip = "172."

        for capture_folder in os.listdir(data_folder + "TrafficCapturesOnion/" + onion_server_folder):
            if '._' in capture_folder:
                continue
            if(".DS_Store" in capture_folder):
                continue
            if 'file.log' in capture_folder:
                continue

            print("- " + data_folder + "TrafficCapturesOnion/" + onion_server_folder + "/" + capture_folder)
            extract_traffic_features(data_folder + "TrafficCapturesOnion/" + onion_server_folder + "/" + capture_folder, onion_ip, "onion_server")


def extract_traffic_features(capture_folder, machine_ip, mode):

    for sample in os.listdir(capture_folder):
        if(".DS_Store" in sample):
            continue

        if(".pcap" not in sample):
            continue

        if ("._" in sample):
            continue
            
        # Target only full session captures
        if ("request" in sample):
            continue

        ###############################################################
        # Extract packet features from the .pcap
        ###############################################################

        #print(capture_folder + "/" + sample)

        try:
            cap = PcapReader(capture_folder + "/" + sample)
        except Exception as e:
            print("Problem parsing pcap {}".format(sample))
            print(e)
            continue

        packetTimesIn = []
        packetTimesInRel = [0]
        packetTimesOut = []
        packetTimesOutRel = [0]
        packetTimesInAbs = []
        packetTimesOutAbs = []
        packetSizesIn = []
        packetSizesOut = []

        prev_ts_in = 0
        prev_ts_out = 0
        first_ts = 0
        tor_node = None

        ###################################
        # Diogo's Features Here
        ###################################

        # Analyse packets transmited
        totalPackets = 0
        totalPacketsIn = 0
        totalPacketsOut = 0

        # Analyse bytes transmitted
        totalBytes = 0
        totalBytesIn = 0
        totalBytesOut = 0

        # Analyse packet sizes
        packetSizes = []

        bin_dict = {}
        bin_dict2 = {}
        binWidth = 5
        # Generate the set of all possible bins
        for i in range(0, 100000, binWidth):
            bin_dict[i] = 0
            bin_dict2[i] = 0

        # Analyse inter packet timing
        packetTimes = []

        # Analyse outcoming bursts
        out_bursts_packets = []
        out_burst_sizes = []
        out_burst_times = []
        out_current_burst = 0
        out_current_burst_start = 0
        out_current_burst_size = 0

        # Analyse incoming bursts
        in_bursts_packets = []
        in_burst_sizes = []
        in_burst_times = []
        in_current_burst = 0
        in_current_burst_size = 0

        prev_ts = 0


        counter = 0
        for i, pkt in enumerate(cap):
            
            ts = np.float64(pkt.time)
            size = pkt.wirelen

            try:
                # Target TCP communication
                if pkt.haslayer(TCP):
                    src_ip_addr_str = pkt[IP].src
                    dst_ip_addr_str = pkt[IP].dst
                    
                    dport = pkt[TCP].dport
                    sport = pkt[TCP].sport

                    # Internal communications between Docker containers to use Tor socket
                    if(dport == 9050 or sport == 9050):
                        continue

                    #Do not target packets produced due to synchronizing REST calls
                    if(dport == 5005 or sport == 5005):
                        continue

                    # skip HTTP packets to manage Google Cloud instances
                    if(dport == 80 or sport == 80):
                        continue
                    
                    #Record initial timestamp
                    if(first_ts == 0):
                        first_ts = ts

                    if(machine_ip in dst_ip_addr_str):

                        #Update tor node
                        if(tor_node is None):
                            tor_node = src_ip_addr_str

                        packetSizesIn.append(size)

                        if (prev_ts_in != 0):
                            
                            ts_difference_in = max(0, ts - prev_ts_in)
                            packetTimesIn.append(ts_difference_in)
                        
                        else:
                            packetTimesIn.append(0)


                        prev_ts_in = ts

                        packetTimesInAbs.append(ts)
                        packetTimesInRel.append(ts - first_ts)

                        totalPacketsIn += 1
                        binned = RoundToNearest(size, binWidth)
                        bin_dict2[binned] += 1

                        if (out_current_burst != 0):
                            if (out_current_burst > 1):
                                out_bursts_packets.append(out_current_burst)  # packets on burst
                                out_burst_sizes.append(out_current_burst_size)  # total bytes on burst
                                out_burst_times.append(ts - out_current_burst_start)
                            out_current_burst = 0
                            out_current_burst_size = 0
                            out_current_burst_start = 0
                        if (in_current_burst == 0):
                            in_current_burst_start = ts
                        in_current_burst += 1
                        #in_current_burst_size += len(buf)
                        in_current_burst_size += size

                    # If machine is sender
                    elif(machine_ip in src_ip_addr_str):
                        packetSizesOut.append(size)
                        
                        if (prev_ts_out != 0):
                            ts_difference_out = max(0, ts - prev_ts_out)
                            packetTimesOut.append(ts_difference_out)

                        else:
                            packetTimesOut.append(0)

                        prev_ts_out = ts

                        packetTimesOutAbs.append(ts)
                        packetTimesOutRel.append(ts - first_ts)


                        totalPacketsOut += 1
                        binned = RoundToNearest(size, binWidth)
                        bin_dict[binned] += 1
                        if (out_current_burst == 0):
                            out_current_burst_start = ts
                        out_current_burst += 1
                        out_current_burst_size += size

                        if (in_current_burst != 0):
                            if (in_current_burst > 1):
                                in_bursts_packets.append(out_current_burst)  # packets on burst
                                in_burst_sizes.append(out_current_burst_size)  # total bytes on burst
                                in_burst_times.append(ts - out_current_burst_start)
                            in_current_burst = 0
                            in_current_burst_size = 0

                    # Bytes transmitted statistics
                    totalBytes += pkt.wirelen
                    totalPackets += 1

                    if (machine_ip in src_ip_addr_str):
                        totalBytesOut += size
                    else:
                        totalBytesIn += size

                    # Packet Size statistics
                    packetSizes.append(size)

                    # Packet Times statistics
                    if (prev_ts != 0):
                        ts_difference = max(0, ts - prev_ts)
                        packetTimes.append(ts_difference * 1000)

                    prev_ts = ts

                    
            except Exception as e:
                print("Corrupted packet")
                print(repr(e))
                print(e)

            counter += 1


        ################################################################
        ####################Compute statistics#####################
        ################################################################

        try:
            ##########################################################
            # Statistical indicators for packet sizes (total)
            meanPacketSizes = np.mean(packetSizes)
            stdevPacketSizes = np.std(packetSizes)
            variancePacketSizes = np.var(packetSizes)
            kurtosisPacketSizes = kurtosis(packetSizes)
            skewPacketSizes = skew(packetSizes)
            maxPacketSize = np.amax(packetSizes)
            minPacketSize = np.amin(packetSizes)
            p10PacketSizes = np.percentile(packetSizes, 10)
            p20PacketSizes = np.percentile(packetSizes, 20)
            p30PacketSizes = np.percentile(packetSizes, 30)
            p40PacketSizes = np.percentile(packetSizes, 40)
            p50PacketSizes = np.percentile(packetSizes, 50)
            p60PacketSizes = np.percentile(packetSizes, 60)
            p70PacketSizes = np.percentile(packetSizes, 70)
            p80PacketSizes = np.percentile(packetSizes, 80)
            p90PacketSizes = np.percentile(packetSizes, 90)

        except Exception as e:
            print("Error in block 1 when processing " + capture_folder + "/" + sample)
            print("Skipping sample")
            print(e)
            continue

        try:
            ##########################################################
            # Statistical indicators for packet sizes (in)
            meanPacketSizesIn = np.mean(packetSizesIn)
            stdevPacketSizesIn = np.std(packetSizesIn)
            variancePacketSizesIn = np.var(packetSizesIn)
            kurtosisPacketSizesIn = kurtosis(packetSizesIn)
            skewPacketSizesIn = skew(packetSizesIn)
            maxPacketSizeIn = np.amax(packetSizesIn)
            minPacketSizeIn = np.amin(packetSizesIn)
            p10PacketSizesIn = np.percentile(packetSizesIn, 10)
            p20PacketSizesIn = np.percentile(packetSizesIn, 20)
            p30PacketSizesIn = np.percentile(packetSizesIn, 30)
            p40PacketSizesIn = np.percentile(packetSizesIn, 40)
            p50PacketSizesIn = np.percentile(packetSizesIn, 50)
            p60PacketSizesIn = np.percentile(packetSizesIn, 60)
            p70PacketSizesIn = np.percentile(packetSizesIn, 70)
            p80PacketSizesIn = np.percentile(packetSizesIn, 80)
            p90PacketSizesIn = np.percentile(packetSizesIn, 90)
        
        except Exception as e:
            print("Error in block 2 when processing " + capture_folder + "/" + sample)
            print("Skipping sample")
            print(e)
            continue

        try:    
            ##########################################################
            # Statistical indicators for packet sizes (out)
            meanPacketSizesOut = np.mean(packetSizesOut)
            stdevPacketSizesOut = np.std(packetSizesOut)
            variancePacketSizesOut = np.var(packetSizesOut)
            kurtosisPacketSizesOut = kurtosis(packetSizesOut)
            skewPacketSizesOut = skew(packetSizesOut)
            maxPacketSizeOut = np.amax(packetSizesOut)
            minPacketSizeOut = np.amin(packetSizesOut)
            p10PacketSizesOut = np.percentile(packetSizesOut, 10)
            p20PacketSizesOut = np.percentile(packetSizesOut, 20)
            p30PacketSizesOut = np.percentile(packetSizesOut, 30)
            p40PacketSizesOut = np.percentile(packetSizesOut, 40)
            p50PacketSizesOut = np.percentile(packetSizesOut, 50)
            p60PacketSizesOut = np.percentile(packetSizesOut, 60)
            p70PacketSizesOut = np.percentile(packetSizesOut, 70)
            p80PacketSizesOut = np.percentile(packetSizesOut, 80)
            p90PacketSizesOut = np.percentile(packetSizesOut, 90)

        except Exception as e:
            print("Error in block 3 when processing " + capture_folder + "/" + sample)
            print("Skipping sample")
            print(e)
            continue

        try:
            ##################################################################
            # Statistical indicators for Inter-Packet Times (total)
            meanPacketTimes = np.mean(packetTimes)
            stdevPacketTimes = np.std(packetTimes)
            variancePacketTimes = np.var(packetTimes)
            kurtosisPacketTimes = kurtosis(packetTimes)
            skewPacketTimes = skew(packetTimes)
            maxIPT = np.amax(packetTimes)
            minIPT = np.amin(packetTimes)
            p10PacketTimes = np.percentile(packetTimes, 10)
            p20PacketTimes = np.percentile(packetTimes, 20)
            p30PacketTimes = np.percentile(packetTimes, 30)
            p40PacketTimes = np.percentile(packetTimes, 40)
            p50PacketTimes = np.percentile(packetTimes, 50)
            p60PacketTimes = np.percentile(packetTimes, 60)
            p70PacketTimes = np.percentile(packetTimes, 70)
            p80PacketTimes = np.percentile(packetTimes, 80)
            p90PacketTimes = np.percentile(packetTimes, 90)
        
        except Exception as e:
            print("Error in block 4 when processing " + capture_folder + "/" + sample)
            print("Skipping sample")
            print(e)
            continue

        try:
            ##################################################################
            # Statistical indicators for Inter-Packet Times (in)
            meanPacketTimesIn = np.mean(packetTimesIn)
            stdevPacketTimesIn = np.std(packetTimesIn)
            variancePacketTimesIn = np.var(packetTimesIn)
            kurtosisPacketTimesIn = kurtosis(packetTimesIn)
            skewPacketTimesIn = skew(packetTimesIn)
            maxPacketTimesIn = np.amax(packetTimesIn)
            minPacketTimesIn = np.amin(packetTimesIn)
            p10PacketTimesIn = np.percentile(packetTimesIn, 10)
            p20PacketTimesIn = np.percentile(packetTimesIn, 20)
            p30PacketTimesIn = np.percentile(packetTimesIn, 30)
            p40PacketTimesIn = np.percentile(packetTimesIn, 40)
            p50PacketTimesIn = np.percentile(packetTimesIn, 50)
            p60PacketTimesIn = np.percentile(packetTimesIn, 60)
            p70PacketTimesIn = np.percentile(packetTimesIn, 70)
            p80PacketTimesIn = np.percentile(packetTimesIn, 80)
            p90PacketTimesIn = np.percentile(packetTimesIn, 90)

        except Exception as e:
            print("Error in block 5 when processing " + capture_folder + "/" + sample)
            print("Skipping sample")
            print(e)
            continue

        try:
            ##################################################################
            # Statistical indicators for Inter-Packet Times (out)
            meanPacketTimesOut = np.mean(packetTimesOut)
            stdevPacketTimesOut = np.std(packetTimesOut)
            variancePacketTimesOut = np.var(packetTimesOut)
            kurtosisPacketTimesOut = kurtosis(packetTimesOut)
            skewPacketTimesOut = skew(packetTimesOut)
            maxPacketTimesOut = np.amax(packetTimesOut)
            minPacketTimesOut = np.amin(packetTimesOut)
            p10PacketTimesOut = np.percentile(packetTimesOut, 10)
            p20PacketTimesOut = np.percentile(packetTimesOut, 20)
            p30PacketTimesOut = np.percentile(packetTimesOut, 30)
            p40PacketTimesOut = np.percentile(packetTimesOut, 40)
            p50PacketTimesOut = np.percentile(packetTimesOut, 50)
            p60PacketTimesOut = np.percentile(packetTimesOut, 60)
            p70PacketTimesOut = np.percentile(packetTimesOut, 70)
            p80PacketTimesOut = np.percentile(packetTimesOut, 80)
            p90PacketTimesOut = np.percentile(packetTimesOut, 90)
        
        except Exception as e:
            print("Error in block 6 when processing " + capture_folder + "/" + sample)
            print("Skipping sample")
            print(e)
            continue

        try:
            ########################################################################
            # Statistical indicators for Outgoing bursts
            out_totalBursts = len(out_bursts_packets)
            out_meanBurst = np.mean(out_bursts_packets)
            out_stdevBurst = np.std(out_bursts_packets)
            out_varianceBurst = np.var(out_bursts_packets)
            out_maxBurst = np.amax(out_bursts_packets)
            out_kurtosisBurst = kurtosis(out_bursts_packets)
            out_skewBurst = skew(out_bursts_packets)
            out_p10Burst = np.percentile(out_bursts_packets, 10)
            out_p20Burst = np.percentile(out_bursts_packets, 20)
            out_p30Burst = np.percentile(out_bursts_packets, 30)
            out_p40Burst = np.percentile(out_bursts_packets, 40)
            out_p50Burst = np.percentile(out_bursts_packets, 50)
            out_p60Burst = np.percentile(out_bursts_packets, 60)
            out_p70Burst = np.percentile(out_bursts_packets, 70)
            out_p80Burst = np.percentile(out_bursts_packets, 80)
            out_p90Burst = np.percentile(out_bursts_packets, 90)

        except Exception as e:
            print("Error in block 7 when processing " + capture_folder + "/" + sample)
            print("Skipping sample")
            print(e)
            continue

        try:
            ########################################################################
            # Statistical indicators for Outgoing bytes (sliced intervals)
            out_meanBurstBytes = np.mean(out_burst_sizes)
            out_stdevBurstBytes = np.std(out_burst_sizes)
            out_varianceBurstBytes = np.var(out_burst_sizes)
            out_kurtosisBurstBytes = kurtosis(out_burst_sizes)
            out_skewBurstBytes = skew(out_burst_sizes)
            out_maxBurstBytes = np.amax(out_burst_sizes)
            out_minBurstBytes = np.amin(out_burst_sizes)
            out_p10BurstBytes = np.percentile(out_burst_sizes, 10)
            out_p20BurstBytes = np.percentile(out_burst_sizes, 20)
            out_p30BurstBytes = np.percentile(out_burst_sizes, 30)
            out_p40BurstBytes = np.percentile(out_burst_sizes, 40)
            out_p50BurstBytes = np.percentile(out_burst_sizes, 50)
            out_p60BurstBytes = np.percentile(out_burst_sizes, 60)
            out_p70BurstBytes = np.percentile(out_burst_sizes, 70)
            out_p80BurstBytes = np.percentile(out_burst_sizes, 80)
            out_p90BurstBytes = np.percentile(out_burst_sizes, 90)

        except Exception as e:
            print("Error in block 8 when processing " + capture_folder + "/" + sample)
            print("Skipping sample")
            print(e)
            continue

        try:
            ########################################################################
            # Statistical indicators for Incoming bursts
            in_totalBursts = len(in_bursts_packets)
            in_meanBurst = np.mean(in_bursts_packets)
            in_stdevBurst = np.std(in_bursts_packets)
            in_varianceBurst = np.var(in_bursts_packets)
            in_maxBurst = np.amax(in_bursts_packets)
            in_kurtosisBurst = kurtosis(in_bursts_packets)
            in_skewBurst = skew(in_bursts_packets)
            in_p10Burst = np.percentile(in_bursts_packets, 10)
            in_p20Burst = np.percentile(in_bursts_packets, 20)
            in_p30Burst = np.percentile(in_bursts_packets, 30)
            in_p40Burst = np.percentile(in_bursts_packets, 40)
            in_p50Burst = np.percentile(in_bursts_packets, 50)
            in_p60Burst = np.percentile(in_bursts_packets, 60)
            in_p70Burst = np.percentile(in_bursts_packets, 70)
            in_p80Burst = np.percentile(in_bursts_packets, 80)
            in_p90Burst = np.percentile(in_bursts_packets, 90)

        except Exception as e:
            print("Error in block 9 when processing " + capture_folder + "/" + sample)
            print("Skipping sample")
            print(e)
            continue

        try:
            ########################################################################
            # Statistical indicators for Incoming burst bytes (sliced intervals)
            in_meanBurstBytes = np.mean(in_burst_sizes)
            in_stdevBurstBytes = np.std(in_burst_sizes)
            in_varianceBurstBytes = np.var(in_burst_sizes)
            in_kurtosisBurstBytes = kurtosis(in_burst_sizes)
            in_skewBurstBytes = skew(in_burst_sizes)
            in_maxBurstBytes = np.amax(in_burst_sizes)
            in_minBurstBytes = np.amin(in_burst_sizes)
            in_p10BurstBytes = np.percentile(in_burst_sizes, 10)
            in_p20BurstBytes = np.percentile(in_burst_sizes, 20)
            in_p30BurstBytes = np.percentile(in_burst_sizes, 30)
            in_p40BurstBytes = np.percentile(in_burst_sizes, 40)
            in_p50BurstBytes = np.percentile(in_burst_sizes, 50)
            in_p60BurstBytes = np.percentile(in_burst_sizes, 60)
            in_p70BurstBytes = np.percentile(in_burst_sizes, 70)
            in_p80BurstBytes = np.percentile(in_burst_sizes, 80)
            in_p90BurstBytes = np.percentile(in_burst_sizes, 90)
        
        except Exception as e:
            print("Error in block 10 when processing " + capture_folder + "/" + sample)
            print("Skipping sample")
            print(e)
            continue

        ###############################################################
        # Save extracted packet features
        ###############################################################
        if(mode == "client"):
            extracted_features_folder = "%s/%s/%s/%s/"%(topPath, mode+dataset_name, os.path.basename(capture_folder),sample[:-5])
            tor_node = dst_ip_addr_str
        elif(mode == "onion_server"):
            extracted_features_folder = "%s/%s/%s/%s/%s/"%(topPath, mode+dataset_name, "captures-"+capture_folder.split("/")[-1].split("-")[1], os.path.basename(capture_folder),sample[:-5])
            tor_node = src_ip_addr_str

        if not os.path.exists(extracted_features_folder):
            os.makedirs(extracted_features_folder)

        #Sizes (in)
        sizes_in_file = open(extracted_features_folder + "sizes_in", "w")
        for size in packetSizesIn:
            sizes_in_file.write("%d\n"%size)
        sizes_in_file.close()

        #Sizes (out)
        sizes_out_file = open(extracted_features_folder + "sizes_out", "w")
        for size in packetSizesOut:
            sizes_out_file.write("%d\n"%size)
        sizes_out_file.close()

        #IPT (in)
        times_in_file = open(extracted_features_folder + "times_in", "w")
        for time in packetTimesIn:
            times_in_file.write("%f\n"%time)
        times_in_file.close()

        times_in_file = open(extracted_features_folder + "times_in_rel", "w")
        for time in packetTimesInRel:
            times_in_file.write("%f\n"%time)
        times_in_file.close()

        times_in_file = open(extracted_features_folder + "times_in_abs", "w")
        for time in packetTimesInAbs:
            times_in_file.write("%f\n"%time)
        times_in_file.close()

        #IPT (out)
        times_out_file = open(extracted_features_folder + "times_out", "w")
        for time in packetTimesOut:
            times_out_file.write("%f\n"%time)
        times_out_file.close()

        times_out_file = open(extracted_features_folder + "times_out_rel", "w")
        for time in packetTimesOutRel:
            times_out_file.write("%f\n"%time)
        times_out_file.close()

        times_out_file = open(extracted_features_folder + "times_out_abs", "w")
        for time in packetTimesOutAbs:
            times_out_file.write("%f\n"%time)
        times_out_file.close()

        #Meta stats
        stats_file = open(extracted_features_folder + "meta_stats", "w")
        #stats_file.write("InitialTimestamp: %s\n"%str(datetime.datetime.utcfromtimestamp(first_ts)))
        stats_file.write("InitialTimestamp: %s\n"%str(first_ts))
        stats_file.write("Sizes (in): %s\n"%str(len(packetSizesIn)))
        stats_file.write("Sizes (out): %s\n"%str(len(packetSizesOut)))
        stats_file.write("Times (in): %s\n"%str(len(packetTimesIn)))
        stats_file.write("Times (out): %s\n"%str(len(packetTimesOut)))
        stats_file.write("TorNode: %s\n"%tor_node)
        stats_file.close()

        #Saving Diogo's Features
        f_names_stats = []
        f_values_stats = []

        od_dict = collections.OrderedDict(sorted(bin_dict.items(), key=lambda t: float(t[0])))
        bin_list = []
        for i in od_dict:
            bin_list.append(od_dict[i])

        od_dict2 = collections.OrderedDict(sorted(bin_dict2.items(), key=lambda t: float(t[0])))
        bin_list2 = []
        for i in od_dict2:
            bin_list2.append(od_dict2[i])

        ###################################################################
        # Global Packet Features
        f_names_stats.append('TotalPackets')
        f_values_stats.append(totalPackets)
        f_names_stats.append('totalPacketsIn')
        f_values_stats.append(totalPacketsIn)
        f_names_stats.append('totalPacketsOut')
        f_values_stats.append(totalPacketsOut)
        f_names_stats.append('totalBytes')
        f_values_stats.append(totalBytes)
        f_names_stats.append('totalBytesIn')
        f_values_stats.append(totalBytesIn)
        f_names_stats.append('totalBytesOut')
        f_values_stats.append(totalBytesOut)

        ###################################################################
        # Packet Length Features
        f_names_stats.append('minPacketSize')
        f_values_stats.append(minPacketSize)
        f_names_stats.append('maxPacketSize')
        f_values_stats.append(maxPacketSize)
        f_names_stats.append('meanPacketSizes')
        f_values_stats.append(meanPacketSizes)
        f_names_stats.append('stdevPacketSizes')
        f_values_stats.append(stdevPacketSizes)
        f_names_stats.append('variancePacketSizes')
        f_values_stats.append(variancePacketSizes)
        f_names_stats.append('kurtosisPacketSizes')
        f_values_stats.append(kurtosisPacketSizes)
        f_names_stats.append('skewPacketSizes')
        f_values_stats.append(skewPacketSizes)

        f_names_stats.append('p10PacketSizes')
        f_values_stats.append(p10PacketSizes)
        f_names_stats.append('p20PacketSizes')
        f_values_stats.append(p20PacketSizes)
        f_names_stats.append('p30PacketSizes')
        f_values_stats.append(p30PacketSizes)
        f_names_stats.append('p40PacketSizes')
        f_values_stats.append(p40PacketSizes)
        f_names_stats.append('p50PacketSizes')
        f_values_stats.append(p50PacketSizes)
        f_names_stats.append('p60PacketSizes')
        f_values_stats.append(p60PacketSizes)
        f_names_stats.append('p70PacketSizes')
        f_values_stats.append(p70PacketSizes)
        f_names_stats.append('p80PacketSizes')
        f_values_stats.append(p80PacketSizes)
        f_names_stats.append('p90PacketSizes')
        f_values_stats.append(p90PacketSizes)

        ###################################################################
        # Packet Length Features (in)
        f_names_stats.append('minPacketSizeIn')
        f_values_stats.append(minPacketSizeIn)
        f_names_stats.append('maxPacketSizeIn')
        f_values_stats.append(maxPacketSizeIn)
        f_names_stats.append('meanPacketSizesIn')
        f_values_stats.append(meanPacketSizesIn)
        f_names_stats.append('stdevPacketSizesIn')
        f_values_stats.append(stdevPacketSizesIn)
        f_names_stats.append('variancePacketSizesIn')
        f_values_stats.append(variancePacketSizesIn)
        f_names_stats.append('skewPacketSizesIn')
        f_values_stats.append(skewPacketSizesIn)
        f_names_stats.append('kurtosisPacketSizesIn')
        f_values_stats.append(kurtosisPacketSizesIn)

        f_names_stats.append('p10PacketSizesIn')
        f_values_stats.append(p10PacketSizesIn)
        f_names_stats.append('p20PacketSizesIn')
        f_values_stats.append(p20PacketSizesIn)
        f_names_stats.append('p30PacketSizesIn')
        f_values_stats.append(p30PacketSizesIn)
        f_names_stats.append('p40PacketSizesIn')
        f_values_stats.append(p40PacketSizesIn)
        f_names_stats.append('p50PacketSizesIn')
        f_values_stats.append(p50PacketSizesIn)
        f_names_stats.append('p60PacketSizesIn')
        f_values_stats.append(p60PacketSizesIn)
        f_names_stats.append('p70PacketSizesIn')
        f_values_stats.append(p70PacketSizesIn)
        f_names_stats.append('p80PacketSizesIn')
        f_values_stats.append(p80PacketSizesIn)
        f_names_stats.append('p90PacketSizesIn')
        f_values_stats.append(p90PacketSizesIn)

        ###################################################################
        # Packet Length Features (out)
        f_names_stats.append('minPacketSizeOut')
        f_values_stats.append(minPacketSizeOut)
        f_names_stats.append('maxPacketSizeOut')
        f_values_stats.append(maxPacketSizeOut)
        f_names_stats.append('meanPacketSizesOut')
        f_values_stats.append(meanPacketSizesOut)
        f_names_stats.append('stdevPacketSizesOut')
        f_values_stats.append(stdevPacketSizesOut)
        f_names_stats.append('variancePacketSizesOut')
        f_values_stats.append(variancePacketSizesOut)
        f_names_stats.append('skewPacketSizesOut')
        f_values_stats.append(skewPacketSizesOut)
        f_names_stats.append('kurtosisPacketSizesOut')
        f_values_stats.append(kurtosisPacketSizesOut)

        f_names_stats.append('p10PacketSizesOut')
        f_values_stats.append(p10PacketSizesOut)
        f_names_stats.append('p20PacketSizesOut')
        f_values_stats.append(p20PacketSizesOut)
        f_names_stats.append('p30PacketSizesOut')
        f_values_stats.append(p30PacketSizesOut)
        f_names_stats.append('p40PacketSizesOut')
        f_values_stats.append(p40PacketSizesOut)
        f_names_stats.append('p50PacketSizesOut')
        f_values_stats.append(p50PacketSizesOut)
        f_names_stats.append('p60PacketSizesOut')
        f_values_stats.append(p60PacketSizesOut)
        f_names_stats.append('p70PacketSizesOut')
        f_values_stats.append(p70PacketSizesOut)
        f_names_stats.append('p80PacketSizesOut')
        f_values_stats.append(p80PacketSizesOut)
        f_names_stats.append('p90PacketSizesOut')
        f_values_stats.append(p90PacketSizesOut)

        ###################################################################
        # Packet Timing Features
        f_names_stats.append('maxIPT')
        f_values_stats.append(maxIPT)
        f_names_stats.append('minIPT')
        f_values_stats.append(minIPT)
        f_names_stats.append('meanPacketTimes')
        f_values_stats.append(meanPacketTimes)
        f_names_stats.append('stdevPacketTimes')
        f_values_stats.append(stdevPacketTimes)
        f_names_stats.append('variancePacketTimes')
        f_values_stats.append(variancePacketTimes)
        f_names_stats.append('kurtosisPacketTimes')
        f_values_stats.append(kurtosisPacketTimes)
        f_names_stats.append('skewPacketTimes')
        f_values_stats.append(skewPacketTimes)

        f_names_stats.append('p10PacketTimes')
        f_values_stats.append(p10PacketTimes)
        f_names_stats.append('p20PacketTimes')
        f_values_stats.append(p20PacketTimes)
        f_names_stats.append('p30PacketTimes')
        f_values_stats.append(p30PacketTimes)
        f_names_stats.append('p40PacketTimes')
        f_values_stats.append(p40PacketTimes)
        f_names_stats.append('p50PacketTimes')
        f_values_stats.append(p50PacketTimes)
        f_names_stats.append('p60PacketTimes')
        f_values_stats.append(p60PacketTimes)
        f_names_stats.append('p70PacketTimes')
        f_values_stats.append(p70PacketTimes)
        f_names_stats.append('p80PacketTimes')
        f_values_stats.append(p80PacketTimes)
        f_names_stats.append('p90PacketTimes')
        f_values_stats.append(p90PacketTimes)

        ###################################################################
        # Packet Timing Features (in)
        f_names_stats.append('minPacketTimesIn')
        f_values_stats.append(minPacketTimesIn)
        f_names_stats.append('maxPacketTimesIn')
        f_values_stats.append(maxPacketTimesIn)
        f_names_stats.append('meanPacketTimesIn')
        f_values_stats.append(meanPacketTimesIn)
        f_names_stats.append('stdevPacketTimesIn')
        f_values_stats.append(stdevPacketTimesIn)
        f_names_stats.append('variancePacketTimesIn')
        f_values_stats.append(variancePacketTimesIn)
        f_names_stats.append('skewPacketTimesIn')
        f_values_stats.append(skewPacketTimesIn)
        f_names_stats.append('kurtosisPacketTimesIn')
        f_values_stats.append(kurtosisPacketTimesIn)

        f_names_stats.append('p10PacketTimesIn')
        f_values_stats.append(p10PacketTimesIn)
        f_names_stats.append('p20PacketTimesIn')
        f_values_stats.append(p20PacketTimesIn)
        f_names_stats.append('p30PacketTimesIn')
        f_values_stats.append(p30PacketTimesIn)
        f_names_stats.append('p40PacketTimesIn')
        f_values_stats.append(p40PacketTimesIn)
        f_names_stats.append('p50PacketTimesIn')
        f_values_stats.append(p50PacketTimesIn)
        f_names_stats.append('p60PacketTimesIn')
        f_values_stats.append(p60PacketTimesIn)
        f_names_stats.append('p70PacketTimesIn')
        f_values_stats.append(p70PacketTimesIn)
        f_names_stats.append('p80PacketTimesIn')
        f_values_stats.append(p80PacketTimesIn)
        f_names_stats.append('p90PacketTimesIn')
        f_values_stats.append(p90PacketTimesIn)

        ###################################################################
        # Packet Timing Features (out)
        f_names_stats.append('minPacketTimesOut')
        f_values_stats.append(minPacketTimesOut)
        f_names_stats.append('maxPacketTimesOut')
        f_values_stats.append(maxPacketTimesOut)
        f_names_stats.append('meanPacketTimesOut')
        f_values_stats.append(meanPacketTimesOut)
        f_names_stats.append('stdevPacketTimesOut')
        f_values_stats.append(stdevPacketTimesOut)
        f_names_stats.append('variancePacketTimesOut')
        f_values_stats.append(variancePacketTimesOut)
        f_names_stats.append('skewPacketTimesOut')
        f_values_stats.append(skewPacketTimesOut)
        f_names_stats.append('kurtosisPacketTimesOut')
        f_values_stats.append(kurtosisPacketTimesOut)

        f_names_stats.append('p10PacketTimesOut')
        f_values_stats.append(p10PacketTimesOut)
        f_names_stats.append('p20PacketTimesOut')
        f_values_stats.append(p20PacketTimesOut)
        f_names_stats.append('p30PacketTimesOut')
        f_values_stats.append(p30PacketTimesOut)
        f_names_stats.append('p40PacketTimesOut')
        f_values_stats.append(p40PacketTimesOut)
        f_names_stats.append('p50PacketTimesOut')
        f_values_stats.append(p50PacketTimesOut)
        f_names_stats.append('p60PacketTimesOut')
        f_values_stats.append(p60PacketTimesOut)
        f_names_stats.append('p70PacketTimesOut')
        f_values_stats.append(p70PacketTimesOut)
        f_names_stats.append('p80PacketTimesOut')
        f_values_stats.append(p80PacketTimesOut)
        f_names_stats.append('p90PacketTimesOut')
        f_values_stats.append(p90PacketTimesOut)

        #################################################################
        # Outgoing Packet number of Bursts features
        f_names_stats.append('out_totalBursts')
        f_values_stats.append(out_totalBursts)
        f_names_stats.append('out_maxBurst')
        f_values_stats.append(out_maxBurst)
        f_names_stats.append('out_meanBurst')
        f_values_stats.append(out_meanBurst)
        f_names_stats.append('out_stdevBurst')
        f_values_stats.append(out_stdevBurst)
        f_names_stats.append('out_varianceBurst')
        f_values_stats.append(out_varianceBurst)
        f_names_stats.append('out_kurtosisBurst')
        f_values_stats.append(out_kurtosisBurst)
        f_names_stats.append('out_skewBurst')
        f_values_stats.append(out_skewBurst)

        f_names_stats.append('out_p10Burst')
        f_values_stats.append(out_p10Burst)
        f_names_stats.append('out_p20Burst')
        f_values_stats.append(out_p20Burst)
        f_names_stats.append('out_p30Burst')
        f_values_stats.append(out_p30Burst)
        f_names_stats.append('out_p40Burst')
        f_values_stats.append(out_p40Burst)
        f_names_stats.append('out_p50Burst')
        f_values_stats.append(out_p50Burst)
        f_names_stats.append('out_p60Burst')
        f_values_stats.append(out_p60Burst)
        f_names_stats.append('out_p70Burst')
        f_values_stats.append(out_p70Burst)
        f_names_stats.append('out_p80Burst')
        f_values_stats.append(out_p80Burst)
        f_names_stats.append('out_p90Burst')
        f_values_stats.append(out_p90Burst)

        #################################################################
        # Outgoing Packet Bursts data size features
        f_names_stats.append('out_maxBurstBytes')
        f_values_stats.append(out_maxBurstBytes)
        f_names_stats.append('out_minBurstBytes')
        f_values_stats.append(out_minBurstBytes)
        f_names_stats.append('out_meanBurstBytes')
        f_values_stats.append(out_meanBurstBytes)
        f_names_stats.append('out_stdevBurstBytes')
        f_values_stats.append(out_stdevBurstBytes)
        f_names_stats.append('out_varianceBurstBytes')
        f_values_stats.append(out_varianceBurstBytes)
        f_names_stats.append('out_kurtosisBurstBytes')
        f_values_stats.append(out_kurtosisBurstBytes)
        f_names_stats.append('out_skewBurstBytes')
        f_values_stats.append(out_skewBurstBytes)

        f_names_stats.append('out_p10BurstBytes')
        f_values_stats.append(out_p10BurstBytes)
        f_names_stats.append('out_p20BurstBytes')
        f_values_stats.append(out_p20BurstBytes)
        f_names_stats.append('out_p30BurstBytes')
        f_values_stats.append(out_p30BurstBytes)
        f_names_stats.append('out_p40BurstBytes')
        f_values_stats.append(out_p40BurstBytes)
        f_names_stats.append('out_p50BurstBytes')
        f_values_stats.append(out_p50BurstBytes)
        f_names_stats.append('out_p60BurstBytes')
        f_values_stats.append(out_p60BurstBytes)
        f_names_stats.append('out_p70BurstBytes')
        f_values_stats.append(out_p70BurstBytes)
        f_names_stats.append('out_p80BurstBytes')
        f_values_stats.append(out_p80BurstBytes)
        f_names_stats.append('out_p90BurstBytes')
        f_values_stats.append(out_p90BurstBytes)

        #################################################################
        # Incoming Packet number of Bursts features
        f_names_stats.append('in_totalBursts')
        f_values_stats.append(in_totalBursts)
        f_names_stats.append('in_maxBurst')
        f_values_stats.append(in_maxBurst)
        f_names_stats.append('in_meanBurst')
        f_values_stats.append(in_meanBurst)
        f_names_stats.append('in_stdevBurst')
        f_values_stats.append(in_stdevBurst)
        f_names_stats.append('in_varianceBurst')
        f_values_stats.append(in_varianceBurst)
        f_names_stats.append('in_kurtosisBurst')
        f_values_stats.append(in_kurtosisBurst)
        f_names_stats.append('in_skewBurst')
        f_values_stats.append(in_skewBurst)

        f_names_stats.append('in_p10Burst')
        f_values_stats.append(in_p10Burst)
        f_names_stats.append('in_p20Burst')
        f_values_stats.append(in_p20Burst)
        f_names_stats.append('in_p30Burst')
        f_values_stats.append(in_p30Burst)
        f_names_stats.append('in_p40Burst')
        f_values_stats.append(in_p40Burst)
        f_names_stats.append('in_p50Burst')
        f_values_stats.append(in_p50Burst)
        f_names_stats.append('in_p60Burst')
        f_values_stats.append(in_p60Burst)
        f_names_stats.append('in_p70Burst')
        f_values_stats.append(in_p70Burst)
        f_names_stats.append('in_p80Burst')
        f_values_stats.append(in_p80Burst)
        f_names_stats.append('in_p90Burst')
        f_values_stats.append(in_p90Burst)

        #################################################################
        # Incoming Packet Bursts data size features
        f_names_stats.append('in_maxBurstBytes')
        f_values_stats.append(in_maxBurstBytes)
        f_names_stats.append('in_minBurstBytes')
        f_values_stats.append(in_minBurstBytes)
        f_names_stats.append('in_meanBurstBytes')
        f_values_stats.append(in_meanBurstBytes)
        f_names_stats.append('in_stdevBurstBytes')
        f_values_stats.append(in_stdevBurstBytes)
        f_names_stats.append('in_varianceBurstBytes')
        f_values_stats.append(in_varianceBurstBytes)
        f_names_stats.append('in_kurtosisBurstBytes')
        f_values_stats.append(in_kurtosisBurstBytes)
        f_names_stats.append('in_skewBurstBytes')
        f_values_stats.append(in_skewBurstBytes)

        f_names_stats.append('in_p10BurstBytes')
        f_values_stats.append(in_p10BurstBytes)
        f_names_stats.append('in_p20BurstBytes')
        f_values_stats.append(in_p20BurstBytes)
        f_names_stats.append('in_p30BurstBytes')
        f_values_stats.append(in_p30BurstBytes)
        f_names_stats.append('in_p40BurstBytes')
        f_values_stats.append(in_p40BurstBytes)
        f_names_stats.append('in_p50BurstBytes')
        f_values_stats.append(in_p50BurstBytes)
        f_names_stats.append('in_p60BurstBytes')
        f_values_stats.append(in_p60BurstBytes)
        f_names_stats.append('in_p70BurstBytes')
        f_values_stats.append(in_p70BurstBytes)
        f_names_stats.append('in_p80BurstBytes')
        f_values_stats.append(in_p80BurstBytes)
        f_names_stats.append('in_p90BurstBytes')
        f_values_stats.append(in_p90BurstBytes)

        special_features = {}
        for i in range(len(f_names_stats)):
            special_features[f_names_stats[i]] = f_values_stats[i]

        special_features_file = open(extracted_features_folder + "special_features", "wb")
        pickle.dump(special_features, special_features_file)
        special_features_file.close()


def extract_features():
    extract_client_data(DATA_FOLDER)
    extract_onion_server_data(DATA_FOLDER)


def store_alexa_features(connection):
    folderDict = {}
    folderDict['clientFolder'] = connection

    clientInitialTimeStamp = 0
    clientIn = 0
    clientOut = 0

    #client reading flow properties
    with open(folderDict['clientFolder'] + '/meta_stats') as f:
        for line in f:
            if 'InitialTimestamp' in line:
                clientInitialTimeStamp = float(line[:-1].split(' ')[-1])
            elif 'Sizes (in)' in line:
                clientIn = int(line[:-1].split(' ')[-1])
            elif 'Sizes (out)' in line:
                clientOut = int(line[:-1].split(' ')[-1])

    folderDict['clientMetaStats'] = {}
    folderDict['clientMetaStats']['initialTimestamp'] = clientInitialTimeStamp
    folderDict['clientMetaStats']['sizesIn'] = clientIn
    folderDict['clientMetaStats']['sizesOut'] = clientOut

    #client reading flow properties
    with open(folderDict['clientFolder'] + '/times_in') as f:
        clientTimesIn = f.readlines()
    clientTimesIn = [float(x) for x in clientTimesIn] 

    with open(folderDict['clientFolder'] + '/times_in_rel') as f:
        clientTimesInRel = f.readlines()
    clientTimesInRel = [float(x) for x in clientTimesInRel] 

    with open(folderDict['clientFolder'] + '/times_in_abs') as f:
        clientTimesInAbs = f.readlines()
    clientTimesInAbs = [float(x) for x in clientTimesInAbs] 

    with open(folderDict['clientFolder'] + '/times_out') as f:
        clientTimesOut= f.readlines()
    clientTimesOut = [float(x) for x in clientTimesOut] 

    with open(folderDict['clientFolder'] + '/times_out_rel') as f:
        clientTimesOutRel= f.readlines()
    clientTimesOutRel = [float(x) for x in clientTimesOutRel]

    with open(folderDict['clientFolder'] + '/times_out_abs') as f:
        clientTimesOutAbs= f.readlines()
    clientTimesOutAbs = [float(x) for x in clientTimesOutAbs]

    with open(folderDict['clientFolder'] + '/sizes_in') as f:
        clientSizesIn = f.readlines()
    clientSizesIn = [float(x) for x in clientSizesIn] 

    with open(folderDict['clientFolder'] + '/sizes_out') as f:
        clientSizesOut = f.readlines()
    clientSizesOut = [float(x) for x in clientSizesOut] 

    folderDict['clientFlow'] = {}
    folderDict['clientFlow']['timesIn'] = clientTimesIn
    folderDict['clientFlow']['timesOut'] = clientTimesOut
    folderDict['clientFlow']['timesInRel'] = clientTimesInRel
    folderDict['clientFlow']['timesOutRel'] = clientTimesOutRel
    folderDict['clientFlow']['timesInAbs'] = clientTimesInAbs
    folderDict['clientFlow']['timesOutAbs'] = clientTimesOutAbs
    folderDict['clientFlow']['sizesIn'] = clientSizesIn
    folderDict['clientFlow']['sizesOut'] = clientSizesOut

    folderDict['clientFeatures'] = pickle.load(open(folderDict['clientFolder'] + '/diogos_features', 'rb'))

    key = connection
    sessionIndex = int(connection.split('session_')[1].split('_')[0])
    if key not in alexaFolders:
        alexaFolders[key] = []

    if sessionIndex >= len(alexaFolders[key]):
        for i in range(len(alexaFolders[key]), sessionIndex + 1):
            alexaFolders[key].append([])
    alexaFolders[key][sessionIndex] += [folderDict]

    if onionUrl not in onionAddressData:
        onionAddressData[onionUrl] = {'connectionIndex': 0}


#for locationIndex in tqdm.tqdm(listdir(clientPath)):
for connection in tqdm.tqdm(listdir(clientPath)):
    #print("----> locationIndex:", locationIndex)
    # Take care of .DS_Store files
    #if isdir(clientPath+locationIndex):
    if isdir(clientPath+connection):
        #for connection in tqdm.tqdm(listdir(clientPath+locationIndex)):

        if 'request' in connection:
            continue
        # Process alexa into another folder
        if 'alexa' in connection:
            continue
        
        #if 'alexa' in connection:
        #    store_alexa_features(connection)
        #    continue

        count += 1
        folderDict = {}
        #clientFolder = clientPath + locationIndex + '/' + connection
        clientFolder = clientPath + '/' + connection

        #print("locationIndex", locationIndex)
        
        origin = connection.split('_')[0]
        origin_machine = origin.split('-client')[0]
        destination = connection.split('_')[1]
        destination_machine = 'os' + destination.split('-os')[1]
        onionUrl = connection.split('_')[2]
        #size = connection.split('_')[3]
        #extraRequests = connection.split('_')[4]
        #index = connection.split('_')[5]
        index = connection.split('_')[3]

        originFolder = origin.split("-")[1]
        
        hsEnding_part0 = connection.split("_session")[1]
        hsEnding_part1 = hsEnding_part0.split("client")[0]
        hsEnding = hsEnding_part1 + "hs"
        #hsFolder = hsPath + "captures-" + originFolder + '/' + origin + '-' + destination + '/' + origin + '_' + destination + '_' + onionUrl + '_' + index + hsEnding
        hsFolder = hsPath + "captures-" + originFolder + '/' + origin_machine + '-' + destination_machine + '/' + origin + '_' + destination + '_' + onionUrl + '_' + index + hsEnding
        #hsFolder = hsPath + "captures-" + originFolder + '/' + origin + '-' + destination + '/' + origin + '_' + destination + '_' + onionUrl + '_' + size + '_' + extraRequests + '_' + index + hsEnding

        if(not isdir(hsFolder)):
            print("not dir:" , hsFolder)
            continue
        
        folderDict['clientFolder'] = clientFolder
        folderDict['hsFolder'] = hsFolder
        folderDict['clientLocation'] = origin
        folderDict['hsLocation'] = destination
        folderDict['onionAddress'] = onionUrl
        #folderDict['size'] = size
        #folderDict['extraRequests'] = extraRequests
        

        clientInitialTimeStamp = 0
        clientIn = 0
        clientOut = 0

        hsInitialTimeStamp = 0
        hsIn = 0
        hsOut = 0

        #client reading flow properties
        with open(folderDict['clientFolder'] + '/meta_stats') as f:
            for line in f:
                if 'InitialTimestamp' in line:
                    clientInitialTimeStamp = float(line[:-1].split(' ')[-1])
                elif 'Sizes (in)' in line:
                    clientIn = int(line[:-1].split(' ')[-1])
                elif 'Sizes (out)' in line:
                    clientOut = int(line[:-1].split(' ')[-1])


        #hs reading flow properties
        with open(folderDict['hsFolder'] + '/meta_stats') as f:
            for line in f:
                if 'InitialTimestamp' in line:
                    hsInitialTimeStamp = float(line[:-1].split(' ')[-1])
                elif 'Sizes (in)' in line:
                    hsIn = int(line[:-1].split(' ')[-1])
                elif 'Sizes (out)' in line:
                    hsOut = int(line[:-1].split(' ')[-1]) 

        folderDict['clientMetaStats'] = {}
        folderDict['clientMetaStats']['initialTimestamp'] = clientInitialTimeStamp
        folderDict['clientMetaStats']['sizesIn'] = clientIn
        folderDict['clientMetaStats']['sizesOut'] = clientOut

        folderDict['hsMetaStats'] = {}
        folderDict['hsMetaStats']['initialTimestamp'] = hsInitialTimeStamp
        folderDict['hsMetaStats']['sizesIn'] = hsIn
        folderDict['hsMetaStats']['sizesOut'] = hsOut


        #client reading flow properties
        with open(folderDict['clientFolder'] + '/times_in') as f:
            clientTimesIn = f.readlines()
        clientTimesIn = [float(x) for x in clientTimesIn] 

        with open(folderDict['clientFolder'] + '/times_in_rel') as f:
            clientTimesInRel = f.readlines()
        clientTimesInRel = [float(x) for x in clientTimesInRel] 

        with open(folderDict['clientFolder'] + '/times_in_abs') as f:
            clientTimesInAbs = f.readlines()
        clientTimesInAbs = [float(x) for x in clientTimesInAbs] 

        with open(folderDict['clientFolder'] + '/times_out') as f:
            clientTimesOut= f.readlines()
        clientTimesOut = [float(x) for x in clientTimesOut] 

        with open(folderDict['clientFolder'] + '/times_out_rel') as f:
            clientTimesOutRel= f.readlines()
        clientTimesOutRel = [float(x) for x in clientTimesOutRel]

        with open(folderDict['clientFolder'] + '/times_out_abs') as f:
            clientTimesOutAbs= f.readlines()
        clientTimesOutAbs = [float(x) for x in clientTimesOutAbs]

        with open(folderDict['clientFolder'] + '/sizes_in') as f:
            clientSizesIn = f.readlines()
        clientSizesIn = [float(x) for x in clientSizesIn] 

        with open(folderDict['clientFolder'] + '/sizes_out') as f:
            clientSizesOut = f.readlines()
        clientSizesOut = [float(x) for x in clientSizesOut] 

        #hs reading flow properties
        with open(folderDict['hsFolder'] + '/times_in') as f:
            hsTimesIn = f.readlines()
        hsTimesIn = [float(x) for x in hsTimesIn] 

        with open(folderDict['hsFolder'] + '/times_in_abs') as f:
            hsTimesInAbs = f.readlines()
        hsTimesInAbs = [float(x) for x in hsTimesInAbs] 

        with open(folderDict['hsFolder'] + '/times_in_rel') as f:
            hsTimesInRel = f.readlines()
        hsTimesInRel = [float(x) for x in hsTimesInRel] 

        with open(folderDict['hsFolder'] + '/times_out') as f:
            hsTimesOut= f.readlines()
        hsTimesOut = [float(x) for x in hsTimesOut] 

        with open(folderDict['hsFolder'] + '/times_out_rel') as f:
            hsTimesOutRel= f.readlines()
        hsTimesOutRel = [float(x) for x in hsTimesOutRel]

        with open(folderDict['hsFolder'] + '/times_out_abs') as f:
            hsTimesOutAbs= f.readlines()
        hsTimesOutAbs = [float(x) for x in hsTimesOutAbs]

        with open(folderDict['hsFolder'] + '/sizes_in') as f:
            hsSizesIn = f.readlines()
        hsSizesIn = [float(x) for x in hsSizesIn] 

        with open(folderDict['hsFolder'] + '/sizes_out') as f:
            hsSizesOut = f.readlines()
        hsSizesOut = [float(x) for x in hsSizesOut]  

        folderDict['clientFlow'] = {}
        folderDict['clientFlow']['timesIn'] = clientTimesIn
        folderDict['clientFlow']['timesOut'] = clientTimesOut
        folderDict['clientFlow']['timesInRel'] = clientTimesInRel
        folderDict['clientFlow']['timesOutRel'] = clientTimesOutRel
        folderDict['clientFlow']['timesInAbs'] = clientTimesInAbs
        folderDict['clientFlow']['timesOutAbs'] = clientTimesOutAbs
        folderDict['clientFlow']['sizesIn'] = clientSizesIn
        folderDict['clientFlow']['sizesOut'] = clientSizesOut

        folderDict['hsFlow'] = {}
        folderDict['hsFlow']['timesIn'] = hsTimesIn
        folderDict['hsFlow']['timesOut'] = hsTimesOut
        folderDict['hsFlow']['timesInRel'] = hsTimesInRel
        folderDict['hsFlow']['timesOutRel'] = hsTimesOutRel
        folderDict['hsFlow']['timesInAbs'] = hsTimesInAbs
        folderDict['hsFlow']['timesOutAbs'] = hsTimesOutAbs
        folderDict['hsFlow']['sizesIn'] = hsSizesIn
        folderDict['hsFlow']['sizesOut'] = hsSizesOut

        folderDict['hsFeatures'] = pickle.load(open(folderDict['hsFolder'] + '/diogos_features', 'rb'))
        folderDict['clientFeatures'] = pickle.load(open(folderDict['clientFolder'] + '/diogos_features', 'rb'))

        key = (origin, destination)
        sessionIndex = int(connection.split('session_')[1].split('_')[0])
        if key not in pairsFolders:
            pairsFolders[key] = []

        if sessionIndex >= len(pairsFolders[key]):
            for i in range(len(pairsFolders[key]), sessionIndex + 1):
                pairsFolders[key].append([])
        pairsFolders[key][sessionIndex] += [folderDict]

        if onionUrl not in onionAddressData:
            onionAddressData[onionUrl] = {'connectionIndex': 0}

        countBothWays += 1


def flattenList(list1):
    return [item for sublist in list1 for item in sublist]


def shufflePairs(pairsFolders):

    testPairsFolders = []

    for key in pairsFolders:
        sessionFolders = pairsFolders[key]

        # Get rid of empty sublists
        sessionFoldersNoEmpties = [x for x in sessionFolders if x != []]

        rd.shuffle(sessionFoldersNoEmpties)
        
        testPairsFoldersFlat = flattenList(sessionFoldersNoEmpties)

        testPairsFolders += testPairsFoldersFlat

    return testPairsFolders


def generateCorrelatedPairs(pairsFoldersInput):

    samples = []
    labels = []

    for pairFolder in tqdm.tqdm(pairsFoldersInput):
        samples += [pairFolder]
        labels += [1]
        
    return samples, labels


def extract_pairs_features():
    extract_features()

    testPairsFolders = shufflePairs(pairsFolders)
    pickle.dump(alexaFolders, open("alexa_features.pickle", "wb" ))

    allPairs = {'correlated': {}}
    saveFile = 'testPairs_{}'.format(dataset_name)
    samples, labels = generateCorrelatedPairs(testPairsFolders)
    print('##############################3')
    print('Correlated Pairs')
    print('Total number of pairs:', len(samples))
    allPairs['correlated']['samples'] = samples 
    allPairs['correlated']['labels'] = labels  
    pickle.dump(allPairs, open(saveFile, "wb" ))
