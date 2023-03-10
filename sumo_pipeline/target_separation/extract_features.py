#!/usr/bin/env python3
import collections
import os
import numpy as np
from scipy.stats import kurtosis, skew
from scapy.all import *


def RoundToNearest(n, m):
    r = n % m
    return n + m - r if r + r >= m else n - r


def extract_features(captureFolder, arff_stats, arff_pl, written_header_stats, written_header_pl):
    
    for capture in os.listdir(captureFolder):

        if '.pcap' not in capture:
            continue

        if '.zst' in capture:
            continue

        if '._' in capture:
            continue

        # we only want session captures
        if 'request' in capture:
            continue

        if 'alexa' in capture:
            label = 0
        else:
            label = 1

        try:
            pcap = PcapReader(captureFolder+capture)
        except Exception as e:
            print("Problem parsing pcap {}".format(captureFolder+capture))
            print(e)
            continue

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
        packetSizesIn = []
        packetSizesOut = []

        bin_dict = {}
        bin_dict2 = {}
        binWidth = 5
        # Generate the set of all possible bins
        for i in range(0, 150000, binWidth):
            bin_dict[i] = 0
            bin_dict2[i] = 0

        # Analyse inter packet timing
        packetTimes = []
        packetTimesIn = []
        packetTimesOut = []

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
        absTimesOut = []
        first_ts = -1

        i = 0

        packetCount = 0
        for i, pkt in enumerate(pcap):
            #if packetCount > capturPacketLimit:
            #    break
            ts = np.float64(pkt.time)
            size = pkt.wirelen

            if first_ts == -1:
                first_ts = ts

            #Ignore UDP packets
            if pkt.haslayer(TCP):
            
                try:
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

                    # General packet statistics
                    totalPackets += 1

                    # If source is recipient
                    if ('172.' in src_ip_addr_str):
                        totalPacketsIn += 1
                        packetSizesIn.append(size)
                        binned = RoundToNearest(size, binWidth)
                        bin_dict2[binned] += 1
                        if (prev_ts != 0):
                            ts_difference = max(0, ts - prev_ts)
                            packetTimesIn.append(ts_difference * 1000)

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
                        in_current_burst_size += size
                    # If source is caller
                    else:
                        totalPacketsOut += 1
                        absTimesOut.append(ts)
                        packetSizesOut.append(size)
                        binned = RoundToNearest(size, binWidth)
                        bin_dict[binned] += 1
                        if (prev_ts != 0):
                            ts_difference = max(0, ts - prev_ts)
                            packetTimesOut.append(ts_difference * 1000)
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
                            in_current_burst_start = 0

                    # Bytes transmitted statistics
                    totalBytes += size
                    if ('172.' in src_ip_addr_str):
                        totalBytesIn += size
                    else:
                        totalBytesOut += size

                    # Packet Size statistics
                    packetSizes.append(size)

                    # Packet Times statistics
                    if (prev_ts != 0):
                        # print "{0:.6f}".format(ts)
                        ts_difference = max(0, ts - prev_ts)
                        packetTimes.append(ts_difference * 1000)

                    prev_ts = ts
                except Exception as e:
                    #print("Exception occurred for capture", capture)
                    #print(e)
                    pass
                packetCount += 1

        ################################################################
        ####################Compute statistics#####################
        ################################################################
        try:
            ##########################################################
            # Statistical indicators for packet sizes (total)
            if len(packetSizes) == 0:
                meanPacketSizes = 0
                stdevPacketSizes = 0
                variancePacketSizes = 0
                kurtosisPacketSizes = 0
                skewPacketSizes = 0
                maxPacketSize = 0
                minPacketSize = 0
                p10PacketSizes = 0
                p20PacketSizes = 0
                p30PacketSizes = 0
                p40PacketSizes = 0
                p50PacketSizes = 0
                p60PacketSizes = 0
                p70PacketSizes = 0
                p80PacketSizes = 0
                p90PacketSizes = 0
            else:
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

            ##########################################################
            # Statistical indicators for packet sizes (in)
            if len(packetSizesIn) == 0:
                meanPacketSizesIn = 0
                stdevPacketSizesIn = 0
                variancePacketSizesIn = 0
                kurtosisPacketSizesIn = 0
                skewPacketSizesIn = 0
                maxPacketSizeIn = 0
                minPacketSizeIn = 0
                p10PacketSizesIn = 0
                p20PacketSizesIn = 0
                p30PacketSizesIn = 0
                p40PacketSizesIn = 0
                p50PacketSizesIn = 0
                p60PacketSizesIn = 0
                p70PacketSizesIn = 0
                p80PacketSizesIn = 0
                p90PacketSizesIn = 0
            else:
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

            ##########################################################
            # Statistical indicators for packet sizes (out)
            if len(packetSizesOut) == 0:
                meanPacketSizesOut = 0
                stdevPacketSizesOut = 0
                variancePacketSizesOut = 0
                kurtosisPacketSizesOut = 0
                skewPacketSizesOut = 0
                maxPacketSizeOut = 0
                minPacketSizeOut = 0
                p10PacketSizesOut = 0
                p20PacketSizesOut = 0
                p30PacketSizesOut = 0
                p40PacketSizesOut = 0
                p50PacketSizesOut = 0
                p60PacketSizesOut = 0
                p70PacketSizesOut = 0
                p80PacketSizesOut = 0
                p90PacketSizesOut = 0
            else:
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

            ##################################################################
            # Statistical indicators for Inter-Packet Times (total)
            if len(packetTimes) == 0:
                meanPacketTimes = 0
                stdevPacketTimes = 0
                variancePacketTimes = 0
                kurtosisPacketTimes = 0
                skewPacketTimes = 0
                maxIPT = 0
                minIPT = 0
                p10PacketTimes = 0
                p20PacketTimes = 0
                p30PacketTimes = 0
                p40PacketTimes = 0
                p50PacketTimes = 0
                p60PacketTimes = 0
                p70PacketTimes = 0
                p80PacketTimes = 0
                p90PacketTimes = 0
            else:
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

            ##################################################################
            # Statistical indicators for Inter-Packet Times (in)
            if len(packetTimesIn) == 0:
                meanPacketTimesIn = 0
                stdevPacketTimesIn = 0
                variancePacketTimesIn = 0
                kurtosisPacketTimesIn = 0
                skewPacketTimesIn = 0
                maxPacketTimesIn = 0
                minPacketTimesIn = 0
                p10PacketTimesIn = 0
                p20PacketTimesIn = 0
                p30PacketTimesIn = 0
                p40PacketTimesIn = 0
                p50PacketTimesIn = 0
                p60PacketTimesIn = 0
                p70PacketTimesIn = 0
                p80PacketTimesIn = 0
                p90PacketTimesIn = 0
            else:
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

            ##################################################################
            # Statistical indicators for Inter-Packet Times (out)
            if len(packetTimesOut) == 0:
                meanPacketTimesOut = 0
                stdevPacketTimesOut = 0
                variancePacketTimesOut = 0
                kurtosisPacketTimesOut = 0
                skewPacketTimesOut = 0
                maxPacketTimesOut = 0
                minPacketTimesOut = 0
                p10PacketTimesOut = 0
                p20PacketTimesOut = 0
                p30PacketTimesOut = 0
                p40PacketTimesOut = 0
                p50PacketTimesOut = 0
                p60PacketTimesOut = 0
                p70PacketTimesOut = 0
                p80PacketTimesOut = 0
                p90PacketTimesOut = 0
            else:
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

            ########################################################################
            # Statistical indicators for Outgoing bursts
            if len(out_bursts_packets) == 0:
                out_totalBursts = 0
                out_meanBurst = 0
                out_stdevBurst = 0
                out_varianceBurst = 0
                out_maxBurst = 0
                out_kurtosisBurst = 0
                out_skewBurst = 0
                out_p10Burst = 0
                out_p20Burst = 0
                out_p30Burst = 0
                out_p40Burst = 0
                out_p50Burst = 0
                out_p60Burst = 0
                out_p70Burst = 0
                out_p80Burst = 0
                out_p90Burst = 0
            else:
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

            ########################################################################
            # Statistical indicators for Outgoing bytes (sliced intervals)
            if len(out_burst_sizes) == 0:
                out_meanBurstBytes = 0
                out_stdevBurstBytes = 0
                out_varianceBurstBytes = 0
                out_kurtosisBurstBytes = 0
                out_skewBurstBytes = 0
                out_maxBurstBytes = 0
                out_minBurstBytes = 0
                out_p10BurstBytes = 0
                out_p20BurstBytes = 0
                out_p30BurstBytes = 0
                out_p40BurstBytes = 0
                out_p50BurstBytes = 0
                out_p60BurstBytes = 0
                out_p70BurstBytes = 0
                out_p80BurstBytes = 0
                out_p90BurstBytes = 0
            else:
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

            ########################################################################
            # Statistical indicators for Incoming bursts
            if len(in_bursts_packets) == 0:
                in_totalBursts = 0
                in_meanBurst = 0
                in_stdevBurst = 0
                in_varianceBurst = 0
                in_maxBurst = 0
                in_kurtosisBurst = 0
                in_skewBurst = 0
                in_p10Burst = 0
                in_p20Burst = 0
                in_p30Burst = 0
                in_p40Burst = 0
                in_p50Burst = 0
                in_p60Burst = 0
                in_p70Burst = 0
                in_p80Burst = 0
                in_p90Burst = 0
            else:
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

            ########################################################################
            # Statistical indicators for Incoming burst bytes (sliced intervals)
            if len(in_burst_sizes) == 0:
                in_meanBurstBytes = 0
                in_stdevBurstBytes = 0
                in_varianceBurstBytes = 0
                in_kurtosisBurstBytes = 0
                in_skewBurstBytes = 0
                in_maxBurstBytes = 0
                in_minBurstBytes = 0
                in_p10BurstBytes = 0
                in_p20BurstBytes = 0
                in_p30BurstBytes = 0
                in_p40BurstBytes = 0
                in_p50BurstBytes = 0
                in_p60BurstBytes = 0
                in_p70BurstBytes = 0
                in_p80BurstBytes = 0
                in_p90BurstBytes = 0
            else:
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
            print("Skipping sample")
            continue

        # Write sample features to the csv file
        f_names_stats = []
        f_values_stats = []

        f_names_pl = []
        f_values_pl = []

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

        #print("### f_names_stats: " + str(f_names_stats))
        #print("### f_values_stats: " + str(f_values_stats))

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


        # Write Stats csv
        f_names_stats.append('Class')
        f_values_stats.append(label)

        f_names_stats.append('Capture')
        f_values_stats.append(capture)

        if (not written_header_stats):
            arff_stats.write(', '.join(f_names_stats))
            arff_stats.write('\n')
            written_header_stats = True

        l = []
        for v in f_values_stats:
            l.append(str(v))
        arff_stats.write(', '.join(l))
        arff_stats.write('\n')


        # Write PL csv
        f_names_pl = []
        f_values_pl = []

        for i, b in enumerate(bin_list):
            f_names_pl.append('packetLengthBin_' + str(i))
            f_values_pl.append(b)

        for i, b in enumerate(bin_list2):
            f_names_pl.append('packetLengthBin2_' + str(i))
            f_values_pl.append(b)

        f_names_pl.append('Class')
        f_values_pl.append(label)

        if (not written_header_pl):
            arff_pl.write(', '.join(f_names_pl))
            arff_pl.write('\n')
            written_header_pl = True

        l = []
        for v in f_values_pl:
            l.append(str(v))
        arff_pl.write(', '.join(l))
        arff_pl.write('\n')

    return written_header_stats, written_header_pl


def extract_features_train(captures_folder, featureFolderTrain):

    if not os.path.exists(featureFolderTrain):
        os.makedirs(featureFolderTrain)

    arff_path_stats = featureFolderTrain + 'stats.csv'
    arff_path_pl = featureFolderTrain + 'pl.csv'

    arff_stats = open(arff_path_stats, 'w')
    arff_pl = open(arff_path_pl, 'w')

    written_header_stats = False
    written_header_pl = False

    for innerCaptureFolder in os.listdir(captures_folder):
        if '._' in innerCaptureFolder:
            continue
        if '.DS_Store' in innerCaptureFolder:
            continue

        for innerFolder2 in os.listdir(captures_folder + innerCaptureFolder):
            if '._' in innerFolder2:
                continue
            if '.DS_Store' in innerFolder2:
                continue
            
            captureFolder = captures_folder+innerCaptureFolder+'/'+innerFolder2+'/'
            written_header_stats, written_header_pl = extract_features(captureFolder, arff_stats, arff_pl, written_header_stats, written_header_pl)

    arff_stats.close()
    arff_pl.close()


def extract_features_test(captures_folder, featureFolderTest):

    if not os.path.exists(featureFolderTest):
        os.makedirs(featureFolderTest)

    arff_path_stats = featureFolderTest + 'stats.csv'
    arff_path_pl = featureFolderTest + 'pl.csv'

    arff_stats = open(arff_path_stats, 'w')
    arff_pl = open(arff_path_pl, 'w')

    written_header_stats = False
    written_header_pl = False

    for innerCaptureFolder in os.listdir(captures_folder):
        if '._' in innerCaptureFolder:
            continue
        if '.DS_Store' in innerCaptureFolder:
            continue

        captureFolder = captures_folder+innerCaptureFolder+'/'
        written_header_stats, written_header_pl = extract_features(captureFolder, arff_stats, arff_pl, written_header_stats, written_header_pl)

    arff_stats.close()
    arff_pl.close()