from http.client import CONTINUE
import dpkt
import socket
import numpy as np
import pickle
import os


def generateBuckets(initialTs, lastTs, timeSamplingInterval):
    initialBucket = 0
    lastBucket = int((lastTs - initialTs) * 1000 / timeSamplingInterval)
    
    return np.arange(initialBucket, lastBucket + 1)


def generateBucketsEpochs(initialTs, lastTs, timeSamplingInterval):
    initialBucket = 0
    lastBucket = (((lastTs - initialTs) * 1000) // timeSamplingInterval) + 1
    
    return np.arange(initialBucket, lastBucket + 1)


def generateAllClientsBuckets(testPairs, timeSamplingInterval, earlyStop=None):
    client_buckets = {}
    client_buckets_tses = {}

    counter = 0

    for key in testPairs:
        if key == 'correlated':
            samples = testPairs[key]['samples']

            for i, testPair in enumerate(samples):
                if earlyStop is not None and counter == earlyStop: 
                    break

                clientCapture = testPair['clientFolder'].split("/")[-1]   
                sessionId = clientCapture.split("_request")[0]

                # fp : ('client-brazil-south_os-north-europe_ig2ioz6j2vpcmz27nlqmfdrscijqeqnjv6ku3pkpte7pm53gxeal5hqd_700_9_session_7', 'client-germany-west-central_os-australia-east_f2fv76wtuwdvbpci_400_4_session_9')
                # fp : ('client-brazil-south_os-north-europe_ig2ioz6j2vpcmz27nlqmfdrscijqeqnjv6ku3pkpte7pm53gxeal5hqd_700_9_session_6', 'client-germany-west-central_os-australia-east_f2fv76wtuwdvbpci_400_4_session_8')
                #if not(sessionId == 'client-germany-west-central_os-australia-east_f2fv76wtuwdvbpci_400_4_session_37'):
                #    continue
                
                if sessionId not in client_buckets_tses:
                    client_buckets_tses[sessionId] = {'initialTses': [], 'finalTses': []}
                client_buckets_tses[sessionId]['initialTses'].append(min(testPair['clientFlow']['timesInAbs']))
                client_buckets_tses[sessionId]['finalTses'].append(max(testPair['clientFlow']['timesInAbs']))

                #if i == 10: 
                #    break
                counter += 1

    for sessionId, data in client_buckets_tses.items():
        initialTs = min(data['initialTses'])
        finalTs = max(data['finalTses'])

        client_buckets[sessionId] = {'initialTs': initialTs, 'finalTs': finalTs, 'buckets': generateBuckets(initialTs, finalTs, timeSamplingInterval)}
    
    return client_buckets


def bucketToTimestamp(bucket, timeSamplingInterval, initialTs):
    return initialTs + ((bucket * timeSamplingInterval) / 1000)


def timestampToBucket(timestamp, timeSamplingInterval, initialTs):
    return int(((timestamp - initialTs) * 1000) / timeSamplingInterval)


def getFirstAndLastTs(basePath, fileNames):
    packets = []
    for fileName in fileNames:
        f = open(basePath + fileName, 'rb')

        try:
            pcap = dpkt.pcap.Reader(f)
        except dpkt.dpkt.NeedData:
            print("[*] pcap header is corrupted, skipping sample...")

        #Read one by one
        while True:
            try:
                ts, buf = pcap.__next__()
                packets.append([ts,buf])
            except Exception as e:
                #Break when we find a corrupted packet at the end of the capture
                #print("Stopped in packet %d from %s"%(i, sample))
                break

    first_ts = packets[0][0]
    last_ts = packets[len(packets)-1][0]

    return first_ts, last_ts


def getTsesAndBucketsEpochsSessionsAlexa(alexaFeatures, timeSamplingInterval):
    tses = []
    buckets_clients = {}
    buckets_oses = {}

    for capture, testPairList in alexaFeatures.items():
        for innerTestPairList in testPairList:
            if len(innerTestPairList) > 0:
                for testPair in innerTestPairList:
                    clientCapture = testPair['clientFolder'].split("/")[-1]   
                    sessionId = clientCapture.split("_client")[0]
                    for i in range(0, len(testPair['clientFlow']['sizesIn'])):
                        if sessionId not in buckets_clients:
                            buckets_clients[sessionId] = {'initialTses': [], 'finalTses': []}
                        buckets_clients[sessionId]['initialTses'].append(min(testPair['clientFlow']['timesInAbs']))
                        buckets_clients[sessionId]['finalTses'].append(max(testPair['clientFlow']['timesInAbs']))
                        
                        tses.append(testPair['clientFlow']['timesInAbs'][i])

    for sessionId, data in buckets_clients.items():
        clientInitialTs = min(data['initialTses'])
        clientFinalTs = max(data['finalTses'])
        buckets_clients[sessionId] = {'initialTs': clientInitialTs, 'finalTs': clientFinalTs, 'buckets': generateBucketsEpochs(clientInitialTs, clientFinalTs, timeSamplingInterval)}

    return buckets_clients


def getTsesAndBucketsEpochsSessions(testPairs, timeSamplingInterval):
    tses = []
    buckets_clients = {}
    buckets_oses = {}

    for i, testPair in enumerate(testPairs['correlated']['samples']):
        #if i > 200:
         #   break
        
        clientCapture = testPair['clientFolder'].split("/")[-1]   
        sessionId = clientCapture.split("_client")[0]
        for i in range(0, len(testPair['clientFlow']['sizesIn'])):
            if sessionId not in buckets_clients:
                buckets_clients[sessionId] = {'initialTses': [], 'finalTses': []}
            buckets_clients[sessionId]['initialTses'].append(min(testPair['clientFlow']['timesInAbs']))
            buckets_clients[sessionId]['finalTses'].append(max(testPair['clientFlow']['timesInAbs']))
            
            tses.append(testPair['clientFlow']['timesInAbs'][i])

        onionCapture = testPair['hsFolder'].split("/")[-1]
        onionSessionId = onionCapture.split('_hs')[0]
        for i in range(0, len(testPair['hsFlow']['sizesOut'])):
            if onionSessionId not in buckets_oses:
                buckets_oses[onionSessionId] = {'initialTses': [], 'finalTses': []}
            buckets_oses[onionSessionId]['initialTses'].append(min(testPair['hsFlow']['timesOutAbs']))
            buckets_oses[onionSessionId]['finalTses'].append(max(testPair['hsFlow']['timesOutAbs']))

            tses.append(testPair['hsFlow']['timesOutAbs'][i])


    for sessionId, data in buckets_clients.items():
        clientInitialTs = min(data['initialTses'])
        clientFinalTs = max(data['finalTses'])
        buckets_clients[sessionId] = {'initialTs': clientInitialTs, 'finalTs': clientFinalTs, 'buckets': generateBucketsEpochs(clientInitialTs, clientFinalTs, timeSamplingInterval)}

    for onionSessionId, data in buckets_oses.items():
        osInitialTs = min(data['initialTses'])
        osFinalTs = max(data['finalTses'])
        buckets_oses[onionSessionId] = {'initialTs': osInitialTs, 'finalTs': osFinalTs, 'buckets': generateBucketsEpochs(osInitialTs, osFinalTs, timeSamplingInterval)}

    return min(tses), max(tses), buckets_clients, buckets_oses


def getTsesAndBucketsEpochs(testPairs, timeSamplingInterval):
    tses = []
    buckets_clients = {}
    buckets_oses = {}

    for testPair in testPairs['correlated']['samples']:
        
        clientCapture = testPair['clientFolder'].split("/")[-1]   
        sessionId = clientCapture.split("_request")[0]
        for i in range(0, len(testPair['clientFlow']['sizesIn'])):
            if sessionId not in buckets_clients:
                buckets_clients[sessionId] = {'initialTses': [], 'finalTses': []}
            buckets_clients[sessionId]['initialTses'].append(min(testPair['clientFlow']['timesInAbs']))
            buckets_clients[sessionId]['finalTses'].append(max(testPair['clientFlow']['timesInAbs']))
            
            tses.append(testPair['clientFlow']['timesInAbs'][i])

        onionCapture = testPair['hsFolder'].split("/")[-1]
        onionSessionId = onionCapture.split('_request')[0]
        for i in range(0, len(testPair['hsFlow']['sizesOut'])):
            if onionSessionId not in buckets_oses:
                buckets_oses[onionSessionId] = {'initialTses': [], 'finalTses': []}
            buckets_oses[onionSessionId]['initialTses'].append(min(testPair['hsFlow']['timesOutAbs']))
            buckets_oses[onionSessionId]['finalTses'].append(max(testPair['hsFlow']['timesOutAbs']))

            tses.append(testPair['hsFlow']['timesOutAbs'][i])

    for sessionId, data in buckets_clients.items():
        clientInitialTs = min(data['initialTses'])
        clientFinalTs = max(data['finalTses'])
        buckets_clients[sessionId] = {'initialTs': clientInitialTs, 'finalTs': clientFinalTs, 'buckets': generateBucketsEpochs(clientInitialTs, clientFinalTs, timeSamplingInterval)}

    for onionSessionId, data in buckets_oses.items():
        osInitialTs = min(data['initialTses'])
        osFinalTs = max(data['finalTses'])
        buckets_oses[onionSessionId] = {'initialTs': osInitialTs, 'finalTs': osFinalTs, 'buckets': generateBucketsEpochs(osInitialTs, osFinalTs, timeSamplingInterval)}

    return min(tses), max(tses), buckets_clients, buckets_oses


def getTsesAndBucketsEpochsRequests(testPairs, timeSamplingInterval):
    tses = []
    buckets_clients = {}
    buckets_oses = {}

    for testPair in testPairs['correlated']['samples']:
        
        clientCapture = testPair['clientFolder'].split("/")[-1]   
        requestId = clientCapture.split("_client")[0]
        for i in range(0, len(testPair['clientFlow']['sizesIn'])):
            if requestId not in buckets_clients:
                buckets_clients[requestId] = {'initialTses': [], 'finalTses': []}
            buckets_clients[requestId]['initialTses'].append(min(testPair['clientFlow']['timesInAbs']))
            buckets_clients[requestId]['finalTses'].append(max(testPair['clientFlow']['timesInAbs']))
            
            tses.append(testPair['clientFlow']['timesInAbs'][i])

        onionCapture = testPair['hsFolder'].split("/")[-1]
        onionRequestId = onionCapture.split('_hs')[0]
        for i in range(0, len(testPair['hsFlow']['sizesOut'])):
            if onionRequestId not in buckets_oses:
                buckets_oses[onionRequestId] = {'initialTses': [], 'finalTses': []}
            buckets_oses[onionRequestId]['initialTses'].append(min(testPair['hsFlow']['timesOutAbs']))
            buckets_oses[onionRequestId]['finalTses'].append(max(testPair['hsFlow']['timesOutAbs']))

            tses.append(testPair['hsFlow']['timesOutAbs'][i])

    for requestId, data in buckets_clients.items():
        clientInitialTs = min(data['initialTses'])
        clientFinalTs = max(data['finalTses'])
        buckets_clients[requestId] = {'initialTs': clientInitialTs, 'finalTs': clientFinalTs, 'buckets': generateBucketsEpochs(clientInitialTs, clientFinalTs, timeSamplingInterval)}

    for onionRequestId, data in buckets_oses.items():
        osInitialTs = min(data['initialTses'])
        osFinalTs = max(data['finalTses'])
        buckets_oses[onionRequestId] = {'initialTs': osInitialTs, 'finalTs': osFinalTs, 'buckets': generateBucketsEpochs(osInitialTs, osFinalTs, timeSamplingInterval)}

    return min(tses), max(tses), buckets_clients, buckets_oses


# It's not currently working properly, it takes too many resources to make all combinations this way, program gets killed
def process_features_epochs_sessions_all_combinations(testPairs, timeSamplingInterval, epoch_size, epoch_tolerance, earlyStop=None):
    possible_request_combinations = {}
    client_rtts = {}
    os_rtts = {}

    counter = 0

    # absolute initial and final tses of the whole experience
    initial_ts_experience, last_ts_experience, buckets_clients, buckets_oses = getTsesAndBucketsEpochsSessions(testPairs, timeSamplingInterval)

    print("=== Finished organizing buckets")
    for testPair in testPairs['correlated']['samples']:
        if earlyStop is not None and counter == earlyStop: 
            break

        clientCapture = testPair['clientFolder'].split("/")[-1]   
        sessionId = clientCapture.split("_client")[0]

        yPacketBytesInDict =  {}
        yPacketCountInDict = {}
        for bucket in buckets_clients[sessionId]['buckets']:
            yPacketBytesInDict[bucket] = 0
        for bucket in buckets_clients[sessionId]['buckets']:
            yPacketCountInDict[bucket] = 0

        for i in range(0, len(testPair['clientFlow']['sizesIn'])):
            initial_ts = buckets_clients[sessionId]['initialTs']
            ts = testPair['clientFlow']['timesInAbs'][i] # time in milliseconds

            relativeTs = ts-initial_ts
            bucket = relativeTs * 1000 // timeSamplingInterval
            
            yPacketCountInDict[bucket] += 1
            yPacketBytesInDict[bucket] += testPair['clientFlow']['sizesIn'][i]

        yPacketBytesIn = list(yPacketBytesInDict.values())
        yPacketCountIn = list(yPacketCountInDict.values())

        allAbsTimes = testPair['clientFlow']['timesOutAbs'] + testPair['clientFlow']['timesInAbs']
        absoluteInitialTime = min(allAbsTimes)
        maxAbsoluteTime = max(allAbsTimes)

        client_rtts[sessionId] = {'rtts': [absoluteInitialTime, maxAbsoluteTime], 'yPacketBytesIn': yPacketBytesIn, 'yPacketCountIn': yPacketCountIn, 'yPacketTimesIn': testPair['clientFlow']['timesInAbs']}

        # onion part
        yPacketBytesOutOnion = []
        yPacketTimesOutOnion = []
        for i in range(0, len(testPair['hsFlow']['sizesOut'])):
            yPacketBytesOutOnion.append(testPair['hsFlow']['sizesOut'][i])
            yPacketTimesOutOnion.append(testPair['hsFlow']['timesOutAbs'][i])

        allAbsTimesOnion = testPair['hsFlow']['timesOutAbs'] + testPair['hsFlow']['timesInAbs']
        absoluteInitialTimeOnion = min(allAbsTimesOnion)
        maxAbsoluteTimeOnion = max(allAbsTimesOnion)
        
        os_rtts[sessionId] = {'rtts': [absoluteInitialTimeOnion, maxAbsoluteTimeOnion], 'yPacketBytesOutOnion': yPacketBytesOutOnion, 'yPacketTimesOutOnion': yPacketTimesOutOnion}
        
        counter += 1

    print("=== Finished gathering data on correlated pairs")
    counter = 0
    # Now we have a list of all possible client-side sessions and os-side sessions
    # and their respetive start and end times. So, now we group all possible
    # combinations per epoch
    for clientSessionId in client_rtts.keys():
        #if earlyStop is not None and counter == earlyStop: 
         #       break
        if counter % 10 == 0:
            print("--- Counter", counter)
            print("--- clientSessionId", clientSessionId)
        # Check which OSes are within the same epochs
        for osSessionId in os_rtts.keys():

            key = (clientSessionId, osSessionId)
            label = 0
            if clientSessionId == osSessionId:
                label = 1
            #else:
                # remove duplicated captures from same OS
                #osName = osSessionId.split("_")[1]
                #if osName in clientSessionId:
                #    continue
            
            initial_session_ts = min(buckets_clients[clientSessionId]['initialTs'], buckets_oses[osSessionId]['initialTs'])
            final_session_ts = max(buckets_clients[clientSessionId]['finalTs'], buckets_oses[osSessionId]['finalTs'])
            buckets_session = generateBucketsEpochs(initial_session_ts, final_session_ts, timeSamplingInterval)

            yPacketBytesOutOnionDict =  {}
            yPacketCountOutOnionDict = {}
            yPacketBytesInDict =  {}
            yPacketCountInDict = {}
            for bucket in buckets_session:
                yPacketBytesOutOnionDict[bucket] = 0
                yPacketCountOutOnionDict[bucket] = 0
                yPacketBytesInDict[bucket] = 0
                yPacketCountInDict[bucket] = 0
                

            # onion
            for i in range(0, len(os_rtts[osSessionId]['yPacketTimesOutOnion'])):
                ts = os_rtts[osSessionId]['yPacketTimesOutOnion'][i] # time in milliseconds

                relativeTs = ts - initial_session_ts
                bucket = relativeTs * 1000 // timeSamplingInterval
                    
                yPacketCountOutOnionDict[bucket] += 1
                yPacketBytesOutOnionDict[bucket] += os_rtts[osSessionId]['yPacketBytesOutOnion'][i]
 
            # client
            for i in range(0, len(client_rtts[clientSessionId]['yPacketTimesIn'])):
                ts = client_rtts[clientSessionId]['yPacketTimesIn'][i] # time in milliseconds

                relativeTs = ts - initial_session_ts
                bucket = relativeTs * 1000 // timeSamplingInterval
                    
                yPacketCountInDict[bucket] += 1
                # TODO: fix this, these should be the orginal bytes received in the features, not the bucketed ones
                #yPacketBytesInDict[bucket] += client_rtts[clientSessionId]['yPacketBytesIn'][i]

            # Here we place only the bucket range from the OS that makes sense to compare with the client
            possible_request_combinations[key] = {'yPacketBytesOutOnion': list(yPacketBytesOutOnionDict.values()), 'yPacketCountOutOnion': list(yPacketCountOutOnionDict.values()), \
                                                    'yPacketBytesIn': list(yPacketBytesInDict.values()), 'yPacketCountIn': list(yPacketCountInDict.values()), 'label': label}
                

        counter += 1

    return possible_request_combinations, client_rtts, os_rtts


def process_features_epochs_sessions_full_pipeline(testPairs, timeSamplingInterval, epoch_size, epoch_tolerance, earlyStop=None):
    possible_request_combinations = {}
    client_rtts = {}
    os_rtts = {}

    counter = 0

    missed_client_flows_full_pipeline = 0
    missed_os_flows_full_pipeline = 0

    #alexa_features = pickle.load(open('/Volumes/TOSHIBA_EXT/datasets_new/cnns_datasets_new/allTraining/alexa_allTraining_simulate_users_incomplete_v1_truncated_fixed_sessions_full_pipeline'), 'rb')
    #client_flows_full_pipeline = pickle.load(open('../../client_classifier/outputClientFeatures_XGBoost'), 'rb')
    alexa_features = pickle.load(open('alexa_allTraining_simulate_users_incomplete_v1_truncated_fixed_sessions_full_pipeline', 'rb'))
    #client_flows_full_pipeline = pickle.load(open('outputClientFeatures_XGBoost', 'rb'))
    #client_flows_full_pipeline = pickle.load(open('outputClientFeatures_XGBoost_thr_0.9', 'rb'))
    #client_flows_full_pipeline = pickle.load(open('outputClientFeatures_january_thr_0.9999', 'rb'))
    client_flows_full_pipeline = pickle.load(open('outputClientFeatures_january_thr_0.9995', 'rb'))
    #client_flows_full_pipeline = pickle.load(open('outputClientFeatures_XGBoost_thr_0.99243695', 'rb'))
    os_flows_full_pipeline = pickle.load(open('outputOSFeatures_os_classifier_xgboost', 'rb'))

    # absolute initial and final tses of the whole experience
    initial_ts_experience, last_ts_experience, buckets_clients, buckets_oses = getTsesAndBucketsEpochsSessions(testPairs, timeSamplingInterval)
    # TODO extract buckets for alexa captures
    buckets_alexa = getTsesAndBucketsEpochsSessionsAlexa(alexa_features, timeSamplingInterval)

    print("=== Finished organizing buckets")
    for testPair in testPairs['correlated']['samples']:
        if earlyStop is not None and counter == earlyStop: 
            break

        clientCapture = testPair['clientFolder'].split("/")[-1]   
        sessionId = clientCapture.split("_client")[0]
        #print("****** sessionId", sessionId)

        key = " " + sessionId + "_client.pcap"
        if key not in client_flows_full_pipeline.keys():
            print("MISSED CLIENT:", key)
            # This flow was not considered as a flow to an OS by our filtering phase
            missed_client_flows_full_pipeline += 1
            continue

        key = " " + sessionId + "_hs.pcap"
        if key not in os_flows_full_pipeline.keys():
            print("MISSED OS:", key)
            # This flow was not considered as a flow to an OS by our filtering phase
            missed_os_flows_full_pipeline += 1
            continue

        yPacketBytesInDict =  {}
        yPacketCountInDict = {}
        for bucket in buckets_clients[sessionId]['buckets']:
            yPacketBytesInDict[bucket] = 0
        for bucket in buckets_clients[sessionId]['buckets']:
            yPacketCountInDict[bucket] = 0

        for i in range(0, len(testPair['clientFlow']['sizesIn'])):
            initial_ts = buckets_clients[sessionId]['initialTs']
            ts = testPair['clientFlow']['timesInAbs'][i] # time in milliseconds

            relativeTs = ts-initial_ts
            bucket = relativeTs * 1000 // timeSamplingInterval
            
            yPacketCountInDict[bucket] += 1
            yPacketBytesInDict[bucket] += testPair['clientFlow']['sizesIn'][i]

        yPacketBytesIn = list(yPacketBytesInDict.values())
        yPacketCountIn = list(yPacketCountInDict.values())

        allAbsTimes = testPair['clientFlow']['timesOutAbs'] + testPair['clientFlow']['timesInAbs']
        absoluteInitialTime = min(allAbsTimes)
        maxAbsoluteTime = max(allAbsTimes)

        client_rtts[sessionId] = {'rtts': [absoluteInitialTime, maxAbsoluteTime], 'yPacketBytesIn': yPacketBytesIn, 'yPacketCountIn': yPacketCountIn, 'yPacketTimesIn': testPair['clientFlow']['timesInAbs']}

        # onion part
        yPacketBytesOutOnion = []
        yPacketTimesOutOnion = []
        for i in range(0, len(testPair['hsFlow']['sizesOut'])):
            yPacketBytesOutOnion.append(testPair['hsFlow']['sizesOut'][i])
            yPacketTimesOutOnion.append(testPair['hsFlow']['timesOutAbs'][i])

        allAbsTimesOnion = testPair['hsFlow']['timesOutAbs'] + testPair['hsFlow']['timesInAbs']
        absoluteInitialTimeOnion = min(allAbsTimesOnion)
        maxAbsoluteTimeOnion = max(allAbsTimesOnion)
        
        os_rtts[sessionId] = {'rtts': [absoluteInitialTimeOnion, maxAbsoluteTimeOnion], 'yPacketBytesOutOnion': yPacketBytesOutOnion, 'yPacketTimesOutOnion': yPacketTimesOutOnion}
        
        counter += 1

    print("=== Finished gathering data on correlated pairs")

    alexa_counter = 0
    for alexaFlow in client_flows_full_pipeline.keys():
        # Gather the flows that were passed from the pipeline
        if 'alexa' in alexaFlow:
            print("Alexa", alexaFlow)
            alexa_counter += 1
    # Passing all client flows to our classifier
    #for alexaFlow in alexa_features.keys():
            key = alexaFlow.split(".pcap")[0]
            key = key.strip()
            for innerFolder in alexa_features[key]:
                if len(innerFolder) > 0:
                    for alexa_feature in innerFolder:
                        clientCapture = alexa_feature['clientFolder'].split("/")[-1]   
                        sessionId = clientCapture.split("_client")[0]
                        
                        yPacketBytesInDict =  {}
                        yPacketCountInDict = {}
                        for bucket in buckets_alexa[sessionId]['buckets']:
                            yPacketBytesInDict[bucket] = 0
                        for bucket in buckets_alexa[sessionId]['buckets']:
                            yPacketCountInDict[bucket] = 0

                        for i in range(0, len(alexa_feature['clientFlow']['sizesIn'])):
                            initial_ts = buckets_alexa[sessionId]['initialTs']
                            ts = alexa_feature['clientFlow']['timesInAbs'][i] # time in milliseconds

                            relativeTs = ts-initial_ts
                            bucket = relativeTs * 1000 // timeSamplingInterval
                            
                            yPacketCountInDict[bucket] += 1
                            yPacketBytesInDict[bucket] += alexa_feature['clientFlow']['sizesIn'][i]

                        yPacketBytesIn = list(yPacketBytesInDict.values())
                        yPacketCountIn = list(yPacketCountInDict.values())

                        allAbsTimes = alexa_feature['clientFlow']['timesOutAbs'] + alexa_feature['clientFlow']['timesInAbs']
                        absoluteInitialTime = min(allAbsTimes)
                        maxAbsoluteTime = max(allAbsTimes)

                        client_rtts[sessionId] = {'rtts': [absoluteInitialTime, maxAbsoluteTime], 'yPacketBytesIn': yPacketBytesIn, 'yPacketCountIn': yPacketCountIn, 'yPacketTimesIn': alexa_feature['clientFlow']['timesInAbs']}
                        if 'alexa' in alexaFlow:
                            buckets_clients[sessionId] = buckets_alexa[sessionId]
    print("alexa_counter", alexa_counter)
    print("=== Finished gathering data on alexa captures that were misclassified in the filtering phase")

    counter = 0
    # Now we have a list of all possible client-side sessions and os-side sessions
    # and their respetive start and end times. So, now we group all possible
    # combinations per epoch
    for clientSessionId in client_rtts.keys():
        #if earlyStop is not None and counter == earlyStop: 
         #       break

        initial_epoch = buckets_clients[clientSessionId]['initialTs'] // epoch_size
        last_epoch = (buckets_clients[clientSessionId]['finalTs'] // epoch_size) + 1

        # Check which OSes are within the same epochs
        for osSessionId in os_rtts.keys():

            os_initial_epoch = buckets_oses[osSessionId]['initialTs'] // epoch_size
            os_last_epoch = (buckets_oses[osSessionId]['finalTs'] // epoch_size) + 1
            
            #(StartDate1 <= EndDate2) and (StartDate2 <= EndDate1)
            # Both flows overlap in epoch times, so we consider them a possible combination
            #if (os_initial_epoch <= last_epoch) and (initial_epoch <= os_last_epoch):
            if ((os_initial_epoch >= initial_epoch - epoch_tolerance) and (os_initial_epoch <= initial_epoch + epoch_tolerance)) and ((os_last_epoch >= last_epoch - epoch_tolerance) and (os_last_epoch <= last_epoch + epoch_tolerance)):
                key = (clientSessionId, osSessionId)
                label = 0
                if clientSessionId == osSessionId:
                    label = 1
                else:
                    # remove duplicated captures from same OS
                    osName = osSessionId.split("_")[1]
                    if osName in clientSessionId:
                        continue
                #print("PAIRS {}: {} - {}".format(len(possible_request_combinations), clientSessionId, osSessionId))
                
                initial_session_ts = min(buckets_clients[clientSessionId]['initialTs'], buckets_oses[osSessionId]['initialTs'])
                final_session_ts = max(buckets_clients[clientSessionId]['finalTs'], buckets_oses[osSessionId]['finalTs'])
                buckets_session = generateBucketsEpochs(initial_session_ts, final_session_ts, timeSamplingInterval)

                yPacketBytesOutOnionDict =  {}
                yPacketCountOutOnionDict = {}
                yPacketBytesInDict =  {}
                yPacketCountInDict = {}
                for bucket in buckets_session:
                    yPacketBytesOutOnionDict[bucket] = 0
                    yPacketCountOutOnionDict[bucket] = 0
                    yPacketBytesInDict[bucket] = 0
                    yPacketCountInDict[bucket] = 0
                

                # onion
                for i in range(0, len(os_rtts[osSessionId]['yPacketTimesOutOnion'])):
                    ts = os_rtts[osSessionId]['yPacketTimesOutOnion'][i] # time in milliseconds

                    relativeTs = ts - initial_session_ts
                    bucket = relativeTs * 1000 // timeSamplingInterval
                        
                    yPacketCountOutOnionDict[bucket] += 1
                    yPacketBytesOutOnionDict[bucket] += os_rtts[osSessionId]['yPacketBytesOutOnion'][i]
                
                # client
                for i in range(0, len(client_rtts[clientSessionId]['yPacketTimesIn'])):
                    ts = client_rtts[clientSessionId]['yPacketTimesIn'][i] # time in milliseconds

                    relativeTs = ts - initial_session_ts
                    bucket = relativeTs * 1000 // timeSamplingInterval
                        
                    yPacketCountInDict[bucket] += 1
                    # TODO: fix this, these should be the orginal bytes received in the features, not the bucketed ones
                    #yPacketBytesInDict[bucket] += client_rtts[clientSessionId]['yPacketBytesIn'][i]

                # Here we place only the bucket range from the OS that makes sense to compare with the client
                possible_request_combinations[key] = {'yPacketBytesOutOnion': list(yPacketBytesOutOnionDict.values()), 'yPacketCountOutOnion': list(yPacketCountOutOnionDict.values()), \
                                                        'yPacketBytesIn': list(yPacketBytesInDict.values()), 'yPacketCountIn': list(yPacketCountInDict.values()), 'label': label}
                
            else:
                if clientSessionId == osSessionId:
                    print("\n--- Removed correlated flow for being in different epochs:\nclientSessionId", clientSessionId)
                    print("osSessionId", osSessionId)
                    print("buckets_clients[clientSessionId]['initialTs']", buckets_clients[clientSessionId]['initialTs'])
                    print("buckets_clients[clientSessionId]['finalTs']", buckets_clients[clientSessionId]['finalTs'])
                    print("initial_epoch", initial_epoch)
                    print("last_epoch", last_epoch)
                    print("buckets_os[osSessionId]['initialTs']", buckets_oses[osSessionId]['initialTs'])
                    print("buckets_os[osSessionId]['finalTs']", buckets_oses[osSessionId]['finalTs'])
                    print("os_initial_epoch", os_initial_epoch)
                    print("os_last_epoch", os_last_epoch)

        counter += 1

    return possible_request_combinations, client_rtts, os_rtts, missed_client_flows_full_pipeline - 1, missed_os_flows_full_pipeline - 1


def process_features_epochs_sessions(testPairs, timeSamplingInterval, epoch_size, epoch_tolerance, earlyStop=None):
    possible_request_combinations = {}
    client_rtts = {}
    os_rtts = {}

    counter = 0

    # absolute initial and final tses of the whole experience
    initial_ts_experience, last_ts_experience, buckets_clients, buckets_oses = getTsesAndBucketsEpochsSessions(testPairs, timeSamplingInterval)

    print("=== Finished organizing buckets")
    for test_idx, testPair in enumerate(testPairs['correlated']['samples']):
        if earlyStop is not None and counter == earlyStop: 
            break

        #if test_idx > 200:
        #    break

        clientCapture = testPair['clientFolder'].split("/")[-1]   
        sessionId = clientCapture.split("_client")[0]

        yPacketBytesInDict =  {}
        yPacketCountInDict = {}
        for bucket in buckets_clients[sessionId]['buckets']:
            yPacketBytesInDict[bucket] = 0
        for bucket in buckets_clients[sessionId]['buckets']:
            yPacketCountInDict[bucket] = 0

        for i in range(0, len(testPair['clientFlow']['sizesIn'])):
            initial_ts = buckets_clients[sessionId]['initialTs']
            ts = testPair['clientFlow']['timesInAbs'][i] # time in milliseconds

            relativeTs = ts-initial_ts
            bucket = relativeTs * 1000 // timeSamplingInterval
            
            yPacketCountInDict[bucket] += 1
            yPacketBytesInDict[bucket] += testPair['clientFlow']['sizesIn'][i]

        yPacketBytesIn = list(yPacketBytesInDict.values())
        yPacketCountIn = list(yPacketCountInDict.values())

        allAbsTimes = testPair['clientFlow']['timesOutAbs'] + testPair['clientFlow']['timesInAbs']
        absoluteInitialTime = min(allAbsTimes)
        maxAbsoluteTime = max(allAbsTimes)

        client_rtts[sessionId] = {'rtts': [absoluteInitialTime, maxAbsoluteTime], 'yPacketBytesIn': yPacketBytesIn, 'yPacketCountIn': yPacketCountIn, 'yPacketTimesIn': testPair['clientFlow']['timesInAbs']}

        # onion part
        yPacketBytesOutOnion = []
        yPacketTimesOutOnion = []
        for i in range(0, len(testPair['hsFlow']['sizesOut'])):
            yPacketBytesOutOnion.append(testPair['hsFlow']['sizesOut'][i])
            yPacketTimesOutOnion.append(testPair['hsFlow']['timesOutAbs'][i])

        allAbsTimesOnion = testPair['hsFlow']['timesOutAbs'] + testPair['hsFlow']['timesInAbs']
        absoluteInitialTimeOnion = min(allAbsTimesOnion)
        maxAbsoluteTimeOnion = max(allAbsTimesOnion)
        
        os_rtts[sessionId] = {'rtts': [absoluteInitialTimeOnion, maxAbsoluteTimeOnion], 'yPacketBytesOutOnion': yPacketBytesOutOnion, 'yPacketTimesOutOnion': yPacketTimesOutOnion}
        
        counter += 1

    print("=== Finished gathering data on correlated pairs {}".format(counter))

    counter = 0
    # Now we have a list of all possible client-side sessions and os-side sessions
    # and their respetive start and end times. So, now we group all possible
    # combinations per epoch
    for clientSessionId in client_rtts.keys():
        #if earlyStop is not None and counter == earlyStop: 
         #       break

        initial_epoch = buckets_clients[clientSessionId]['initialTs'] // epoch_size
        last_epoch = (buckets_clients[clientSessionId]['finalTs'] // epoch_size) + 1

        # Check which OSes are within the same epochs
        for osSessionId in os_rtts.keys():

            os_initial_epoch = buckets_oses[osSessionId]['initialTs'] // epoch_size
            os_last_epoch = (buckets_oses[osSessionId]['finalTs'] // epoch_size) + 1
            
            #(StartDate1 <= EndDate2) and (StartDate2 <= EndDate1)
            # Both flows overlap in epoch times, so we consider them a possible combination
            #if (os_initial_epoch <= last_epoch) and (initial_epoch <= os_last_epoch):
            if ((os_initial_epoch >= initial_epoch - epoch_tolerance) and (os_initial_epoch <= initial_epoch + epoch_tolerance)): #and ((os_last_epoch >= last_epoch - epoch_tolerance) and (os_last_epoch <= last_epoch + epoch_tolerance)):
                key = (clientSessionId, osSessionId)
                label = 0
                if clientSessionId == osSessionId:
                    label = 1
                else:
                    # remove duplicated captures from same OS
                    osName = osSessionId.split("_")[1]
                    if osName in clientSessionId:
                        continue
                    
                """
                yPacketBytesOutOnionDict =  {}
                yPacketCountOutOnionDict = {}
                for bucket in buckets_clients[clientSessionId]['buckets']:
                    yPacketBytesOutOnionDict[bucket] = 0
                for bucket in buckets_clients[clientSessionId]['buckets']:
                    yPacketCountOutOnionDict[bucket] = 0
                """
                
                initial_session_ts = min(buckets_clients[clientSessionId]['initialTs'], buckets_oses[osSessionId]['initialTs'])
                final_session_ts = max(buckets_clients[clientSessionId]['finalTs'], buckets_oses[osSessionId]['finalTs'])
                buckets_session = generateBucketsEpochs(initial_session_ts, final_session_ts, timeSamplingInterval)

                yPacketBytesOutOnionDict =  {}
                yPacketCountOutOnionDict = {}
                yPacketBytesInDict =  {}
                yPacketCountInDict = {}
                for bucket in buckets_session:
                    yPacketBytesOutOnionDict[bucket] = 0
                    yPacketCountOutOnionDict[bucket] = 0
                    yPacketBytesInDict[bucket] = 0
                    yPacketCountInDict[bucket] = 0
                

                """
                for i in range(0, len(os_rtts[osSessionId]['yPacketTimesOutOnion'])):
                    initial_ts = buckets_oses[osSessionId]['initialTs']
                    client_initial_ts = buckets_clients[clientSessionId]['initialTs']
                    client_final_ts = buckets_clients[clientSessionId]['finalTs']
                    ts = os_rtts[osSessionId]['yPacketTimesOutOnion'][i] # time in milliseconds

                    if ts >= client_initial_ts and ts <= client_final_ts:
                        #relativeTs = ts-initial_ts
                        relativeTs = ts - client_initial_ts
                        bucket = relativeTs * 1000 // timeSamplingInterval
                        yPacketCountOutOnionDict[bucket] += 1
                        yPacketBytesOutOnionDict[bucket] += os_rtts[osSessionId]['yPacketBytesOutOnion'][i]

                possible_request_combinations[key] = {'yPacketBytesOutOnion': list(yPacketBytesOutOnionDict.values()), 'yPacketCountOutOnion': list(yPacketCountOutOnionDict.values()), \
                                                        'yPacketBytesIn': client_rtts[clientSessionId]['yPacketBytesIn'], 'yPacketCountIn': client_rtts[clientSessionId]['yPacketCountIn'], 'label': label}
                """
                # onion
                for i in range(0, len(os_rtts[osSessionId]['yPacketTimesOutOnion'])):
                    ts = os_rtts[osSessionId]['yPacketTimesOutOnion'][i] # time in milliseconds

                    relativeTs = ts - initial_session_ts
                    bucket = relativeTs * 1000 // timeSamplingInterval
                        
                    yPacketCountOutOnionDict[bucket] += 1
                    yPacketBytesOutOnionDict[bucket] += os_rtts[osSessionId]['yPacketBytesOutOnion'][i]
                
                # client
                for i in range(0, len(client_rtts[clientSessionId]['yPacketTimesIn'])):
                    ts = client_rtts[clientSessionId]['yPacketTimesIn'][i] # time in milliseconds

                    relativeTs = ts - initial_session_ts
                    bucket = relativeTs * 1000 // timeSamplingInterval
                        
                    yPacketCountInDict[bucket] += 1
                    # TODO: fix this, these should be the orginal bytes received in the features, not the bucketed ones
                    #yPacketBytesInDict[bucket] += client_rtts[clientSessionId]['yPacketBytesIn'][i]

                # Here we place only the bucket range from the OS that makes sense to compare with the client
                possible_request_combinations[key] = {'yPacketBytesOutOnion': list(yPacketBytesOutOnionDict.values()), 'yPacketCountOutOnion': list(yPacketCountOutOnionDict.values()), \
                                                        'yPacketBytesIn': list(yPacketBytesInDict.values()), 'yPacketCountIn': list(yPacketCountInDict.values()), 'label': label}
                
            else:
                #print("---- removed flow {} : {}".format(clientSessionId, osSessionId))

                if clientSessionId == osSessionId:
                    print("\n--- Removed correlated flow for being in different epochs:\nclientSessionId", clientSessionId)
                    print("osSessionId", osSessionId)
                    print("buckets_clients[clientSessionId]['initialTs']", buckets_clients[clientSessionId]['initialTs'])
                    print("buckets_clients[clientSessionId]['finalTs']", buckets_clients[clientSessionId]['finalTs'])
                    print("initial_epoch", initial_epoch)
                    print("last_epoch", last_epoch)
                    print("buckets_os[osSessionId]['initialTs']", buckets_oses[osSessionId]['initialTs'])
                    print("buckets_os[osSessionId]['finalTs']", buckets_oses[osSessionId]['finalTs'])
                    print("os_initial_epoch", os_initial_epoch)
                    print("os_last_epoch", os_last_epoch)

        counter += 1

    return possible_request_combinations, client_rtts, os_rtts


# Groups requests features into full sessions, to be used with older datasets
def process_features_epochs_requests(testPairs, timeSamplingInterval, epoch_size, epoch_tolerance, earlyStop=None):
    possible_request_combinations = {}
    client_rtts = {}
    os_rtts = {}

    counter = 0

    # absolute initial and final tses of the whole experience
    initial_ts_experience, last_ts_experience, buckets_clients, buckets_oses = getTsesAndBucketsEpochs(testPairs, timeSamplingInterval)

    print("=== Finished organizing buckets")
    for testPair in testPairs['correlated']['samples']:
        if earlyStop is not None and counter == earlyStop: 
            break

        clientCapture = testPair['clientFolder'].split("/")[-1]   
        sessionId = clientCapture.split("_request")[0]
        onionCapture = testPair['hsFolder'].split("/")[-1]

        yPacketBytesInDict =  {}
        yPacketCountInDict = {}
        for bucket in buckets_clients[sessionId]['buckets']:
            yPacketBytesInDict[bucket] = 0
        for bucket in buckets_clients[sessionId]['buckets']:
            yPacketCountInDict[bucket] = 0

        for i in range(0, len(testPair['clientFlow']['sizesIn'])):
            initial_ts = buckets_clients[sessionId]['initialTs']
            ts = testPair['clientFlow']['timesInAbs'][i] # time in milliseconds

            relativeTs = ts-initial_ts
            bucket = relativeTs * 1000 // timeSamplingInterval
            
            yPacketCountInDict[bucket] += 1
            yPacketBytesInDict[bucket] += testPair['clientFlow']['sizesIn'][i]

        yPacketBytesIn = list(yPacketBytesInDict.values())
        yPacketCountIn = list(yPacketCountInDict.values())

        allAbsTimes = testPair['clientFlow']['timesOutAbs'] + testPair['clientFlow']['timesInAbs']
        absoluteInitialTime = min(allAbsTimes)
        maxAbsoluteTime = max(allAbsTimes)

        if sessionId not in client_rtts:
            client_rtts[sessionId] = {'rtts': [absoluteInitialTime, maxAbsoluteTime], 'yPacketBytesIn': yPacketBytesIn, 'yPacketCountIn': yPacketCountIn, 'requestIds': [clientCapture], 'yPacketTimesIn': testPair['clientFlow']['timesInAbs']}
        else:
            if clientCapture not in client_rtts[sessionId]['requestIds']:
                client_rtts[sessionId]['rtts'] += [absoluteInitialTime, maxAbsoluteTime]
                client_rtts[sessionId]['yPacketBytesIn'] = np.add(client_rtts[sessionId]['yPacketBytesIn'], yPacketBytesIn)
                client_rtts[sessionId]['yPacketCountIn'] = np.add(client_rtts[sessionId]['yPacketCountIn'], yPacketCountIn)
                client_rtts[sessionId]['requestIds'] += [clientCapture]
                client_rtts[sessionId]['yPacketTimesIn'] += testPair['clientFlow']['timesInAbs']

        # onion part
        yPacketBytesOutOnion = []
        yPacketTimesOutOnion = []
        for i in range(0, len(testPair['hsFlow']['sizesOut'])):
            yPacketBytesOutOnion.append(testPair['hsFlow']['sizesOut'][i])
            yPacketTimesOutOnion.append(testPair['hsFlow']['timesOutAbs'][i])

        allAbsTimesOnion = testPair['hsFlow']['timesOutAbs'] + testPair['hsFlow']['timesInAbs']
        absoluteInitialTimeOnion = min(allAbsTimesOnion)
        maxAbsoluteTimeOnion = max(allAbsTimesOnion)
        
        if sessionId not in os_rtts:
            os_rtts[sessionId] = {'rtts': [absoluteInitialTimeOnion, maxAbsoluteTimeOnion], 'yPacketBytesOutOnion': yPacketBytesOutOnion, 'yPacketTimesOutOnion': yPacketTimesOutOnion, 'requestIds': [onionCapture]}
        else:
            if onionCapture not in os_rtts[sessionId]['requestIds']:
                os_rtts[sessionId]['rtts'] += [absoluteInitialTimeOnion, maxAbsoluteTimeOnion]
                os_rtts[sessionId]['yPacketBytesOutOnion'] += yPacketBytesOutOnion
                os_rtts[sessionId]['yPacketTimesOutOnion'] += yPacketTimesOutOnion
                os_rtts[sessionId]['requestIds'] += [onionCapture]

        counter += 1

    print("=== Finished gathering data on correlated pairs")
    counter = 0
    # Now we have a list of all possible client-side sessions and os-side sessions
    # and their respetive start and end times. So, now we group all possible
    # combinations per epoch
    for clientSessionId in client_rtts.keys():
        #if earlyStop is not None and counter == earlyStop: 
         #       break

        initial_epoch = buckets_clients[clientSessionId]['initialTs'] // epoch_size
        last_epoch = (buckets_clients[clientSessionId]['finalTs'] // epoch_size) + 1

        # Check which OSes are within the same epochs
        for osSessionId in os_rtts.keys():

            os_initial_epoch = buckets_oses[osSessionId]['initialTs'] // epoch_size
            os_last_epoch = (buckets_oses[osSessionId]['finalTs'] // epoch_size) + 1
            
            #(StartDate1 <= EndDate2) and (StartDate2 <= EndDate1)
            # Both flows overlap in epoch times, so we consider them a possible combination
            #if (os_initial_epoch <= last_epoch) and (initial_epoch <= os_last_epoch):
            if ((os_initial_epoch >= initial_epoch - epoch_tolerance) and (os_initial_epoch <= initial_epoch + epoch_tolerance)) and ((os_last_epoch >= last_epoch - epoch_tolerance) and (os_last_epoch <= last_epoch + epoch_tolerance)):
                key = (clientSessionId, osSessionId)
                label = 0
                if clientSessionId == osSessionId:
                    label = 1
                else:
                    # remove duplicated captures from same OS
                    osName = osSessionId.split("_")[1]
                    if osName in clientSessionId:
                        continue
                    
                
                initial_session_ts = min(buckets_clients[clientSessionId]['initialTs'], buckets_oses[osSessionId]['initialTs'])
                final_session_ts = max(buckets_clients[clientSessionId]['finalTs'], buckets_oses[osSessionId]['finalTs'])
                buckets_session = generateBucketsEpochs(initial_session_ts, final_session_ts, timeSamplingInterval)

                yPacketBytesOutOnionDict =  {}
                yPacketCountOutOnionDict = {}
                yPacketBytesInDict =  {}
                yPacketCountInDict = {}
                for bucket in buckets_session:
                    yPacketBytesOutOnionDict[bucket] = 0
                    yPacketCountOutOnionDict[bucket] = 0
                    yPacketBytesInDict[bucket] = 0
                    yPacketCountInDict[bucket] = 0
                

                # onion
                for i in range(0, len(os_rtts[osSessionId]['yPacketTimesOutOnion'])):
                    ts = os_rtts[osSessionId]['yPacketTimesOutOnion'][i] # time in milliseconds

                    relativeTs = ts - initial_session_ts
                    bucket = relativeTs * 1000 // timeSamplingInterval
                        
                    yPacketCountOutOnionDict[bucket] += 1
                    yPacketBytesOutOnionDict[bucket] += os_rtts[osSessionId]['yPacketBytesOutOnion'][i]
                
                # client
                for i in range(0, len(client_rtts[clientSessionId]['yPacketTimesIn'])):
                    ts = client_rtts[clientSessionId]['yPacketTimesIn'][i] # time in milliseconds

                    relativeTs = ts - initial_session_ts
                    bucket = relativeTs * 1000 // timeSamplingInterval
                        
                    yPacketCountInDict[bucket] += 1
                    # TODO: fix this, these should be the orginal bytes received in the features, not the bucketed ones
                    #yPacketBytesInDict[bucket] += client_rtts[clientSessionId]['yPacketBytesIn'][i]

                # Here we place only the bucket range from the OS that makes sense to compare with the client
                possible_request_combinations[key] = {'yPacketBytesOutOnion': list(yPacketBytesOutOnionDict.values()), 'yPacketCountOutOnion': list(yPacketCountOutOnionDict.values()), \
                                                        'yPacketBytesIn': list(yPacketBytesInDict.values()), 'yPacketCountIn': list(yPacketCountInDict.values()), 'label': label}
                
            else:
                if clientSessionId == osSessionId:
                    print("\n--- Removed correlated flow for being in different epochs:\nclientSessionId", clientSessionId)
                    print("osSessionId", osSessionId)
                    print("buckets_clients[clientSessionId]['initialTs']", buckets_clients[clientSessionId]['initialTs'])
                    print("buckets_clients[clientSessionId]['finalTs']", buckets_clients[clientSessionId]['finalTs'])
                    print("initial_epoch", initial_epoch)
                    print("last_epoch", last_epoch)
                    print("buckets_os[osSessionId]['initialTs']", buckets_oses[osSessionId]['initialTs'])
                    print("buckets_os[osSessionId]['finalTs']", buckets_oses[osSessionId]['finalTs'])
                    print("os_initial_epoch", os_initial_epoch)
                    print("os_last_epoch", os_last_epoch)

        counter += 1

    return possible_request_combinations, client_rtts, os_rtts


"""
def process_features_epochs_requests_test_deepcoffea_our_dataset_march(testPairs, timeSamplingInterval, earlyStop=None):
    possible_request_combinations = {}
    client_rtts = {}
    os_rtts = {}

    counter = 0

    # absolute initial and final tses of the whole experience
    initial_ts_experience, last_ts_experience, buckets_clients, buckets_oses = getTsesAndBucketsEpochs(testPairs, timeSamplingInterval)

    print("=== Finished organizing buckets")
    for testPair in testPairs['correlated']['samples']:
        if earlyStop is not None and counter == earlyStop: 
            break

        clientCapture = testPair['clientFolder'].split("/")[-1]   
        requestId = clientCapture.split("_client")[0]
        onionCapture = testPair['hsFolder'].split("/")[-1]

        yPacketBytesInDict =  {}
        yPacketCountInDict = {}
        for bucket in buckets_clients[requestId]['buckets']:
            yPacketBytesInDict[bucket] = 0
        for bucket in buckets_clients[requestId]['buckets']:
            yPacketCountInDict[bucket] = 0

        for i in range(0, len(testPair['clientFlow']['sizesIn'])):
            initial_ts = buckets_clients[requestId]['initialTs']
            ts = testPair['clientFlow']['timesInAbs'][i] # time in milliseconds

            relativeTs = ts-initial_ts
            bucket = relativeTs * 1000 // timeSamplingInterval
            
            yPacketCountInDict[bucket] += 1
            yPacketBytesInDict[bucket] += testPair['clientFlow']['sizesIn'][i]

        yPacketBytesIn = list(yPacketBytesInDict.values())
        yPacketCountIn = list(yPacketCountInDict.values())

        allAbsTimes = testPair['clientFlow']['timesOutAbs'] + testPair['clientFlow']['timesInAbs']
        absoluteInitialTime = min(allAbsTimes)
        maxAbsoluteTime = max(allAbsTimes)

        client_rtts[sessionId] = {'rtts': [absoluteInitialTime, maxAbsoluteTime], 'yPacketBytesIn': yPacketBytesIn, 'yPacketCountIn': yPacketCountIn, 'requestIds': [clientCapture], 'yPacketTimesIn': testPair['clientFlow']['timesInAbs']}

        # onion part
        yPacketBytesOutOnion = []
        yPacketTimesOutOnion = []
        for i in range(0, len(testPair['hsFlow']['sizesOut'])):
            yPacketBytesOutOnion.append(testPair['hsFlow']['sizesOut'][i])
            yPacketTimesOutOnion.append(testPair['hsFlow']['timesOutAbs'][i])

        allAbsTimesOnion = testPair['hsFlow']['timesOutAbs'] + testPair['hsFlow']['timesInAbs']
        absoluteInitialTimeOnion = min(allAbsTimesOnion)
        maxAbsoluteTimeOnion = max(allAbsTimesOnion)
        
        if sessionId not in os_rtts:
            os_rtts[sessionId] = {'rtts': [absoluteInitialTimeOnion, maxAbsoluteTimeOnion], 'yPacketBytesOutOnion': yPacketBytesOutOnion, 'yPacketTimesOutOnion': yPacketTimesOutOnion, 'requestIds': [onionCapture]}
        else:
            if onionCapture not in os_rtts[sessionId]['requestIds']:
                os_rtts[sessionId]['rtts'] += [absoluteInitialTimeOnion, maxAbsoluteTimeOnion]
                os_rtts[sessionId]['yPacketBytesOutOnion'] += yPacketBytesOutOnion
                os_rtts[sessionId]['yPacketTimesOutOnion'] += yPacketTimesOutOnion
                os_rtts[sessionId]['requestIds'] += [onionCapture]

        counter += 1

    print("=== Finished gathering data on correlated pairs")
    counter = 0

    test_samples_file = open('d1.0_ws1.6_nw5_thr10_tl200_el300_nt500_test_files.txt', 'r')
    test_samples = test_samples_file.readlines()
    test_samples_file.close()

    count_correlated = 0
    for sample in test_samples:
        print("\n--- sample", sample)
        clientSessionId = (sample.split('/')[-1]).split('_request_')[0]
        for sample in test_samples:
            osSessionId = (sample.split('/')[-1]).split('_request_')[0]

            key = (clientSessionId, osSessionId)
            label = 0
            if clientSessionId == osSessionId:
                label = 1
                count_correlated += 1
            else:
                # remove duplicated captures from same OS
                osName = osSessionId.split("_")[1]
                if osName in clientSessionId:
                    continue
                
            
            initial_session_ts = min(buckets_clients[clientSessionId]['initialTs'], buckets_oses[osSessionId]['initialTs'])
            final_session_ts = max(buckets_clients[clientSessionId]['finalTs'], buckets_oses[osSessionId]['finalTs'])
            buckets_session = generateBucketsEpochs(initial_session_ts, final_session_ts, timeSamplingInterval)

            yPacketBytesOutOnionDict =  {}
            yPacketCountOutOnionDict = {}
            yPacketBytesInDict =  {}
            yPacketCountInDict = {}
            for bucket in buckets_session:
                yPacketBytesOutOnionDict[bucket] = 0
                yPacketCountOutOnionDict[bucket] = 0
                yPacketBytesInDict[bucket] = 0
                yPacketCountInDict[bucket] = 0
                

            # onion
            for i in range(0, len(os_rtts[osSessionId]['yPacketTimesOutOnion'])):
                ts = os_rtts[osSessionId]['yPacketTimesOutOnion'][i] # time in milliseconds

                relativeTs = ts - initial_session_ts
                bucket = relativeTs * 1000 // timeSamplingInterval
                    
                yPacketCountOutOnionDict[bucket] += 1
                yPacketBytesOutOnionDict[bucket] += os_rtts[osSessionId]['yPacketBytesOutOnion'][i]
            
            # client
            for i in range(0, len(client_rtts[clientSessionId]['yPacketTimesIn'])):
                ts = client_rtts[clientSessionId]['yPacketTimesIn'][i] # time in milliseconds

                relativeTs = ts - initial_session_ts
                bucket = relativeTs * 1000 // timeSamplingInterval
                    
                yPacketCountInDict[bucket] += 1
                # TODO: fix this, these should be the orginal bytes received in the features, not the bucketed ones
                #yPacketBytesInDict[bucket] += client_rtts[clientSessionId]['yPacketBytesIn'][i]

            # Here we place only the bucket range from the OS that makes sense to compare with the client
            possible_request_combinations[key] = {'yPacketBytesOutOnion': list(yPacketBytesOutOnionDict.values()), 'yPacketCountOutOnion': list(yPacketCountOutOnionDict.values()), \
                                                    'yPacketBytesIn': list(yPacketBytesInDict.values()), 'yPacketCountIn': list(yPacketCountInDict.values()), 'label': label}
            

        counter += 1

    print("\n+++++ count_correlated", count_correlated)

    return possible_request_combinations, client_rtts, os_rtts

"""


def process_features_epochs_requests_test_deepcoffea_our_dataset_march(testPairs, timeSamplingInterval, earlyStop=None):
    possible_request_combinations = {}
    client_rtts = {}
    os_rtts = {}

    counter = 0

    # absolute initial and final tses of the whole experience
    initial_ts_experience, last_ts_experience, buckets_clients, buckets_oses = getTsesAndBucketsEpochsRequests(testPairs, timeSamplingInterval)

    print("=== Finished organizing buckets")
    for testPair in testPairs['correlated']['samples']:
        if earlyStop is not None and counter == earlyStop: 
            break

        clientCapture = testPair['clientFolder'].split("/")[-1]   
        requestId = clientCapture.split("_client")[0]
        onionCapture = testPair['hsFolder'].split("/")[-1]

        yPacketBytesInDict =  {}
        yPacketCountInDict = {}

        for bucket in buckets_clients[requestId]['buckets']:
            yPacketBytesInDict[bucket] = 0
        for bucket in buckets_clients[requestId]['buckets']:
            yPacketCountInDict[bucket] = 0

        for i in range(0, len(testPair['clientFlow']['sizesIn'])):
            initial_ts = buckets_clients[requestId]['initialTs']
            ts = testPair['clientFlow']['timesInAbs'][i] # time in milliseconds

            relativeTs = ts-initial_ts
            bucket = relativeTs * 1000 // timeSamplingInterval
            
            yPacketCountInDict[bucket] += 1
            yPacketBytesInDict[bucket] += testPair['clientFlow']['sizesIn'][i]

        yPacketBytesIn = list(yPacketBytesInDict.values())
        yPacketCountIn = list(yPacketCountInDict.values())

        allAbsTimes = testPair['clientFlow']['timesOutAbs'] + testPair['clientFlow']['timesInAbs']
        absoluteInitialTime = min(allAbsTimes)
        maxAbsoluteTime = max(allAbsTimes)

        client_rtts[requestId] = {'rtts': [absoluteInitialTime, maxAbsoluteTime], 'yPacketBytesIn': yPacketBytesIn, 'yPacketCountIn': yPacketCountIn, 'requestIds': [clientCapture], 'yPacketTimesIn': testPair['clientFlow']['timesInAbs']}

        # onion part
        yPacketBytesOutOnion = []
        yPacketTimesOutOnion = []
        for i in range(0, len(testPair['hsFlow']['sizesOut'])):
            yPacketBytesOutOnion.append(testPair['hsFlow']['sizesOut'][i])
            yPacketTimesOutOnion.append(testPair['hsFlow']['timesOutAbs'][i])

        allAbsTimesOnion = testPair['hsFlow']['timesOutAbs'] + testPair['hsFlow']['timesInAbs']
        absoluteInitialTimeOnion = min(allAbsTimesOnion)
        maxAbsoluteTimeOnion = max(allAbsTimesOnion)
        
        os_rtts[requestId] = {'rtts': [absoluteInitialTimeOnion, maxAbsoluteTimeOnion], 'yPacketBytesOutOnion': yPacketBytesOutOnion, 'yPacketTimesOutOnion': yPacketTimesOutOnion, 'requestIds': [onionCapture]}

        counter += 1

    print("=== Finished gathering data on correlated pairs")
    counter = 0

    test_samples_file = open('d1.0_ws1.6_nw5_thr10_tl200_el300_nt500_test_files.txt', 'r')
    test_samples = test_samples_file.readlines()
    test_samples_file.close()

    count_correlated = 0
    for clientSample in test_samples:
        print("\n--- clientSample", clientSample)
        #sample = sample.strip('\n')
        clientSample = clientSample.replace("\n", "")
        clientRequestId = clientSample.split('/')[-1]
        for osSample in test_samples:
            osSample = osSample.replace("\n", "")
            osRequestId = osSample.split('/')[-1]

            key = (clientRequestId, osRequestId)
            label = 0
            if clientRequestId == osRequestId:
                label = 1
                count_correlated += 1
            else:
                # remove duplicated captures from same OS
                osName = osRequestId.split("_")[1]
                if osName in clientRequestId:
                    continue
                
            
            initial_session_ts = min(buckets_clients[clientRequestId]['initialTs'], buckets_oses[osRequestId]['initialTs'])
            final_session_ts = max(buckets_clients[clientRequestId]['finalTs'], buckets_oses[osRequestId]['finalTs'])
            buckets_session = generateBucketsEpochs(initial_session_ts, final_session_ts, timeSamplingInterval)

            yPacketBytesOutOnionDict =  {}
            yPacketCountOutOnionDict = {}
            yPacketBytesInDict =  {}
            yPacketCountInDict = {}
            for bucket in buckets_session:
                yPacketBytesOutOnionDict[bucket] = 0
                yPacketCountOutOnionDict[bucket] = 0
                yPacketBytesInDict[bucket] = 0
                yPacketCountInDict[bucket] = 0
                

            # onion
            for i in range(0, len(os_rtts[osRequestId]['yPacketTimesOutOnion'])):
                ts = os_rtts[osRequestId]['yPacketTimesOutOnion'][i] # time in milliseconds

                relativeTs = ts - initial_session_ts
                bucket = relativeTs * 1000 // timeSamplingInterval
                    
                yPacketCountOutOnionDict[bucket] += 1
                yPacketBytesOutOnionDict[bucket] += os_rtts[osRequestId]['yPacketBytesOutOnion'][i]
            
            # client
            for i in range(0, len(client_rtts[clientRequestId]['yPacketTimesIn'])):
                ts = client_rtts[clientRequestId]['yPacketTimesIn'][i] # time in milliseconds

                relativeTs = ts - initial_session_ts
                bucket = relativeTs * 1000 // timeSamplingInterval
                    
                yPacketCountInDict[bucket] += 1
                # TODO: fix this, these should be the orginal bytes received in the features, not the bucketed ones
                #yPacketBytesInDict[bucket] += client_rtts[clientSessionId]['yPacketBytesIn'][i]

            # Here we place only the bucket range from the OS that makes sense to compare with the client
            possible_request_combinations[key] = {'yPacketBytesOutOnion': list(yPacketBytesOutOnionDict.values()), 'yPacketCountOutOnion': list(yPacketCountOutOnionDict.values()), \
                                                    'yPacketBytesIn': list(yPacketBytesInDict.values()), 'yPacketCountIn': list(yPacketCountInDict.values()), 'label': label}
            

        counter += 1

    print("\n+++++ count_correlated", count_correlated)

    return possible_request_combinations, client_rtts, os_rtts


def process_features_epochs_requests_test_dataset_deepcoffea(timeSamplingInterval, earlyStop=None):
    possible_request_combinations = {}
    client_rtts = {}
    os_rtts = {}
    buckets_clients = {}
    buckets_oses = {}

    counter = 0

    test_pairs = []
    for file_idx, file in enumerate(os.listdir("ml_experiments/datasets/CrawlE_Proc_for_DC/")):
        if file_idx == 1:
            break
        dataset_chunk = pickle.load(open("ml_experiments/datasets/CrawlE_Proc_for_DC/"+file, 'rb'))
        for pair in dataset_chunk:
            test_pairs.append(pair)

            ts_accm_client = 0
            clientCapture = 'client{}'.format(counter)  
            tses_in_client = pair['here'][0]['<-']
            tses_accm_client = []
            packets_in_client = pair['here'][1]['<-']
            for i in range(0, len(packets_in_client)):
                if clientCapture not in buckets_clients:
                    buckets_clients[clientCapture] = {'initialTses': [], 'finalTses': []}
                ts_accm_client += tses_in_client[i]
                tses_accm_client.append(ts_accm_client)
            buckets_clients[clientCapture]['initialTses'].append(min(tses_accm_client))
            buckets_clients[clientCapture]['finalTses'].append(max(tses_accm_client))
            buckets_clients[clientCapture]['tses'] = tses_accm_client


            ts_accm_os = 0
            osCapture = 'client{}'.format(counter)  
            tses_in_os = pair['there'][0]['->']
            tses_accm_os = []
            packets_in_os = pair['there'][1]['->']
            for i in range(0, len(packets_in_os)):
                if osCapture not in buckets_oses:
                    buckets_oses[osCapture] = {'initialTses': [], 'finalTses': []}
                ts_accm_os += tses_in_os[i]
                tses_accm_os.append(ts_accm_os)
            buckets_oses[osCapture]['initialTses'].append(min(tses_accm_os))
            buckets_oses[osCapture]['finalTses'].append(max(tses_accm_os))
            buckets_oses[osCapture]['tses'] = tses_accm_os


            counter += 1

    for requestId, data in buckets_clients.items():
        #print("requestId", requestId)
        clientInitialTs = min(data['initialTses'])
        clientFinalTs = max(data['finalTses'])
        buckets_clients[requestId]['initialTs'] = clientInitialTs
        buckets_clients[requestId]['finalTs'] = clientFinalTs
        buckets_clients[requestId]['buckets'] = generateBucketsEpochs(clientInitialTs,clientFinalTs, timeSamplingInterval)

    for onionRequestId, data in buckets_oses.items():
        osInitialTs = min(data['initialTses'])
        osFinalTs = max(data['finalTses'])
        buckets_oses[onionRequestId]['initialTs'] = osInitialTs
        buckets_oses[onionRequestId]['finalTs'] = osFinalTs
        buckets_oses[onionRequestId]['buckets'] = generateBucketsEpochs(osInitialTs, osFinalTs, timeSamplingInterval)

    counter = 0
    print("=== Finished organizing buckets")
    for testPair in test_pairs:
        if earlyStop is not None and counter == earlyStop: 
            break
  
        requestId = 'client{}'.format(counter)  

        yPacketBytesInDict =  {}
        yPacketCountInDict = {}

        for bucket in buckets_clients[requestId]['buckets']:
            yPacketBytesInDict[bucket] = 0
        for bucket in buckets_clients[requestId]['buckets']:
            yPacketCountInDict[bucket] = 0

        packets_in_client = testPair['here'][1]['<-']
        for i in range(0, len(packets_in_client)):
            initial_ts = buckets_clients[requestId]['initialTs']
            ts = buckets_clients[requestId]['tses'][i] # time in milliseconds

            relativeTs = ts-initial_ts
            bucket = relativeTs * 1000 // timeSamplingInterval
            
            yPacketCountInDict[bucket] += 1
            yPacketBytesInDict[bucket] += packets_in_client[i]

        yPacketBytesIn = list(yPacketBytesInDict.values())
        yPacketCountIn = list(yPacketCountInDict.values())

        allAbsTimes = buckets_clients[requestId]['tses']
        absoluteInitialTime = min(allAbsTimes)
        maxAbsoluteTime = max(allAbsTimes)

        client_rtts[requestId] = {'rtts': [absoluteInitialTime, maxAbsoluteTime], 'yPacketBytesIn': yPacketBytesIn, 'yPacketCountIn': yPacketCountIn, 'requestIds': [clientCapture], 'yPacketTimesIn': buckets_clients[requestId]['tses']}

        # onion part
        packets_in_os = testPair['there'][1]['->']
        yPacketBytesOutOnion = []
        yPacketTimesOutOnion = []
        for i in range(0, len(packets_in_os)):
            yPacketBytesOutOnion.append(packets_in_os[i])
            yPacketTimesOutOnion.append(buckets_oses[requestId]['tses'][i])

        allAbsTimesOnion = buckets_oses[requestId]['tses']
        absoluteInitialTimeOnion = min(allAbsTimesOnion)
        maxAbsoluteTimeOnion = max(allAbsTimesOnion)
        
        os_rtts[requestId] = {'rtts': [absoluteInitialTimeOnion, maxAbsoluteTimeOnion], 'yPacketBytesOutOnion': yPacketBytesOutOnion, 'yPacketTimesOutOnion': buckets_oses[requestId]['tses']}

        counter += 1

    print("=== Finished gathering data on correlated pairs", counter)
    counter = 0


    count_correlated = 0
    for client_idx, clientRequestId in enumerate(client_rtts.keys()):
        if client_idx % 100 == 0:
            print("client_idx", client_idx)
        for onion_idx, osRequestId in enumerate(os_rtts.keys()):
            if onion_idx % 100 == 0:    
                print("onion_idx", onion_idx)
            key = (clientRequestId, osRequestId)
            label = 0
            if clientRequestId == osRequestId:
                label = 1
                count_correlated += 1
                   
            initial_session_ts = min(buckets_clients[clientRequestId]['initialTs'], buckets_oses[osRequestId]['initialTs'])
            final_session_ts = max(buckets_clients[clientRequestId]['finalTs'], buckets_oses[osRequestId]['finalTs'])
            buckets_session = generateBucketsEpochs(initial_session_ts, final_session_ts, timeSamplingInterval)

            yPacketBytesOutOnionDict =  {}
            yPacketCountOutOnionDict = {}
            yPacketBytesInDict =  {}
            yPacketCountInDict = {}
            for bucket in buckets_session:
                yPacketBytesOutOnionDict[bucket] = 0
                yPacketCountOutOnionDict[bucket] = 0
                yPacketBytesInDict[bucket] = 0
                yPacketCountInDict[bucket] = 0
                

            # onion
            for i in range(0, len(os_rtts[osRequestId]['yPacketTimesOutOnion'])):
                ts = os_rtts[osRequestId]['yPacketTimesOutOnion'][i] # time in milliseconds

                relativeTs = ts - initial_session_ts
                bucket = relativeTs * 1000 // timeSamplingInterval
                    
                yPacketCountOutOnionDict[bucket] += 1
                yPacketBytesOutOnionDict[bucket] += os_rtts[osRequestId]['yPacketBytesOutOnion'][i]


            # client
            for i in range(0, len(client_rtts[clientRequestId]['yPacketTimesIn'])):
                ts = client_rtts[clientRequestId]['yPacketTimesIn'][i] # time in milliseconds

                relativeTs = ts - initial_session_ts
                bucket = relativeTs * 1000 // timeSamplingInterval
                    
                yPacketCountInDict[bucket] += 1


            # Here we place only the bucket range from the OS that makes sense to compare with the client
            possible_request_combinations[key] = {'yPacketBytesOutOnion': list(yPacketBytesOutOnionDict.values()), 'yPacketCountOutOnion': list(yPacketCountOutOnionDict.values()), \
                                                    'yPacketBytesIn': list(yPacketBytesInDict.values()), 'yPacketCountIn': list(yPacketCountInDict.values()), 'label': label}
            

        counter += 1

    print("\n+++++ count_correlated", count_correlated)

    return possible_request_combinations, client_rtts, os_rtts


def process_features_epochs(testPairs, timeSamplingInterval, epoch_size, earlyStop=None):
    possible_request_combinations = {}
    client_rtts = {}
    os_rtts = {}

    counter = 0

    # absolute initial and final tses of the whole experience
    initial_ts_experience, last_ts_experience, buckets_clients, buckets_oses = getTsesAndBucketsEpochs(testPairs, timeSamplingInterval)
    
    print("=== Finished organizing buckets")
    for testPair in testPairs['correlated']['samples']:

        if earlyStop is not None and counter == earlyStop: 
            break

        clientCapture = testPair['clientFolder'].split("/")[-1]   
        sessionId = clientCapture.split("_request")[0]

        onionCapture = testPair['hsFolder'].split("/")[-1]
        onionSessionId = onionCapture.split('_request')[0]

        yPacketBytesInDict =  {}
        yPacketCountInDict = {}
        for bucket in buckets_clients[sessionId]['buckets']:
            yPacketBytesInDict[bucket] = 0
        for bucket in buckets_clients[sessionId]['buckets']:
            yPacketCountInDict[bucket] = 0

        for i in range(0, len(testPair['clientFlow']['sizesIn'])):
            initial_ts = buckets_clients[sessionId]['initialTs']
            final_ts = buckets_clients[sessionId]['finalTs']
            ts = testPair['clientFlow']['timesInAbs'][i] # time in milliseconds

            relativeTs = ts-initial_ts
   
            bucket = relativeTs * 1000 // timeSamplingInterval
            
            yPacketCountInDict[bucket] += 1
            yPacketBytesInDict[bucket] += testPair['clientFlow']['sizesIn'][i]

        yPacketBytesIn = list(yPacketBytesInDict.values())
        yPacketCountIn = list(yPacketCountInDict.values())

        allAbsTimes = testPair['clientFlow']['timesOutAbs'] + testPair['clientFlow']['timesInAbs']
        absoluteInitialTime = min(allAbsTimes)
        maxAbsoluteTime = max(allAbsTimes)

        if sessionId not in client_rtts:
            client_rtts[sessionId] = {'rtts': [absoluteInitialTime, maxAbsoluteTime], 'yPacketBytesIn': yPacketBytesIn, 'yPacketCountIn': yPacketCountIn, 'requestIds': [clientCapture], 'yPacketTimesIn': testPair['clientFlow']['timesInAbs']}
        else:
            if clientCapture not in client_rtts[sessionId]['requestIds']:
                client_rtts[sessionId]['rtts'] += [absoluteInitialTime, maxAbsoluteTime]
                client_rtts[sessionId]['yPacketBytesIn'] = np.add(client_rtts[sessionId]['yPacketBytesIn'], yPacketBytesIn)
                client_rtts[sessionId]['yPacketCountIn'] = np.add(client_rtts[sessionId]['yPacketCountIn'], yPacketCountIn)
                client_rtts[sessionId]['requestIds'] += [clientCapture]

        
        # onion part
        yPacketBytesOutOnion = []
        yPacketTimesOutOnion = []
        for i in range(0, len(testPair['hsFlow']['sizesOut'])):
            yPacketBytesOutOnion.append(testPair['hsFlow']['sizesOut'][i])
            yPacketTimesOutOnion.append(testPair['hsFlow']['timesOutAbs'][i])

        allAbsTimesOnion = testPair['hsFlow']['timesOutAbs'] + testPair['hsFlow']['timesInAbs']
        absoluteInitialTimeOnion = min(allAbsTimesOnion)
        maxAbsoluteTimeOnion = max(allAbsTimesOnion)
        
        if sessionId not in os_rtts:
            os_rtts[sessionId] = {'rtts': [absoluteInitialTimeOnion, maxAbsoluteTimeOnion], 'yPacketBytesOutOnion': yPacketBytesOutOnion, 'yPacketTimesOutOnion': yPacketTimesOutOnion, 'requestIds': [onionCapture]}
        else:
            if onionCapture not in os_rtts[sessionId]['requestIds']:
                os_rtts[sessionId]['rtts'] += [absoluteInitialTimeOnion, maxAbsoluteTimeOnion]
                os_rtts[sessionId]['yPacketBytesOutOnion'] += yPacketBytesOutOnion
                os_rtts[sessionId]['yPacketTimesOutOnion'] += yPacketTimesOutOnion
                os_rtts[sessionId]['requestIds'] += [onionCapture]
        
        counter += 1

    print("=== Finished gathering data on correlated pairs")
    counter = 0
    # Now we have a list of all possible client-side sessions and os-side sessions
    # and their respetive start and end times. So, now we group all possible
    # combinations per epoch
    for clientSessionId in client_rtts.keys():
        #if earlyStop is not None and counter == earlyStop: 
         #       break

        initial_epoch = buckets_clients[clientSessionId]['initialTs'] // epoch_size
        last_epoch = (buckets_clients[clientSessionId]['finalTs'] // epoch_size) + 1

        # Check which OSes are within the same epochs
        for osSessionId in os_rtts.keys():

            os_initial_epoch = buckets_oses[osSessionId]['initialTs'] // epoch_size
            os_last_epoch = (buckets_oses[osSessionId]['finalTs'] // epoch_size) + 1
            
            #(StartDate1 <= EndDate2) and (StartDate2 <= EndDate1)
            # Both flows overlap in epoch times, so we consider them a possible combination
            if (os_initial_epoch <= last_epoch) and (initial_epoch <= os_last_epoch):
                key = (clientSessionId, osSessionId)
                label = 0
                if clientSessionId == osSessionId:
                    label = 1

                yPacketBytesOutOnionDict =  {}
                yPacketCountOutOnionDict = {}
                for bucket in buckets_clients[clientSessionId]['buckets']:
                    yPacketBytesOutOnionDict[bucket] = 0
                for bucket in buckets_clients[clientSessionId]['buckets']:
                    yPacketCountOutOnionDict[bucket] = 0
                for i in range(0, len(os_rtts[osSessionId]['yPacketTimesOutOnion'])):
                    initial_ts = buckets_oses[osSessionId]['initialTs']
                    client_initial_ts = buckets_clients[clientSessionId]['initialTs']
                    client_final_ts = buckets_clients[clientSessionId]['finalTs']
                    ts = os_rtts[osSessionId]['yPacketTimesOutOnion'][i] # time in milliseconds
                    
                    #print("buckets_oses", buckets_oses[osSessionId])
                    #print("initial_ts", initial_ts)
                    #print("buckets_client", buckets_clients[sessionId])
                    if ts >= client_initial_ts and ts <= client_final_ts:
                        #relativeTs = ts-initial_ts
                        relativeTs = ts - client_initial_ts
                        bucket = relativeTs * 1000 // timeSamplingInterval
                        
                        #if clientSessionId != osSessionId:
                        #    print("clientSessionId", clientSessionId)
                        #    print("osSessionId", osSessionId)
                        #    print("initial_ts client", buckets_clients[clientSessionId]['initialTs'])
                        #    print("finalTs client", buckets_clients[clientSessionId]['finalTs'])
                            #print("buckets client", len(buckets_clients[sessionId]))
                        #    print("initial_ts OS", initial_ts)
                        #    print("finalTs OS", buckets_oses[osSessionId]['initialTs'])
                        #    print("relativeTs", relativeTs)
                        #    print("buckets_oses", buckets_oses[osSessionId])
                        #    print("buckets_client", buckets_clients[clientSessionId])
                        #    print("bucket", bucket)
                            
                        #if bucket in buckets_clients[sessionId]['buckets']:
                        yPacketCountOutOnionDict[bucket] += 1
                        yPacketBytesOutOnionDict[bucket] += os_rtts[osSessionId]['yPacketBytesOutOnion'][i]

                # Here we place only the bucket range from the OS that makes sense to compare with the client
                #possible_request_combinations[key] = {'yPacketBytesOutOnion': list(yPacketBytesOutOnionDict.values()), 'yPacketCountOutOnion': list(yPacketCountOutOnionDict.values()), 'label': label}
                possible_request_combinations[key] = {'yPacketBytesOutOnion': list(yPacketBytesOutOnionDict.values()), 'yPacketCountOutOnion': list(yPacketCountOutOnionDict.values()), \
                                                        'yPacketBytesIn': client_rtts[clientSessionId]['yPacketBytesIn'], 'yPacketCountIn': client_rtts[clientSessionId]['yPacketCountIn'], 'label': label}
                                                        
        counter += 1

    return possible_request_combinations, client_rtts, os_rtts


def process_features(testPairs, timeSamplingInterval, buckets, earlyStop=None):
    possible_request_combinations = {}
    client_rtts = {}

    correlated = 0
    non_correlated = 0

    # We have to initialize them with ints, otherwise they will be initialized as floats
    #packetListClients = np.empty(0, int)
    #packetListOSes = np.empty(0, int)
    packetListClients = []
    packetListOSes = []

    counter = 0

    for key in testPairs:
        samples = None
        labels = None

        if key == 'correlated':
            samples = testPairs[key]['samples']
            labels = testPairs[key]['labels']

            index = 0

            for testPair in samples:
                if earlyStop is not None and counter == earlyStop: 
                    break
                #if correlated >= 10: continue
                #correlated += 1

                clientCapture = testPair['clientFolder'].split("/")[-1]   
                sessionId = clientCapture.split("_request")[0]
                clientName = testPair['clientLocation']
                
                onionName = testPair['hsLocation']
                onionCapture = testPair['hsFolder'].split("/")[-1]
                onionSessionId = onionCapture.split('_request')[0]

                sessionKey = (sessionId, onionSessionId)
                
                #if not(('client-brazil-south_os-australia-east_f2fv76wtuwdvbpci_400_4_session_34' in sessionId \
                #        and 'client-brazil-south_os-australia-east_f2fv76wtuwdvbpci_400_4_session_34' in onionSessionId) or \
                #        ('client-brazil-south_os-australia-east_f2fv76wtuwdvbpci_400_4_session_49' in sessionId and \
                #        'client-brazil-south_os-australia-east_f2fv76wtuwdvbpci_400_4_session_49' in onionSessionId)):
                #    continue
                
                #if not(('client-germany-west-central_os-north-europe_ig2ioz6j2vpcmz27nlqmfdrscijqeqnjv6ku3pkpte7pm53gxeal5hqd_700_9_session_44' in sessionId) \
                #        and ('client-germany-west-central_os-north-europe_ig2ioz6j2vpcmz27nlqmfdrscijqeqnjv6ku3pkpte7pm53gxeal5hqd_700_9_session_44' in onionSessionId)):
                #    continue

                yPacketBytesInDict =  {}
                yPacketCountInDict = {}
                for bucket in buckets[sessionId]['buckets']:
                    yPacketBytesInDict[bucket] = 0
                for bucket in buckets[sessionId]['buckets']:
                    yPacketCountInDict[bucket] = 0

                for i in range(0, len(testPair['clientFlow']['sizesIn'])):
                    initial_ts = buckets[sessionId]['initialTs']
                    final_ts = buckets[sessionId]['finalTs']
                    ts = testPair['clientFlow']['timesInAbs'][i] # time in milliseconds
                    #print("sessionId", sessionId)
                    #print("initialTs", initial_ts)
                    #print("final_ts", final_ts)
                    #print("ts", ts)
                    relativeTs = ts-initial_ts
                    bucket = int(relativeTs * 1000 / timeSamplingInterval)
                
                    #print("bucket", bucket)
                    
                    yPacketCountInDict[bucket] += 1
                    yPacketBytesInDict[bucket] += testPair['clientFlow']['sizesIn'][i]

                yPacketBytesIn = list(yPacketBytesInDict.values())
                yPacketCountIn = list(yPacketCountInDict.values())

                allAbsTimes = testPair['clientFlow']['timesOutAbs'] + testPair['clientFlow']['timesInAbs']
                absoluteInitialTime = min(allAbsTimes)
                maxAbsoluteTime = max(allAbsTimes)

                if sessionId not in client_rtts:
                    client_rtts[sessionId] = {'rtts': [absoluteInitialTime, maxAbsoluteTime], 'yPacketBytesIn': yPacketBytesIn, 'yPacketCountIn': yPacketCountIn, 'requestIds': [clientCapture]}
                else:
                    if clientCapture not in client_rtts[sessionId]['requestIds']:
                        client_rtts[sessionId]['rtts'] += [absoluteInitialTime, maxAbsoluteTime]
                        client_rtts[sessionId]['yPacketBytesIn'] = np.add(client_rtts[sessionId]['yPacketBytesIn'], yPacketBytesIn)
                        client_rtts[sessionId]['yPacketCountIn'] = np.add(client_rtts[sessionId]['yPacketCountIn'], yPacketCountIn)
                        client_rtts[sessionId]['requestIds'] += [clientCapture]

                # onion part
                yPacketBytesOutOnionDict =  {}
                yPacketCountOutOnionDict = {}
                for bucket in buckets[sessionId]['buckets']:
                    yPacketBytesOutOnionDict[bucket] = 0
                for bucket in buckets[sessionId]['buckets']:
                    yPacketCountOutOnionDict[bucket] = 0
                for i in range(0, len(testPair['hsFlow']['sizesOut'])):
                    initial_ts = buckets[sessionId]['initialTs']
                    final_ts = buckets[sessionId]['finalTs']
                    ts = testPair['hsFlow']['timesOutAbs'][i] # time in milliseconds
                    # Outside of client flow's window
                    if ts < initial_ts or ts > final_ts:
                        continue
                    relativeTs = ts-initial_ts
                    bucket = int(relativeTs * 1000 / timeSamplingInterval)
                    
                    yPacketCountOutOnionDict[bucket] += 1
                    yPacketBytesOutOnionDict[bucket] += testPair['hsFlow']['sizesOut'][i]

                yPacketBytesOutOnion = list(yPacketBytesOutOnionDict.values())
                yPacketCountOutOnion = list(yPacketCountOutOnionDict.values())

                if sessionKey not in possible_request_combinations:
                    possible_request_combinations[sessionKey] = {'yPacketBytesOutOnion': yPacketBytesOutOnion, 'yPacketCountOutOnion': yPacketCountOutOnion, 'label': 1, 'requestIds': [(clientCapture, onionCapture)]}
                else:
                    onionRequestIds = [x[1] for x in possible_request_combinations[sessionKey]['requestIds']]
                    if onionCapture not in onionRequestIds:
                        possible_request_combinations[sessionKey]['yPacketBytesOutOnion'] = np.add(possible_request_combinations[sessionKey]['yPacketBytesOutOnion'], yPacketBytesOutOnion)
                        possible_request_combinations[sessionKey]['yPacketCountOutOnion'] = np.add(possible_request_combinations[sessionKey]['yPacketCountOutOnion'], yPacketCountOutOnion)
                        possible_request_combinations[sessionKey]['requestIds'] += [(clientCapture, onionCapture)]

                #print("yPacketCountIn", yPacketCountIn)
                #packetListClients += yPacketCountIn
                #packetListOSes += yPacketCountOutOnion
                #packetListClients.append(yPacketCountIn)
                #packetListOSes.append(yPacketCountOutOnion)
                
                #count += 1
                #if count > 16:
                #    return possible_request_combinations, client_rtts, packetListClients, packetListOSes
                counter += 1

        else:
            for key2 in testPairs[key]['samples']:
                if earlyStop is not None and counter == earlyStop: 
                    break

                samples = testPairs[key]['samples'][key2]
                labels = testPairs[key]['labels'][key2]

                index = 0

                for testPair in samples:
                    #if non_correlated >= 10: continue
                    #non_correlated += 1

                    clientCapture = testPair['clientFolder'].split("/")[-1]   
                    sessionId = clientCapture.split("_request")[0]
                    #print("NON CORRELATED:", sessionId)
                    clientName = testPair['clientLocation']
                    
                    onionName = testPair['hsLocation']
                    onionCapture = testPair['hsFolder'].split("/")[-1]
                    onionSessionId = onionCapture.split('_request')[0]

                    # fp : ('client-brazil-south_os-north-europe_ig2ioz6j2vpcmz27nlqmfdrscijqeqnjv6ku3pkpte7pm53gxeal5hqd_700_9_session_7', 'client-germany-west-central_os-australia-east_f2fv76wtuwdvbpci_400_4_session_9')
                    # fp : ('client-brazil-south_os-north-europe_ig2ioz6j2vpcmz27nlqmfdrscijqeqnjv6ku3pkpte7pm53gxeal5hqd_700_9_session_6', 'client-germany-west-central_os-australia-east_f2fv76wtuwdvbpci_400_4_session_8')
                    #if not(sessionId == 'client-germany-west-central_os-australia-east_f2fv76wtuwdvbpci_400_4_session_37' and onionSessionId == 'client-brazil-south_os-north-europe_ig2ioz6j2vpcmz27nlqmfdrscijqeqnjv6ku3pkpte7pm53gxeal5hqd_700_9_session_32'):
                    #    continue

                    sessionKey = (sessionId, onionSessionId)
                    #if not(('client-brazil-south_os-australia-east_f2fv76wtuwdvbpci_400_4_session_34' in sessionId \
                    #        and 'client-brazil-south_os-australia-east_f2fv76wtuwdvbpci_400_4_session_34' in onionSessionId) or \
                    #        ('client-brazil-south_os-australia-east_f2fv76wtuwdvbpci_400_4_session_49' in sessionId and \
                    #        'client-brazil-south_os-australia-east_f2fv76wtuwdvbpci_400_4_session_49' in onionSessionId)):
                    #    continue
                    
                    #if not(('client-germany-west-central_os-north-europe_ig2ioz6j2vpcmz27nlqmfdrscijqeqnjv6ku3pkpte7pm53gxeal5hqd_700_9_session_44' in sessionId) \
                    #        and ('client-germany-west-central_os-north-europe_ig2ioz6j2vpcmz27nlqmfdrscijqeqnjv6ku3pkpte7pm53gxeal5hqd_700_9_session_44' in onionSessionId)):
                    #    continue

                    yPacketBytesInDict =  {}
                    yPacketCountInDict = {}
                    for bucket in buckets[sessionId]['buckets']:
                        yPacketBytesInDict[bucket] = 0
                    for bucket in buckets[sessionId]['buckets']:
                        yPacketCountInDict[bucket] = 0

                    for i in range(0, len(testPair['clientFlow']['sizesIn'])):
                        initial_ts = buckets[sessionId]['initialTs']
                        final_ts = buckets[sessionId]['finalTs']
                        ts = testPair['clientFlow']['timesInAbs'][i] # time in milliseconds
                        relativeTs = ts-initial_ts
                        bucket = int(relativeTs * 1000 / timeSamplingInterval)
                        
                        yPacketCountInDict[bucket] += 1
                        yPacketBytesInDict[bucket] += testPair['clientFlow']['sizesIn'][i]

                    yPacketBytesIn = list(yPacketBytesInDict.values())
                    yPacketCountIn = list(yPacketCountInDict.values())

                    allAbsTimes = testPair['clientFlow']['timesOutAbs'] + testPair['clientFlow']['timesInAbs']
                    absoluteInitialTime = min(allAbsTimes)
                    maxAbsoluteTime = max(allAbsTimes)

                    if sessionId not in client_rtts:
                        client_rtts[sessionId] = {'rtts': [absoluteInitialTime, maxAbsoluteTime], 'yPacketBytesIn': yPacketBytesIn, 'yPacketCountIn': yPacketCountIn, 'requestIds': [clientCapture]}
                    else:
                        # We need to keep track of which requests we already accounted for, otherwise we will be counting them more than one
                        if clientCapture not in client_rtts[sessionId]['requestIds']:
                            client_rtts[sessionId]['rtts'] += [absoluteInitialTime, maxAbsoluteTime]
                            client_rtts[sessionId]['yPacketBytesIn'] = np.add(client_rtts[sessionId]['yPacketBytesIn'], yPacketBytesIn)
                            client_rtts[sessionId]['yPacketCountIn'] = np.add(client_rtts[sessionId]['yPacketCountIn'], yPacketCountIn)
                            client_rtts[sessionId]['requestIds'] += [clientCapture]

                    # onion part
                    yPacketBytesOutOnionDict =  {}
                    yPacketCountOutOnionDict = {}
                    for bucket in buckets[sessionId]['buckets']:
                        yPacketBytesOutOnionDict[bucket] = 0
                    for bucket in buckets[sessionId]['buckets']:
                        yPacketCountOutOnionDict[bucket] = 0
                    for i in range(0, len(testPair['hsFlow']['sizesOut'])):
                        initial_ts = buckets[sessionId]['initialTs']
                        final_ts = buckets[sessionId]['finalTs']
                        ts = testPair['hsFlow']['timesOutAbs'][i] # time in milliseconds
                        # Outside of client flow's window
                        if ts < initial_ts or ts > final_ts:
                            continue
                        relativeTs = ts-initial_ts
                        bucket = int(relativeTs * 1000 / timeSamplingInterval)
                        
                        yPacketCountOutOnionDict[bucket] += 1
                        yPacketBytesOutOnionDict[bucket] += testPair['hsFlow']['sizesOut'][i]

                    yPacketBytesOutOnion = list(yPacketBytesOutOnionDict.values())
                    yPacketCountOutOnion = list(yPacketCountOutOnionDict.values())

                    if sessionId == onionSessionId:
                        label = 1
                    else:
                        label = 0

                    if sessionKey not in possible_request_combinations:
                        possible_request_combinations[sessionKey] = {'yPacketBytesOutOnion': yPacketBytesOutOnion, 'yPacketCountOutOnion': yPacketCountOutOnion, 'label': label, 'requestIds': [(clientCapture, onionCapture)]}
                    else:
                        onionRequestIds = [x[1] for x in possible_request_combinations[sessionKey]['requestIds']]
                        if onionCapture not in onionRequestIds:
                            possible_request_combinations[sessionKey]['yPacketBytesOutOnion'] = np.add(possible_request_combinations[sessionKey]['yPacketBytesOutOnion'], yPacketBytesOutOnion)
                            possible_request_combinations[sessionKey]['yPacketCountOutOnion'] = np.add(possible_request_combinations[sessionKey]['yPacketCountOutOnion'], yPacketCountOutOnion)  
                            possible_request_combinations[sessionKey]['requestIds'] += [(clientCapture, onionCapture)]

                #print("yPacketCountIn", yPacketCountIn)
                #packetListClients += yPacketCountIn
                #packetListOSes += yPacketCountOutOnion
                #packetListClients.append(yPacketCountIn)
                #packetListOSes.append(yPacketCountOutOnion)

    return possible_request_combinations, client_rtts, packetListClients, packetListOSes


# Do this only for 1 session, which is equivalent to 5 requests
# We multiply ts by 1000 because unix time comes in seconds and we want miliseconds
def getPacketTimes(testPairs):
    counter = 0
    n_requests = 5

    # These are hardcoded because the requests within a session are not ordered
    #min_ts_client = int(min(testPairs['correlated']['samples'][2]['clientFlow']['timesInAbs']) * 1000)
    #max_ts_client = int(max(testPairs['correlated']['samples'][4]['clientFlow']['timesInAbs']) * 1000)
    #min_ts_os = int(min(testPairs['correlated']['samples'][2]['hsFlow']['timesOutAbs']) * 1000)
    #max_ts_os = int(max(testPairs['correlated']['samples'][4]['hsFlow']['timesOutAbs']) * 1000)
    min_ts_client = int(min(testPairs['correlated']['samples'][2]['clientFlow']['timesInAbs']) * 1000)
    max_ts_client = int(max(testPairs['correlated']['samples'][4]['clientFlow']['timesInAbs']) * 1000)
    min_ts_os = int(min(testPairs['correlated']['samples'][2]['hsFlow']['timesOutAbs']) * 1000)
    max_ts_os = int(max(testPairs['correlated']['samples'][4]['hsFlow']['timesOutAbs']) * 1000)
    min_ts = min(min_ts_client, min_ts_os)
    max_ts = max(max_ts_client, max_ts_os)
    packetTimesClient = dict.fromkeys(range(min_ts, max_ts + 1), 0)
    packetTimesOS = dict.fromkeys(range(min_ts, max_ts + 1), 0)

    for testPair in testPairs['correlated']['samples']:
        if counter >= n_requests: continue
        counter += 1

        for ts in testPair['clientFlow']['timesInAbs']:
            ts = int(ts * 1000)
            packetTimesClient[ts] += 1

        for ts in testPair['hsFlow']['timesOutAbs']:
            ts = int(ts * 1000)
            packetTimesOS[ts] += 1

    return packetTimesClient, packetTimesOS


def getPacketCountBidirectionalTimePeriod(fileName, machineIp, first_ts_period, last_ts_period, buckets, timeSamplingInterval, direction = 'in', first_ts=0, guardNode=''):

    f = open(fileName, 'rb')

    try:
        pcap = dpkt.pcap.Reader(f)
    except dpkt.dpkt.NeedData:
        print("[*] pcap header is corrupted, skipping sample...")


    packetTimes = {}
    packetCount = {}
    packetDelays = []
    for bucket in buckets:
        packetCount[bucket] = 0

    #Read one by one
    packets = []
    i = 0
    while True:
        try:
            ts, buf = pcap.__next__()
            if ts > first_ts_period and ts < last_ts_period:
                packets.append([ts,buf])
                i += 1
        except Exception as e:
            #Break when we find a corrupted packet at the end of the capture
            #print("Stopped in packet %d from %s"%(i, sample))
            break

    if len(packets) == 0:
        return packetCount, -1, -1, packetTimes, packetDelays
        
    prev_ts = packets[0][0]
    first_ts = packets[0][0]
    last_ts = packets[len(packets)-1][0]
    for ts, buf in packets:
        try:
            eth = dpkt.ethernet.Ethernet(buf)
            if eth.type != dpkt.ethernet.ETH_TYPE_IP:
                continue

            ip_hdr = eth.data

            # Target TCP communication
            if (ip_hdr.p != 6):
                continue

            src_ip_addr_str = socket.inet_ntoa(ip_hdr.src)
            dst_ip_addr_str = socket.inet_ntoa(ip_hdr.dst)
            tcp = ip_hdr.data

            #Do not target packets produced due to synchronizing REST calls
            if(tcp.dport == 5005 or tcp.sport == 5005):
                continue

            # skip HTTP packets to manage Google Cloud instances
            if(tcp.dport == 80 or tcp.sport == 80):
                continue

            if(len(tcp.data) == 0):
                continue

            #Record initial timestamp
            if(first_ts == 0):
                first_ts = ts

            relativeTs = ts-first_ts_period
            bucket = int(relativeTs * 1000 / timeSamplingInterval)
           
            #skip out packets
            if src_ip_addr_str != machineIp and direction == 'out':
                continue
            if dst_ip_addr_str != machineIp and direction == 'in':
                continue
            
            if guardNode != '':
                if src_ip_addr_str != guardNode and dst_ip_addr_str != guardNode:
                    continue

            packetCount[bucket] += 1
            if relativeTs not in packetTimes:
                packetTimes[relativeTs] = 0
            packetTimes[relativeTs] += 1
            packetDelays.append(ts - prev_ts)

            prev_ts = ts

        except Exception as e:
            print('Error occurred while analyzing packets', e) #Uncomment to check what error is showing up when reading the pcap
            #Skip this corrupted packet
            continue
    f.close()

    return packetCount, first_ts, last_ts, packetTimes, packetDelays
