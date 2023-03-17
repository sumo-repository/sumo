from http.client import CONTINUE
import dpkt
import socket
import numpy as np
import pickle
import os


def generateBucketsEpochs(initialTs, lastTs, timeSamplingInterval):
    initialBucket = 0
    lastBucket = (((lastTs - initialTs) * 1000) // timeSamplingInterval) + 1
    
    return np.arange(initialBucket, lastBucket + 1)


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


def process_features_epochs_sessions_full_pipeline(testPairs, timeSamplingInterval, epoch_size, epoch_tolerance, earlyStop=None):
    possible_request_combinations = {}
    client_rtts = {}
    os_rtts = {}

    counter = 0

    missed_client_flows_full_pipeline = 0
    missed_os_flows_full_pipeline = 0

    full_pipeline_features_folder = 'full_pipeline_features/'
    alexa_features = pickle.load(open(full_pipeline_features_folder+'alexa_features.pickle', 'rb'))
    os_flows_full_pipeline = pickle.load(open('../source_separation/full_pipeline_features/os_features_source_separation_thr_0.9.pickle', 'rb'))
    client_flows_full_pipeline = pickle.load(open('../target_separation/full_pipeline_features/client_features_target_separation_thr_0.9.pickle', 'rb'))

    # absolute initial and final tses of the whole experience
    initial_ts_experience, last_ts_experience, buckets_clients, buckets_oses = getTsesAndBucketsEpochsSessions(testPairs, timeSamplingInterval)
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

        yPacketCountInDict = {}
        for bucket in buckets_clients[sessionId]['buckets']:
            yPacketCountInDict[bucket] = 0

        for i in range(0, len(testPair['clientFlow']['sizesIn'])):
            initial_ts = buckets_clients[sessionId]['initialTs']
            ts = testPair['clientFlow']['timesInAbs'][i] # time in milliseconds

            relativeTs = ts-initial_ts
            bucket = relativeTs * 1000 // timeSamplingInterval
            
            yPacketCountInDict[bucket] += 1

        yPacketCountIn = list(yPacketCountInDict.values())

        allAbsTimes = testPair['clientFlow']['timesOutAbs'] + testPair['clientFlow']['timesInAbs']
        absoluteInitialTime = min(allAbsTimes)
        maxAbsoluteTime = max(allAbsTimes)

        client_rtts[sessionId] = {'rtts': [absoluteInitialTime, maxAbsoluteTime], 'yPacketCountIn': yPacketCountIn, 'yPacketTimesIn': testPair['clientFlow']['timesInAbs']}

        # onion part
        yPacketTimesOutOnion = []
        for i in range(0, len(testPair['hsFlow']['sizesOut'])):
            yPacketTimesOutOnion.append(testPair['hsFlow']['timesOutAbs'][i])

        allAbsTimesOnion = testPair['hsFlow']['timesOutAbs'] + testPair['hsFlow']['timesInAbs']
        absoluteInitialTimeOnion = min(allAbsTimesOnion)
        maxAbsoluteTimeOnion = max(allAbsTimesOnion)
        
        os_rtts[sessionId] = {'rtts': [absoluteInitialTimeOnion, maxAbsoluteTimeOnion], 'yPacketTimesOutOnion': yPacketTimesOutOnion}
        
        counter += 1

    print("=== Finished gathering data on correlated pairs")

    alexa_counter = 0
    for alexaFlow in client_flows_full_pipeline.keys():
        # Gather the flows that were passed from the pipeline
        if 'alexa' in alexaFlow:
            #print("Alexa", alexaFlow)
            alexa_counter += 1

            key = alexaFlow.split(".pcap")[0]
            key = key.strip()

            for innerFolder in alexa_features[key]:
                if len(innerFolder) > 0:
                    for alexa_feature in innerFolder:
                        clientCapture = alexa_feature['clientFolder'].split("/")[-1]   
                        sessionId = clientCapture.split("_client")[0]
                        
                        yPacketCountInDict = {}
                        for bucket in buckets_alexa[sessionId]['buckets']:
                            yPacketCountInDict[bucket] = 0

                        for i in range(0, len(alexa_feature['clientFlow']['sizesIn'])):
                            initial_ts = buckets_alexa[sessionId]['initialTs']
                            ts = alexa_feature['clientFlow']['timesInAbs'][i] # time in milliseconds

                            relativeTs = ts-initial_ts
                            bucket = relativeTs * 1000 // timeSamplingInterval
                            
                            yPacketCountInDict[bucket] += 1

                        yPacketCountIn = list(yPacketCountInDict.values())

                        allAbsTimes = alexa_feature['clientFlow']['timesOutAbs'] + alexa_feature['clientFlow']['timesInAbs']
                        absoluteInitialTime = min(allAbsTimes)
                        maxAbsoluteTime = max(allAbsTimes)

                        client_rtts[sessionId] = {'rtts': [absoluteInitialTime, maxAbsoluteTime], 'yPacketCountIn': yPacketCountIn, 'yPacketTimesIn': alexa_feature['clientFlow']['timesInAbs']}
                        if 'alexa' in alexaFlow:
                            buckets_clients[sessionId] = buckets_alexa[sessionId]
    print("alexa_counter", alexa_counter)
    print("=== Finished gathering data on alexa captures that were misclassified in the filtering phase")

    counter = 0
    # Now we have a list of all possible client-side sessions and os-side sessions
    # and their respetive start and end times. So, now we group all possible
    # combinations per epoch
    for clientSessionId in client_rtts.keys():

        initial_epoch = buckets_clients[clientSessionId]['initialTs'] // epoch_size
        last_epoch = (buckets_clients[clientSessionId]['finalTs'] // epoch_size) + 1

        # Check which OSes are within the same epochs
        for osSessionId in os_rtts.keys():

            os_initial_epoch = buckets_oses[osSessionId]['initialTs'] // epoch_size
            os_last_epoch = (buckets_oses[osSessionId]['finalTs'] // epoch_size) + 1
            
            #(StartDate1 <= EndDate2) and (StartDate2 <= EndDate1)
            # Both flows overlap in epoch times, so we consider them a possible combination
            if (os_initial_epoch <= last_epoch) and (initial_epoch <= os_last_epoch):
            #if ((os_initial_epoch >= initial_epoch - epoch_tolerance) and (os_initial_epoch <= initial_epoch + epoch_tolerance)) and ((os_last_epoch >= last_epoch - epoch_tolerance) and (os_last_epoch <= last_epoch + epoch_tolerance)):
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

                yPacketCountOutOnionDict = {}
                yPacketCountInDict = {}
                for bucket in buckets_session:
                    yPacketCountOutOnionDict[bucket] = 0
                    yPacketCountInDict[bucket] = 0
                

                # onion
                for i in range(0, len(os_rtts[osSessionId]['yPacketTimesOutOnion'])):
                    ts = os_rtts[osSessionId]['yPacketTimesOutOnion'][i] # time in milliseconds

                    relativeTs = ts - initial_session_ts
                    bucket = relativeTs * 1000 // timeSamplingInterval
                        
                    yPacketCountOutOnionDict[bucket] += 1
                
                # client
                for i in range(0, len(client_rtts[clientSessionId]['yPacketTimesIn'])):
                    ts = client_rtts[clientSessionId]['yPacketTimesIn'][i] # time in milliseconds

                    relativeTs = ts - initial_session_ts
                    bucket = relativeTs * 1000 // timeSamplingInterval
                        
                    yPacketCountInDict[bucket] += 1


                # Here we place only the bucket range from the OS that makes sense to compare with the client
                possible_request_combinations[key] = {'yPacketCountOutOnion': list(yPacketCountOutOnionDict.values()), \
                                                        'yPacketCountIn': list(yPacketCountInDict.values()), 'label': label}

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

        clientCapture = testPair['clientFolder'].split("/")[-1]   
        sessionId = clientCapture.split("_client")[0]

        yPacketCountInDict = {}
        for bucket in buckets_clients[sessionId]['buckets']:
            yPacketCountInDict[bucket] = 0

        for i in range(0, len(testPair['clientFlow']['sizesIn'])):
            initial_ts = buckets_clients[sessionId]['initialTs']
            ts = testPair['clientFlow']['timesInAbs'][i] # time in milliseconds

            relativeTs = ts-initial_ts
            bucket = relativeTs * 1000 // timeSamplingInterval
            
            yPacketCountInDict[bucket] += 1

        yPacketCountIn = list(yPacketCountInDict.values())

        allAbsTimes = testPair['clientFlow']['timesOutAbs'] + testPair['clientFlow']['timesInAbs']
        absoluteInitialTime = min(allAbsTimes)
        maxAbsoluteTime = max(allAbsTimes)

        client_rtts[sessionId] = {'rtts': [absoluteInitialTime, maxAbsoluteTime], 'yPacketCountIn': yPacketCountIn, 'yPacketTimesIn': testPair['clientFlow']['timesInAbs']}

        # onion part
        yPacketTimesOutOnion = []
        for i in range(0, len(testPair['hsFlow']['sizesOut'])):
            yPacketTimesOutOnion.append(testPair['hsFlow']['timesOutAbs'][i])

        allAbsTimesOnion = testPair['hsFlow']['timesOutAbs'] + testPair['hsFlow']['timesInAbs']
        absoluteInitialTimeOnion = min(allAbsTimesOnion)
        maxAbsoluteTimeOnion = max(allAbsTimesOnion)
        
        os_rtts[sessionId] = {'rtts': [absoluteInitialTimeOnion, maxAbsoluteTimeOnion], 'yPacketTimesOutOnion': yPacketTimesOutOnion}

        counter += 1

    print("=== Finished gathering data on correlated pairs {}".format(counter))

    counter = 0
    # Now we have a list of all possible client-side sessions and os-side sessions
    # and their respetive start and end times. So, now we group all possible
    # combinations per epoch
    for clientSessionId in client_rtts.keys():

        initial_epoch = buckets_clients[clientSessionId]['initialTs'] // epoch_size
        last_epoch = (buckets_clients[clientSessionId]['finalTs'] // epoch_size) + 1

        # Check which OSes are within the same epochs
        for osSessionId in os_rtts.keys():

            os_initial_epoch = buckets_oses[osSessionId]['initialTs'] // epoch_size
            os_last_epoch = (buckets_oses[osSessionId]['finalTs'] // epoch_size) + 1
            
            #(StartDate1 <= EndDate2) and (StartDate2 <= EndDate1)
            # Both flows overlap in epoch times, so we consider them a possible combination
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

                yPacketCountOutOnionDict = {}
                yPacketCountInDict = {}
                for bucket in buckets_session:
                    yPacketCountOutOnionDict[bucket] = 0
                    yPacketCountInDict[bucket] = 0
                
                # onion
                for i in range(0, len(os_rtts[osSessionId]['yPacketTimesOutOnion'])):
                    ts = os_rtts[osSessionId]['yPacketTimesOutOnion'][i] # time in milliseconds

                    relativeTs = ts - initial_session_ts
                    bucket = relativeTs * 1000 // timeSamplingInterval
                        
                    yPacketCountOutOnionDict[bucket] += 1

                    if clientSessionId == 'client-frankfurt-2-new_os-finland-1-new_biden6qccqo5iqzvnjgpivp3owp2v5xodgwenqdh5wsq7zzfhnvodjqd_session_149' and osSessionId == 'client-singapore-1-new_os-singapore-1-new_dse6rlfwpgdohd33ulg623rpzy3zv5y5whfw23jznd3xu4o47vy6xmqd_session_143':
                        print("ts {}; relativeTs {}; bucket {}".format(ts, relativeTs, bucket))
                if clientSessionId == 'client-frankfurt-2-new_os-finland-1-new_biden6qccqo5iqzvnjgpivp3owp2v5xodgwenqdh5wsq7zzfhnvodjqd_session_149' and osSessionId == 'client-singapore-1-new_os-singapore-1-new_dse6rlfwpgdohd33ulg623rpzy3zv5y5whfw23jznd3xu4o47vy6xmqd_session_143':
                    print("yPacketCountOutOnionDict[bucket] {}".format(yPacketCountOutOnionDict[bucket]))
                
                # client
                for i in range(0, len(client_rtts[clientSessionId]['yPacketTimesIn'])):
                    ts = client_rtts[clientSessionId]['yPacketTimesIn'][i] # time in milliseconds

                    relativeTs = ts - initial_session_ts
                    bucket = relativeTs * 1000 // timeSamplingInterval
                        
                    yPacketCountInDict[bucket] += 1
        

                # Here we place only the bucket range from the OS that makes sense to compare with the client
                possible_request_combinations[key] = {'yPacketCountOutOnion': list(yPacketCountOutOnionDict.values()), \
                                                        'yPacketCountIn': list(yPacketCountInDict.values()), 'label': label}

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

        yPacketCountInDict = {}
        for bucket in buckets_clients[sessionId]['buckets']:
            yPacketCountInDict[bucket] = 0

        for i in range(0, len(testPair['clientFlow']['sizesIn'])):
            initial_ts = buckets_clients[sessionId]['initialTs']
            ts = testPair['clientFlow']['timesInAbs'][i] # time in milliseconds

            relativeTs = ts-initial_ts
            bucket = relativeTs * 1000 // timeSamplingInterval
            
            yPacketCountInDict[bucket] += 1

        yPacketCountIn = list(yPacketCountInDict.values())

        allAbsTimes = testPair['clientFlow']['timesOutAbs'] + testPair['clientFlow']['timesInAbs']
        absoluteInitialTime = min(allAbsTimes)
        maxAbsoluteTime = max(allAbsTimes)

        if sessionId not in client_rtts:
            client_rtts[sessionId] = {'rtts': [absoluteInitialTime, maxAbsoluteTime], 'yPacketCountIn': yPacketCountIn, 'requestIds': [clientCapture], 'yPacketTimesIn': testPair['clientFlow']['timesInAbs']}
        else:
            if clientCapture not in client_rtts[sessionId]['requestIds']:
                client_rtts[sessionId]['rtts'] += [absoluteInitialTime, maxAbsoluteTime]
                client_rtts[sessionId]['yPacketCountIn'] = np.add(client_rtts[sessionId]['yPacketCountIn'], yPacketCountIn)
                client_rtts[sessionId]['requestIds'] += [clientCapture]
                client_rtts[sessionId]['yPacketTimesIn'] += testPair['clientFlow']['timesInAbs']

        # onion part
        yPacketTimesOutOnion = []
        for i in range(0, len(testPair['hsFlow']['sizesOut'])):
            yPacketTimesOutOnion.append(testPair['hsFlow']['timesOutAbs'][i])

        allAbsTimesOnion = testPair['hsFlow']['timesOutAbs'] + testPair['hsFlow']['timesInAbs']
        absoluteInitialTimeOnion = min(allAbsTimesOnion)
        maxAbsoluteTimeOnion = max(allAbsTimesOnion)
        
        if sessionId not in os_rtts:
            os_rtts[sessionId] = {'rtts': [absoluteInitialTimeOnion, maxAbsoluteTimeOnion], 'yPacketTimesOutOnion': yPacketTimesOutOnion, 'requestIds': [onionCapture]}
        else:
            if onionCapture not in os_rtts[sessionId]['requestIds']:
                os_rtts[sessionId]['rtts'] += [absoluteInitialTimeOnion, maxAbsoluteTimeOnion]
                os_rtts[sessionId]['yPacketTimesOutOnion'] += yPacketTimesOutOnion
                os_rtts[sessionId]['requestIds'] += [onionCapture]

        counter += 1

    print("=== Finished gathering data on correlated pairs")
    counter = 0
    # Now we have a list of all possible client-side sessions and os-side sessions
    # and their respetive start and end times. So, now we group all possible
    # combinations per epoch
    for clientSessionId in client_rtts.keys():

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

                yPacketCountOutOnionDict = {}
                yPacketCountInDict = {}
                for bucket in buckets_session:
                    yPacketCountOutOnionDict[bucket] = 0
                    yPacketCountInDict[bucket] = 0
                

                # onion
                for i in range(0, len(os_rtts[osSessionId]['yPacketTimesOutOnion'])):
                    ts = os_rtts[osSessionId]['yPacketTimesOutOnion'][i] # time in milliseconds

                    relativeTs = ts - initial_session_ts
                    bucket = relativeTs * 1000 // timeSamplingInterval
                        
                    yPacketCountOutOnionDict[bucket] += 1
                
                # client
                for i in range(0, len(client_rtts[clientSessionId]['yPacketTimesIn'])):
                    ts = client_rtts[clientSessionId]['yPacketTimesIn'][i] # time in milliseconds

                    relativeTs = ts - initial_session_ts
                    bucket = relativeTs * 1000 // timeSamplingInterval
                        
                    yPacketCountInDict[bucket] += 1

                # Here we place only the bucket range from the OS that makes sense to compare with the client
                possible_request_combinations[key] = {'yPacketCountOutOnion': list(yPacketCountOutOnionDict.values()), \
                                                        'yPacketCountIn': list(yPacketCountInDict.values()), 'label': label}

        counter += 1

    return possible_request_combinations, client_rtts, os_rtts


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

        yPacketCountInDict = {}
        for bucket in buckets_clients[requestId]['buckets']:
            yPacketCountInDict[bucket] = 0

        for i in range(0, len(testPair['clientFlow']['sizesIn'])):
            initial_ts = buckets_clients[requestId]['initialTs']
            ts = testPair['clientFlow']['timesInAbs'][i] # time in milliseconds

            relativeTs = ts-initial_ts
            bucket = relativeTs * 1000 // timeSamplingInterval
            
            yPacketCountInDict[bucket] += 1

        yPacketCountIn = list(yPacketCountInDict.values())

        allAbsTimes = testPair['clientFlow']['timesOutAbs'] + testPair['clientFlow']['timesInAbs']
        absoluteInitialTime = min(allAbsTimes)
        maxAbsoluteTime = max(allAbsTimes)

        client_rtts[requestId] = {'rtts': [absoluteInitialTime, maxAbsoluteTime], 'yPacketCountIn': yPacketCountIn, 'requestIds': [clientCapture], 'yPacketTimesIn': testPair['clientFlow']['timesInAbs']}

        # onion part
        yPacketTimesOutOnion = []
        for i in range(0, len(testPair['hsFlow']['sizesOut'])):
            yPacketTimesOutOnion.append(testPair['hsFlow']['timesOutAbs'][i])

        allAbsTimesOnion = testPair['hsFlow']['timesOutAbs'] + testPair['hsFlow']['timesInAbs']
        absoluteInitialTimeOnion = min(allAbsTimesOnion)
        maxAbsoluteTimeOnion = max(allAbsTimesOnion)
        
        os_rtts[requestId] = {'rtts': [absoluteInitialTimeOnion, maxAbsoluteTimeOnion], 'yPacketTimesOutOnion': yPacketTimesOutOnion, 'requestIds': [onionCapture]}

        counter += 1

    print("=== Finished gathering data on correlated pairs")
    counter = 0

    test_samples_file = open('d1.0_ws1.6_nw5_thr10_tl200_el300_nt500_test_files.txt', 'r')
    test_samples = test_samples_file.readlines()
    test_samples_file.close()

    count_correlated = 0
    for clientSample in test_samples:
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

            yPacketCountOutOnionDict = {}
            yPacketCountInDict = {}
            for bucket in buckets_session:
                yPacketCountOutOnionDict[bucket] = 0
                yPacketCountInDict[bucket] = 0
                

            # onion
            for i in range(0, len(os_rtts[osRequestId]['yPacketTimesOutOnion'])):
                ts = os_rtts[osRequestId]['yPacketTimesOutOnion'][i] # time in milliseconds

                relativeTs = ts - initial_session_ts
                bucket = relativeTs * 1000 // timeSamplingInterval
                    
                yPacketCountOutOnionDict[bucket] += 1
            
            # client
            for i in range(0, len(client_rtts[clientRequestId]['yPacketTimesIn'])):
                ts = client_rtts[clientRequestId]['yPacketTimesIn'][i] # time in milliseconds

                relativeTs = ts - initial_session_ts
                bucket = relativeTs * 1000 // timeSamplingInterval
                    
                yPacketCountInDict[bucket] += 1


            # Here we place only the bucket range from the OS that makes sense to compare with the client
            possible_request_combinations[key] = {'yPacketCountOutOnion': list(yPacketCountOutOnionDict.values()), \
                                                    'yPacketCountIn': list(yPacketCountInDict.values()), 'label': label}

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

        yPacketCountInDict = {}

        for bucket in buckets_clients[requestId]['buckets']:
            yPacketCountInDict[bucket] = 0

        packets_in_client = testPair['here'][1]['<-']
        for i in range(0, len(packets_in_client)):
            initial_ts = buckets_clients[requestId]['initialTs']
            ts = buckets_clients[requestId]['tses'][i] # time in milliseconds

            relativeTs = ts-initial_ts
            bucket = relativeTs * 1000 // timeSamplingInterval
            
            yPacketCountInDict[bucket] += 1

        yPacketCountIn = list(yPacketCountInDict.values())

        allAbsTimes = buckets_clients[requestId]['tses']
        absoluteInitialTime = min(allAbsTimes)
        maxAbsoluteTime = max(allAbsTimes)

        client_rtts[requestId] = {'rtts': [absoluteInitialTime, maxAbsoluteTime], 'yPacketCountIn': yPacketCountIn, 'requestIds': [clientCapture], 'yPacketTimesIn': buckets_clients[requestId]['tses']}

        # onion part
        packets_in_os = testPair['there'][1]['->']
        yPacketTimesOutOnion = []
        for i in range(0, len(packets_in_os)):
            yPacketTimesOutOnion.append(buckets_oses[requestId]['tses'][i])

        allAbsTimesOnion = buckets_oses[requestId]['tses']
        absoluteInitialTimeOnion = min(allAbsTimesOnion)
        maxAbsoluteTimeOnion = max(allAbsTimesOnion)
        
        os_rtts[requestId] = {'rtts': [absoluteInitialTimeOnion, maxAbsoluteTimeOnion], 'yPacketTimesOutOnion': buckets_oses[requestId]['tses']}

        counter += 1

    print("=== Finished gathering data on correlated pairs", counter)
    counter = 0


    count_correlated = 0
    for client_idx, clientRequestId in enumerate(client_rtts.keys()):
        for onion_idx, osRequestId in enumerate(os_rtts.keys()):
            key = (clientRequestId, osRequestId)
            label = 0
            if clientRequestId == osRequestId:
                label = 1
                count_correlated += 1
                   
            initial_session_ts = min(buckets_clients[clientRequestId]['initialTs'], buckets_oses[osRequestId]['initialTs'])
            final_session_ts = max(buckets_clients[clientRequestId]['finalTs'], buckets_oses[osRequestId]['finalTs'])
            buckets_session = generateBucketsEpochs(initial_session_ts, final_session_ts, timeSamplingInterval)

            yPacketCountOutOnionDict = {}
            yPacketCountInDict = {}
            for bucket in buckets_session:
                yPacketCountOutOnionDict[bucket] = 0
                yPacketCountInDict[bucket] = 0
                

            # onion
            for i in range(0, len(os_rtts[osRequestId]['yPacketTimesOutOnion'])):
                ts = os_rtts[osRequestId]['yPacketTimesOutOnion'][i] # time in milliseconds

                relativeTs = ts - initial_session_ts
                bucket = relativeTs * 1000 // timeSamplingInterval
                    
                yPacketCountOutOnionDict[bucket] += 1


            # client
            for i in range(0, len(client_rtts[clientRequestId]['yPacketTimesIn'])):
                ts = client_rtts[clientRequestId]['yPacketTimesIn'][i] # time in milliseconds

                relativeTs = ts - initial_session_ts
                bucket = relativeTs * 1000 // timeSamplingInterval
                    
                yPacketCountInDict[bucket] += 1


            # Here we place only the bucket range from the OS that makes sense to compare with the client
            possible_request_combinations[key] = {'yPacketCountOutOnion': list(yPacketCountOutOnionDict.values()), \
                                                    'yPacketCountIn': list(yPacketCountInDict.values()), 'label': label}
            
        counter += 1

    return possible_request_combinations, client_rtts, os_rtts