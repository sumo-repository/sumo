import numpy as np
import pickle


def generateBucketsEpochs(initialTs, lastTs, timeSamplingInterval):
    initialBucket = 0
    lastBucket = (((lastTs - initialTs) * 1000) // timeSamplingInterval) + 1
    
    return np.arange(initialBucket, lastBucket + 1)


def getTsesAndBucketsEpochsSessionsAlexa(alexaFeatures, timeSamplingInterval):
    tses = []
    buckets_clients = {}

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


def process_features_epochs_sessions_full_pipeline(testPairs, timeSamplingInterval, epoch_size, epoch_tolerance, earlyStop=None):
    possible_request_combinations = {}
    client_rtts = {}
    os_rtts = {}

    counter = 0

    missed_client_flows_full_pipeline = 0
    missed_os_flows_full_pipeline = 0

    alexa_features = pickle.load(open('alexa_fatures.pickle', 'rb'))
    client_flows_full_pipeline = pickle.load(open('client_features_target_separation.pickle', 'rb'))
    os_flows_full_pipeline = pickle.load(open('os_features_source_separation.pickle', 'rb'))

    # absolute initial and final tses of the whole experience
    initial_ts_experience, last_ts_experience, buckets_clients, buckets_oses = getTsesAndBucketsEpochsSessions(testPairs, timeSamplingInterval)
    # TODO extract buckets for alexa captures
    buckets_alexa = getTsesAndBucketsEpochsSessionsAlexa(alexa_features, timeSamplingInterval)

    print("=== Finished organizing buckets")
    for testPair in testPairs['correlated']['samples']:

        clientCapture = testPair['clientFolder'].split("/")[-1]   
        sessionId = clientCapture.split("_client")[0]

        key = " " + sessionId + "_client.pcap"
        if key not in client_flows_full_pipeline.keys():
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
                
                # Here we place only the bucket range from the OS that makes sense to compare with the client
                possible_request_combinations[key] = {'yPacketBytesOutOnion': list(yPacketBytesOutOnionDict.values()), 'yPacketCountOutOnion': list(yPacketCountOutOnionDict.values()), \
                                                        'yPacketBytesIn': list(yPacketBytesInDict.values()), 'yPacketCountIn': list(yPacketCountInDict.values()), 'label': label}
                
        counter += 1

    return possible_request_combinations, client_rtts, os_rtts

