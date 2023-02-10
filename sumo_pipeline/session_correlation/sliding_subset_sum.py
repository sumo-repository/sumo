import numpy as np
import pickle
from typing import List, Dict, Tuple
import sys
import pandas as pd
from os.path import isfile

import feature_collection
import process_results


np.set_printoptions(threshold=sys.maxsize)
np.set_printoptions(suppress=True)


# TODO: Parameters to set that influence the results
epoch_size = 10 # seconds
epoch_tolerance = 8
timeSamplingInterval = 500 # ms
window_size = (2 * timeSamplingInterval) / 1000 # seconds
overlap = 500 / 1000 # seconds -> 1
min_session_duration_debug = int(30 * 1000 / 500) # in buckets -> 20 seconds

min_session_durations = np.arange(0, 25, 1)
min_session_durations *= 60 # minutes to seconds

deltas = [60]
thresholds = [-0.05]

buckets_per_window = int(window_size / (timeSamplingInterval / 1000))
buckets_overlap = int(overlap / (timeSamplingInterval / 1000))


IS_2D_OPENCL_IMPL = False
if IS_2D_OPENCL_IMPL == False:
    import mySubsetSumOpenCL as my_subset_sum
else:
    import mySubsetSumOpenCL2D as my_subset_sum


def pre_process(is_full_pipeline):

    datasetName = 'OSTest'
    testPairs = pickle.load(open('testPairs_{}'.format(datasetName), 'rb'))

    is_full_pipeline = False
    if is_full_pipeline == True:
        datasetName += 'full_pipeline'

    possible_request_combinations_file = 'possible_request_combinations_{}.pickle'.format(datasetName)
    clients_rtts_file = 'clients_rtts_{}.pickle'.format(datasetName)
    oses_rtts_file = 'oses_rtts_{}.pickle'.format(datasetName)

    # ---------------------- Data pre-processing ----------------------
    if isfile(possible_request_combinations_file) and isfile(clients_rtts_file) and isfile(oses_rtts_file):
        print("==== Gathering pre-processed data from file...")
        possible_request_combinations = pickle.load(open(possible_request_combinations_file, "rb"))
        clients_rtts = pickle.load(open(clients_rtts_file, "rb"))
        oses_rtts = pickle.load(open(oses_rtts_file, "rb"))
    else: 
        if is_full_pipeline == False:
            possible_request_combinations, clients_rtts, oses_rtts = feature_collection.process_features_epochs_sessions(testPairs, timeSamplingInterval, epoch_size, epoch_tolerance)
        else:
            possible_request_combinations, clients_rtts, oses_rtts, missed_client_flows_full_pipeline, missed_os_flows_full_pipeline = feature_collection.process_features_epochs_sessions_full_pipeline(testPairs, timeSamplingInterval, epoch_size, epoch_tolerance)

        pickle.dump(possible_request_combinations, open(possible_request_combinations_file, 'wb'))
        pickle.dump(clients_rtts, open(clients_rtts_file, 'wb'))
        pickle.dump(oses_rtts, open(oses_rtts_file, 'wb'))


    print("==== After pre-processing data")

    if is_full_pipeline == True:    
        return possible_request_combinations, clients_rtts, oses_rtts, missed_client_flows_full_pipeline, missed_os_flows_full_pipeline
    else:
        return possible_request_combinations, clients_rtts, oses_rtts, 0, 0


def get_buckets_and_windows(possible_request_combinations):
    # ------------------- Preparing for subset sum -----------------
    # These are only auxiliary structures so that we do not need to keep counting them every time
    session_buckets = {}
    session_windows = {}
    for key in possible_request_combinations.keys():
    
        buckets = len(possible_request_combinations[key]['yPacketCountIn'])
        session_buckets[key] = buckets
        session_windows[key] = process_results.getWindowsCount(buckets, buckets_per_window, buckets_overlap)

    return session_buckets, session_windows


def calculate_final_score(scores_per_window):
    seq_penalty = 0
    seq_gain = 0
    score = 0
    for window, score in scores_per_window:
        if score == 1:
            seq_penalty = 0
            score += (1 + 0.1 * seq_gain)
            seq_gain += 1

        elif score == -1:
            seq_gain = 0
            score -= (1 + 0.1 * seq_penalty)
            seq_penalty += 1

    return score


def run_windowed_subset_sum_on_all_pairs(delta, possible_request_combinations, clients_rtts, oses_rtts, session_buckets, session_windows):
    packetListClients = []
    packetListOSes = []
    nBuckets = []
    nWindows = []

    # The structure of each entry is (clientSessionId, osSessionId): [(window1, score1), ... (windown, scoren)]
    database: Dict[Tuple[str, str], List[Tuple[int, int]]] = {} 

    count_pairs = 0
    if IS_2D_OPENCL_IMPL == False:
        keys = list(possible_request_combinations.keys())
        max_windows_per_pair = -1
        count_alexa = 0
        count_oses = 0
        count_correlated = 0
        for clientSessionId, osSessionId in keys:

            if clientSessionId == osSessionId:
                count_correlated += 1
            if 'alexa' in clientSessionId:
                count_alexa += 1
            else:
                count_oses += 1
            # We don't even have enough data for a full window
            if session_buckets[(clientSessionId, osSessionId)] < buckets_per_window:
                possible_request_combinations.pop((clientSessionId, osSessionId))
                continue
            
            packetListClients.append(list(possible_request_combinations[(clientSessionId, osSessionId)]['yPacketCountIn']))
            packetListOSes.append(list(possible_request_combinations[(clientSessionId, osSessionId)]['yPacketCountOutOnion']))

            nBuckets.append(session_buckets[(clientSessionId, osSessionId)])
            nWindows.append(session_windows[(clientSessionId, osSessionId)])

            if session_windows[(clientSessionId, osSessionId)] > max_windows_per_pair:
                max_windows_per_pair = session_windows[(clientSessionId, osSessionId)]

            count_pairs += 1

        scores = my_subset_sum.whole_loop_subset_sum(packetListClients, packetListOSes, len(packetListClients), nBuckets, delta, buckets_per_window, buckets_overlap, nWindows)
        
        counter = 0
        for start, (clientSessionId, osSessionId) in enumerate(possible_request_combinations.keys()):
            if start >= len(scores):
                continue
            for j in range(0, session_windows[(clientSessionId, osSessionId)]):
                key = (clientSessionId, osSessionId)
                if key not in database:
                    database[key] = []
                deltaKey = (delta, clientSessionId, osSessionId)
                if deltaKey not in databaseMultipleDeltas:
                    databaseMultipleDeltas[deltaKey] = []
                database[key].append((j, scores[start].scores[j]))
                databaseMultipleDeltas[(delta, clientSessionId, osSessionId)].append((j, scores[start].scores[j]))

            counter += 1

    # OpenCL 2D implementation
    else:
        keys = list(possible_request_combinations.keys())

        for clientSessionId, osSessionId in keys:
            
            # We don't even have enough data for a full window
            if session_buckets[(clientSessionId, osSessionId)] < buckets_per_window:
                possible_request_combinations.pop((clientSessionId, osSessionId))
                continue
            
            packetListClients += list(possible_request_combinations[(clientSessionId, osSessionId)]['yPacketCountIn'])
            packetListOSes += list(possible_request_combinations[(clientSessionId, osSessionId)]['yPacketCountOutOnion'])

            nBuckets.append(session_buckets[(clientSessionId, osSessionId)])
            nWindows.append(session_windows[(clientSessionId, osSessionId)])
            count_pairs += 1

        acc = 0
        acc_windows = [acc]
        for i in range(1, len(nWindows)):
            acc += nWindows[i - 1]
            acc_windows.append(acc)

        scores = my_subset_sum.whole_loop_subset_sum(packetListClients, packetListOSes, count_pairs, nBuckets, delta, buckets_per_window, buckets_overlap, nWindows, acc_windows)

        count_windows = 0
        for start, (clientSessionId, osSessionId) in enumerate(possible_request_combinations.keys()):
            #windows = client_windows[clientSessionId]
            if start >= len(acc_windows):
                continue
            for j in range(0, session_windows[(clientSessionId, osSessionId)]):
                key = (clientSessionId, osSessionId)
                if key not in database:
                    database[key] = []
                deltaKey = (delta, clientSessionId, osSessionId)
                if deltaKey not in databaseMultipleDeltas:
                    databaseMultipleDeltas[deltaKey] = []
                count_windows += 1
                database[key].append((j, scores[acc_windows[start] + j]))
                databaseMultipleDeltas[(delta, clientSessionId, osSessionId)].append((j, scores[acc_windows[start] + j]))

    return database, databaseMultipleDeltas


def fpr(mapEntry):
    if mapEntry['fp'] + mapEntry['tn'] == 0:
        return 0
    else:
        return mapEntry['fp'] / (mapEntry['fp'] + mapEntry['tn'])


def fnr(mapEntry):
    if mapEntry['fn'] + mapEntry['tp'] == 0:
        return 0
    else:
        return mapEntry['fn'] / (mapEntry['fn'] + mapEntry['tp'])


def precision(mapEntry):
    if mapEntry['tp'] + mapEntry['fp'] == 0:
        return 0
    else:
        return mapEntry['tp'] / (mapEntry['tp'] + mapEntry['fp'])
    

def recall(mapEntry):
    if mapEntry['tp'] + mapEntry['fn'] == 0:
        return 0
    else:
        return mapEntry['tp'] / (mapEntry['tp'] + mapEntry['fn'])
            

def f1_score(mapEntry):
    if mapEntry['precision'] + mapEntry['recall'] == 0:
        return 0
    else:
        return (2 * mapEntry['precision'] * mapEntry['recall']) / (mapEntry['precision'] + mapEntry['recall'])


# ---------------------- Windowed subset sum ----------------------

# The structure of each entry is (delta, clientSessionId, osSessionId): [(window1, score1), ... (windown, scoren)]
databaseMultipleDeltas: Dict[Tuple[int, str, str], List[Tuple[int, int]]] = {} 
score_counter = {}


# print("nb deltas={}, {}".format(len(deltas), deltas))
def find_correlated_sessions(possible_request_combinations, clients_rtts, oses_rtts, session_buckets, session_windows, missed_client_flows_full_pipeline, missed_os_flows_full_pipeline):
    
    for delta in deltas:
        print("\n======================== Delta {} ========================\n".format(delta))
        
        database, databaseMultipleDeltas = run_windowed_subset_sum_on_all_pairs(delta, possible_request_combinations, clients_rtts, oses_rtts, session_buckets, session_windows)

        # ---------------------- Calculate overall score ----------------------
        windows_with_packets, score_counter[delta], scores_per_session = process_results.calculate_overall_score(possible_request_combinations, database, buckets_per_window, buckets_overlap)

        print("=== After calculating overall score")

        #print("***** score_counter", score_counter)
        correlated_scores = []
        uncorrelated_scores = []
        metricsMap = {}
        metricsMapFinalScores = {}
        metricsMapFinalScoresPerSession = {}
        metricsMapScoreCounter = {}
        metricsMapPerSessionPerOS = {}
        metricsMapPerSessionPerClient = {}
        metricsMapPerOS = {}
        metricsMapMoreSessions = {} # Just for debug
        fpSessions = {}

        for threshold in thresholds:
            print("Evaluating threshold {}".format(threshold))
            metricsMap[threshold] = {'tp': 0, 'tn': 0, 'fp': 0, 'fn': missed_client_flows_full_pipeline + missed_os_flows_full_pipeline}
            metricsMapFinalScores[threshold] = {'tp': 0, 'tn': 0, 'fp': 0, 'fn': missed_client_flows_full_pipeline + missed_os_flows_full_pipeline}
            metricsMapFinalScoresPerSession[threshold] = {}
            metricsMapPerOS[threshold] = {}
            metricsMapScoreCounter[threshold] = {'tp': [], 'tn': [], 'fp': [], 'fn': []}
            metricsMapPerSessionPerOS[threshold] = {}
            metricsMapPerSessionPerClient[threshold] = {}
            metricsMapMoreSessions[threshold] = {'tp': 0, 'tn': 0, 'fp': 0, 'fn': missed_client_flows_full_pipeline + missed_os_flows_full_pipeline, 'notEnoughRequests': 0}
            fpSessions[threshold] = {}
            index = 0
            for key, value in score_counter[delta].items(): 
                clientSessionId = key[0]
                osSessionId = key[1]
                
                final_score = calculate_final_score(database[key]) / session_windows[key]
                
                
                if len(possible_request_combinations[key]['yPacketCountOutOnion']) < min_session_duration_debug:
                    metricsMapMoreSessions[threshold]['notEnoughRequests'] += 1
                
                if osSessionId not in metricsMapPerSessionPerOS[threshold]:
                    metricsMapPerSessionPerOS[threshold][osSessionId] = {}
                metricsMapPerSessionPerOS[threshold][osSessionId][clientSessionId] = final_score
                
                if clientSessionId not in metricsMapPerSessionPerClient[threshold]:
                    metricsMapPerSessionPerClient[threshold][clientSessionId] = {}
                metricsMapPerSessionPerClient[threshold][clientSessionId][osSessionId] = final_score

                if clientSessionId == osSessionId:
                    correlated_scores.append(final_score)
                else:
                    uncorrelated_scores.append(final_score)
                
                if final_score >= threshold:
                    if clientSessionId == osSessionId:
                        metricsMap[threshold]['tp'] += 1
                        metricsMapScoreCounter[threshold]['tp'].append(score_counter[delta][key])
                        if len(possible_request_combinations[key]['yPacketCountOutOnion']) >= min_session_duration_debug:
                            metricsMapMoreSessions[threshold]['tp'] += 1
                    else:
                        metricsMap[threshold]['fp'] += 1
                        metricsMapScoreCounter[threshold]['fp'].append(score_counter[delta][key])
                        if len(possible_request_combinations[key]['yPacketCountOutOnion']) >= min_session_duration_debug:
                            metricsMapMoreSessions[threshold]['fp'] += 1
                        
                else:
                    if clientSessionId == osSessionId:
                        metricsMap[threshold]['fn'] += 1
                        metricsMapScoreCounter[threshold]['fn'].append(score_counter[delta][key])
                        if len(possible_request_combinations[key]['yPacketCountOutOnion']) >= min_session_duration_debug:
                            metricsMapMoreSessions[threshold]['fn'] += 1

                    else:
                        metricsMap[threshold]['tn'] += 1
                        metricsMapScoreCounter[threshold]['tn'].append(score_counter[delta][key])
                        if len(possible_request_combinations[key]['yPacketCountOutOnion']) >= min_session_duration_debug:
                            metricsMapMoreSessions[threshold]['tn'] += 1


            # Calculate precision, recall, f1-score, ...
            metricsMap[threshold]['precision'] = precision(metricsMap[threshold])
            metricsMap[threshold]['recall'] = recall(metricsMap[threshold])
            metricsMap[threshold]['fpr'] = fpr(metricsMap[threshold])
            metricsMap[threshold]['fnr'] = fnr(metricsMap[threshold])
            metricsMap[threshold]['f1-score'] = f1_score(metricsMap[threshold])

            index += 1


            client_sessions_with_highest_scores = process_results.count_client_correlated_sessions_highest_score(metricsMapPerSessionPerClient[threshold], threshold)
            for clientSessionId, osSessionId in possible_request_combinations.keys():
                osName = osSessionId.split("_")[1]
                if osName not in metricsMapPerOS[threshold]:
                    metricsMapPerOS[threshold][osName] = {'tp': 0, 'tn': 0, 'fp': 0, 'fn': 0}
                if osSessionId not in metricsMapFinalScoresPerSession[threshold]:
                    metricsMapFinalScoresPerSession[threshold][osSessionId] = {'tp': 0, 'tn': 0, 'fp': 0, 'fn': 0}

                if clientSessionId == osSessionId:
                    if client_sessions_with_highest_scores[clientSessionId]['correlatedHighestScore']:
                        metricsMapFinalScoresPerSession[threshold][osSessionId]['tp'] += 1
                        metricsMapFinalScores[threshold]['tp'] += 1
                        metricsMapPerOS[threshold][osName]['tp'] += 1
                    else:
                        metricsMapFinalScoresPerSession[threshold][osSessionId]['fn'] += 1
                        metricsMapFinalScores[threshold]['fn'] += 1
                        metricsMapPerOS[threshold][osName]['fn'] += 1
                else:
                    if client_sessions_with_highest_scores[clientSessionId]['falseHighestScore'] and client_sessions_with_highest_scores[clientSessionId]['falseSession'] == osSessionId:
                        metricsMapFinalScoresPerSession[threshold][osSessionId]['fp'] += 1
                        metricsMapFinalScores[threshold]['fp'] += 1
                        metricsMapPerOS[threshold][osName]['fp'] += 1
                        key = (clientSessionId, osSessionId)

                    else:
                        metricsMapFinalScoresPerSession[threshold][osSessionId]['tn'] += 1
                        metricsMapFinalScores[threshold]['tn'] += 1
                        metricsMapPerOS[threshold][osName]['tn'] += 1
        

            # Calculate precision, recall, f1-score, ...
            metricsMapFinalScores[threshold]['precision'] = precision(metricsMapFinalScores[threshold])
            metricsMapFinalScores[threshold]['recall'] = recall(metricsMapFinalScores[threshold])
            metricsMapFinalScores[threshold]['fpr'] = fpr(metricsMapFinalScores[threshold])
            metricsMapFinalScores[threshold]['fnr'] = fnr(metricsMapFinalScores[threshold])
            metricsMapFinalScores[threshold]['f1-score'] = f1_score(metricsMapFinalScores[threshold])
            
            #print("metricsMapPerOS[threshold]", metricsMapPerOS[threshold])
            for osName in metricsMapPerOS[threshold].keys():
                metricsMapPerOS[threshold][osName]['precision'] = precision(metricsMapPerOS[threshold][osName])
                metricsMapPerOS[threshold][osName]['recall'] = recall(metricsMapPerOS[threshold][osName])
                metricsMapPerOS[threshold][osName]['fpr'] = fpr(metricsMapPerOS[threshold][osName])
                metricsMapPerOS[threshold][osName]['fnr'] = fnr(metricsMapPerOS[threshold][osName])
                metricsMapPerOS[threshold][osName]['f1-score'] = f1_score(metricsMapPerOS[threshold][osName])

        return metricsMap, metricsMapFinalScores, metricsMapPerOS, metricsMapPerSessionPerClient, metricsMapFinalScoresPerSession


def get_session_duration(clients_rtts, clientSessionId):
    return clients_rtts[clientSessionId]['rtts'][1] - clients_rtts[clientSessionId]['rtts'][0] 


def evaluate(possible_request_combinations, clients_rtts, metricsMapFinalScores, metricsMapPerSessionPerClient, metricsMapFinalScoresPerSession, missed_client_flows_full_pipeline, missed_os_flows_full_pipeline):
    results_by_min_duration = {}
    for threshold in thresholds:
        results_by_min_duration[threshold] = {}
        for min_session_duration in min_session_durations:
            total_sessions_analyzed = 0

            client_sessions_with_highest_scores = process_results.count_client_correlated_sessions_highest_score(metricsMapPerSessionPerClient[threshold], threshold)
            results_by_min_duration[threshold][min_session_duration] = {'tp': 0, 'tn': 0, 'fp': 0, 'fn': missed_client_flows_full_pipeline + missed_os_flows_full_pipeline}
            for clientSessionId, osSessionId in possible_request_combinations.keys():
                duration = get_session_duration(clients_rtts, clientSessionId)

                if duration < min_session_duration:
                    if clientSessionId == osSessionId:
                        results_by_min_duration[threshold][min_session_duration]['fn'] += 1
                    else:
                        results_by_min_duration[threshold][min_session_duration]['tn'] += 1
                    continue
                total_sessions_analyzed += 1

                if clientSessionId == osSessionId:
                    if client_sessions_with_highest_scores[clientSessionId]['correlatedHighestScore']:
                        results_by_min_duration[threshold][min_session_duration]['tp'] += 1
                    else:
                        results_by_min_duration[threshold][min_session_duration]['fn'] += 1
                else:
                    if client_sessions_with_highest_scores[clientSessionId]['falseHighestScore'] and client_sessions_with_highest_scores[clientSessionId]['falseSession'] == osSessionId:
                        results_by_min_duration[threshold][min_session_duration]['fp'] += 1
                    else:
                        results_by_min_duration[threshold][min_session_duration]['tn'] += 1

    for threshold in thresholds:
        for min_session_duration in min_session_durations:
            results_by_min_duration[threshold][min_session_duration]['precision'] = precision(results_by_min_duration[threshold][min_session_duration])
            results_by_min_duration[threshold][min_session_duration]['recall'] = recall(results_by_min_duration[threshold][min_session_duration])
            results_by_min_duration[threshold][min_session_duration]['fpr'] = fpr(results_by_min_duration[threshold][min_session_duration])
            results_by_min_duration[threshold][min_session_duration]['fnr'] = fnr(results_by_min_duration[threshold][min_session_duration])
            results_by_min_duration[threshold][min_session_duration]['f1-score'] = f1_score(results_by_min_duration[threshold][min_session_duration])

    return results_by_min_duration, metricsMapFinalScores



def correlate_sessions(is_full_pipeline=False):
    possible_request_combinations, clients_rtts, oses_rtts, missed_client_flows_full_pipeline, missed_os_flows_full_pipeline = pre_process(is_full_pipeline)
    session_buckets, session_windows = get_buckets_and_windows(possible_request_combinations)
    metricsMap, metricsMapFinalScores, metricsMapPerOS, metricsMapPerSessionPerClient, metricsMapFinalScoresPerSession = find_correlated_sessions(possible_request_combinations, clients_rtts, oses_rtts, session_buckets, session_windows, missed_client_flows_full_pipeline,
    missed_os_flows_full_pipeline)
    evaluate(possible_request_combinations, clients_rtts, metricsMapFinalScores, metricsMapPerSessionPerClient, metricsMapFinalScoresPerSession, missed_client_flows_full_pipeline, missed_os_flows_full_pipeline)
