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


#IS_2D_OPENCL_IMPL = True
IS_2D_OPENCL_IMPL = False
if IS_2D_OPENCL_IMPL == False:
    import subsetSumOpenCLWrapper as sliding_subset_sum
else:
    import subsetSumOpenCL2DWrapper as sliding_subset_sum


def pre_process(is_full_pipeline):

    datasetName = 'OSTest'
    testPairs = pickle.load(open('testPairs_{}'.format(datasetName), 'rb'))

    if is_full_pipeline == True:
        datasetName += 'full_pipeline'

    possible_request_combinations_file = 'possible_request_combinations_{}.pickle'.format(datasetName)
    clients_rtts_file = 'clients_rtts_{}.pickle'.format(datasetName)
    oses_rtts_file = 'oses_rtts_{}.pickle'.format(datasetName)

    missed_client_flows_full_pipeline_file = "missed_client_flows_full_pipeline_{}.pickle".format(datasetName)
    missed_os_flows_full_pipeline_file = "missed_os_flows_full_pipeline_{}.pickle".format(datasetName)

    # ---------------------- Data pre-processing ----------------------
    if is_full_pipeline == False:
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
                pickle.dump(missed_client_flows_full_pipeline, open(missed_client_flows_full_pipeline_file, 'wb'))
                pickle.dump(missed_os_flows_full_pipeline, open(missed_os_flows_full_pipeline_file, 'wb'))

            pickle.dump(possible_request_combinations, open(possible_request_combinations_file, 'wb'))
            pickle.dump(clients_rtts, open(clients_rtts_file, 'wb'))
            pickle.dump(oses_rtts, open(oses_rtts_file, 'wb'))
    else:
        if isfile(possible_request_combinations_file) and isfile(clients_rtts_file) and isfile(oses_rtts_file) and isfile(missed_client_flows_full_pipeline_file) and isfile(missed_os_flows_full_pipeline_file):
            print("==== Gathering pre-processed data from file...")
            possible_request_combinations = pickle.load(open(possible_request_combinations_file, "rb"))
            clients_rtts = pickle.load(open(clients_rtts_file, "rb"))
            oses_rtts = pickle.load(open(oses_rtts_file, "rb"))
        else: 
            if is_full_pipeline == False:
                possible_request_combinations, clients_rtts, oses_rtts = feature_collection.process_features_epochs_sessions(testPairs, timeSamplingInterval, epoch_size, epoch_tolerance)
            else:
                possible_request_combinations, clients_rtts, oses_rtts, missed_client_flows_full_pipeline, missed_os_flows_full_pipeline = feature_collection.process_features_epochs_sessions_full_pipeline(testPairs, timeSamplingInterval, epoch_size, epoch_tolerance)
                pickle.dump(missed_client_flows_full_pipeline, open(missed_client_flows_full_pipeline_file, 'wb'))
                pickle.dump(missed_os_flows_full_pipeline, open(missed_os_flows_full_pipeline_file, 'wb'))

            pickle.dump(possible_request_combinations, open(possible_request_combinations_file, 'wb'))
            pickle.dump(clients_rtts, open(clients_rtts_file, 'wb'))
            pickle.dump(oses_rtts, open(oses_rtts_file, 'wb'))
    
    print("==== After pre-processing data")

    if is_full_pipeline == True:    
        missed_client_flows_full_pipeline = pickle.load(open(missed_client_flows_full_pipeline_file, "rb"))
        missed_os_flows_full_pipeline = pickle.load(open(missed_os_flows_full_pipeline_file, "rb"))
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

        scores = sliding_subset_sum.whole_loop_subset_sum(packetListClients, packetListOSes, len(packetListClients), nBuckets, delta, buckets_per_window, buckets_overlap, nWindows)

        counter = 0
        for start, (clientSessionId, osSessionId) in enumerate(possible_request_combinations.keys()):
            if start >= len(scores):
                continue
            for j in range(0, session_windows[(clientSessionId, osSessionId)]):
                key = (clientSessionId, osSessionId)
                if key not in database:
                    database[key] = []
                deltaKey = (delta, clientSessionId, osSessionId)
                database[key].append((j, scores[start].scores[j]))

            if counter > 28000:
                print("counter", counter)
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

        scores = sliding_subset_sum.whole_loop_subset_sum(packetListClients, packetListOSes, count_pairs, nBuckets, delta, buckets_per_window, buckets_overlap, nWindows, acc_windows)

        count_windows = 0
        for start, (clientSessionId, osSessionId) in enumerate(possible_request_combinations.keys()):
            if start >= len(acc_windows):
                continue
            for j in range(0, session_windows[(clientSessionId, osSessionId)]):
                key = (clientSessionId, osSessionId)
                if key not in database:
                    database[key] = []
                deltaKey = (delta, clientSessionId, osSessionId)
                count_windows += 1
                database[key].append((j, scores[acc_windows[start] + j]))
    
    # TODO: I don't need this, I can calculate the score right away and use the yeld with this
    print("before return database")
    return database


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


def find_correlated_sessions(possible_request_combinations, clients_rtts, oses_rtts, session_buckets, session_windows, missed_client_flows_full_pipeline, missed_os_flows_full_pipeline):
    score_counter = {}

    for delta in deltas:
        print("\n======================== Delta {} ========================\n".format(delta))
        
        database = run_windowed_subset_sum_on_all_pairs(delta, possible_request_combinations, clients_rtts, oses_rtts, session_buckets, session_windows)
        print("***** after run_windowed_subset_sum_on_all_pairs")
        # ---------------------- Calculate overall score ----------------------
        windows_with_packets, score_counter[delta], scores_per_session = process_results.calculate_overall_score(possible_request_combinations, database, buckets_per_window, buckets_overlap)
        
        print("=== After calculating overall score")

        metricsMap = {}
        metricsMapFinalScores = {}
        metricsMapPerSessionPerClient = {}

        for threshold in thresholds:
            print("Evaluating threshold {}".format(threshold))
            metricsMap[threshold] = {'tp': 0, 'tn': 0, 'fp': 0, 'fn': missed_client_flows_full_pipeline + missed_os_flows_full_pipeline}
            metricsMapFinalScores[threshold] = {'tp': 0, 'tn': 0, 'fp': 0, 'fn': missed_client_flows_full_pipeline + missed_os_flows_full_pipeline}
            metricsMapPerSessionPerClient[threshold] = {}
            index = 0
            for key, value in score_counter[delta].items(): 
                clientSessionId = key[0]
                osSessionId = key[1]
                
                final_score = calculate_final_score(database[key]) / session_windows[key]
                
                if clientSessionId not in metricsMapPerSessionPerClient[threshold]:
                    metricsMapPerSessionPerClient[threshold][clientSessionId] = {}
                metricsMapPerSessionPerClient[threshold][clientSessionId][osSessionId] = final_score
                
                if final_score >= threshold:
                    if clientSessionId == osSessionId:
                        metricsMap[threshold]['tp'] += 1
                    else:
                        metricsMap[threshold]['fp'] += 1
                        
                else:
                    if clientSessionId == osSessionId:
                        metricsMap[threshold]['fn'] += 1
                    else:
                        metricsMap[threshold]['tn'] += 1

            # Calculate precision, recall, f1-score, ...
            metricsMap[threshold]['precision'] = precision(metricsMap[threshold])
            metricsMap[threshold]['recall'] = recall(metricsMap[threshold])
            metricsMap[threshold]['fpr'] = fpr(metricsMap[threshold])
            metricsMap[threshold]['fnr'] = fnr(metricsMap[threshold])
            metricsMap[threshold]['f1-score'] = f1_score(metricsMap[threshold])

            index += 1


            client_sessions_with_highest_scores = process_results.count_client_correlated_sessions_highest_score(metricsMapPerSessionPerClient[threshold], threshold)
            for clientSessionId, osSessionId in possible_request_combinations.keys():

                if clientSessionId == osSessionId:
                    if client_sessions_with_highest_scores[clientSessionId]['correlatedHighestScore']:
                        metricsMapFinalScores[threshold]['tp'] += 1
                    else:
                        metricsMapFinalScores[threshold]['fn'] += 1
                else:
                    if client_sessions_with_highest_scores[clientSessionId]['falseHighestScore'] and client_sessions_with_highest_scores[clientSessionId]['falseSession'] == osSessionId:
                        metricsMapFinalScores[threshold]['fp'] += 1
                        key = (clientSessionId, osSessionId)

                    else:
                        metricsMapFinalScores[threshold]['tn'] += 1

            # Calculate precision, recall, f1-score, ...
            metricsMapFinalScores[threshold]['precision'] = precision(metricsMapFinalScores[threshold])
            metricsMapFinalScores[threshold]['recall'] = recall(metricsMapFinalScores[threshold])
            metricsMapFinalScores[threshold]['fpr'] = fpr(metricsMapFinalScores[threshold])
            metricsMapFinalScores[threshold]['fnr'] = fnr(metricsMapFinalScores[threshold])
            metricsMapFinalScores[threshold]['f1-score'] = f1_score(metricsMapFinalScores[threshold])

        return metricsMapFinalScores, metricsMapPerSessionPerClient


def get_session_duration(clients_rtts, clientSessionId):
    return clients_rtts[clientSessionId]['rtts'][1] - clients_rtts[clientSessionId]['rtts'][0] 


def evaluate(possible_request_combinations, clients_rtts, metricsMapFinalScores, metricsMapPerSessionPerClient, missed_client_flows_full_pipeline, missed_os_flows_full_pipeline):
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
    print("****** get_buckets_and_windows")
    session_buckets, session_windows = get_buckets_and_windows(possible_request_combinations)
    print("****** find_correlated_sessions")
    metricsMapFinalScores, metricsMapPerSessionPerClient = find_correlated_sessions(possible_request_combinations, clients_rtts, oses_rtts, session_buckets, session_windows, missed_client_flows_full_pipeline,
    missed_os_flows_full_pipeline)
    print("****** evaluate")
    results_by_min_duration, metricsMapFinalScores = evaluate(possible_request_combinations, clients_rtts, metricsMapFinalScores, metricsMapPerSessionPerClient, metricsMapFinalScoresPerSession, missed_client_flows_full_pipeline, missed_os_flows_full_pipeline)
    print("****** before prints")
    print("results_by_min_duration", results_by_min_duration)
    print("metricsMapFinalScores", metricsMapFinalScores)