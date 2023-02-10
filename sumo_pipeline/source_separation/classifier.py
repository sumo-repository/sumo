"""OS Classifier 

Trains the model through guided learning with features
"""

import matplotlib.pyplot as plt
import matplotlib as mpl
import os
import numpy as np
import pickle
import os
import sklearn
import joblib
from sklearn.decomposition import PCA
#Classifiers
from xgboost import XGBClassifier
#Eval Metrics
from sklearn.metrics import roc_curve, precision_recall_curve, average_precision_score
import pandas as pd
from sklearn.metrics import  roc_curve

sklearn.set_config(assume_finite=True)


LABEL_INDEX = -2
CAPTURE_INDEX = -1

DECISION_THRESHOLD = 0.9
model_save_file = 'source_separation_model.joblib'


plt.rc('font', size=16)          # controls default text sizess
plt.rc('axes', titlesize=30)     # fontsize of the axes title
plt.rc('axes', labelsize=20)    # fontsize of the x and y labels
plt.rc('xtick', labelsize=20)    # fontsize of the tick labels
plt.rc('ytick', labelsize=20)    # fontsize of the tick labels
plt.rc('legend', fontsize=14)    # legend fontsize
plt.rc('figure', titlesize=56)  # fontsize of the figure title

plt.rcParams['axes.xmargin'] = 0
plt.rcParams['axes.ymargin'] = 0
mpl.rcParams['axes.spines.right'] = False
mpl.rcParams['axes.spines.top'] = False


def optimal_threshold(tpr, fpr, thresholds):
    # https://stats.stackexchange.com/questions/123124/how-to-determine-the-optimal-threshold-for-a-classifier-and-generate-roc-curve
    optimal_idx = np.argmax(tpr - fpr)
    optimal_threshold = thresholds[optimal_idx]
    
    return optimal_threshold


def plot_precision_recall_curve(y_test, probas_):
    fig, ax = plt.subplots(figsize=(5, 4))
    
    precision, recall, thresholds = precision_recall_curve(y_test, probas_[:, 1])

    plt.plot(np.insert(recall, 0, recall[0]), np.insert(precision, 0, 0), linewidth=4, color="tab:blue", label="PR curve (AP={})".format(round(average_precision_score(y_test, probas_[:, 1]), 2)))
    plt.plot([0, 1], [0.5, 0.5], linestyle='--', color='orange', label='Random Classifier', linewidth=2)
    plt.plot([0, 1, 1], [1, 1, 0], linestyle=':', color='black', label='Perfect Classifier', linewidth=3)
    plt.ylabel("Precision")
    plt.xlabel("Recall")
    plt.ylim(0.49, 1.01)
    plt.xlim(0, 1.01)
    x_axis = np.arange(0, 1.01, 0.25)
    y_axis = np.arange(0.5, 1.01, 0.25)
    plt.xticks(x_axis, x_axis)
    plt.yticks(y_axis, y_axis)
    plt.legend()
    plt.tight_layout()


def gatherDataset(plFile, statsFile):
    pl = pd.read_csv(plFile) 
    stats = pd.read_csv(statsFile) 

    print("stats:", stats)
    # Transform dtype object columns to numeric
    cols = stats[stats.columns[:LABEL_INDEX]].select_dtypes(exclude=['float']).columns
    stats[cols] = stats[cols].apply(pd.to_numeric, downcast='float', errors='coerce')

    # drop captures (last column)
    pl = pl[pl.columns[:LABEL_INDEX]]

    # Combine both feature sets side by side
    train = pd.concat([pl, stats], axis=1)

    train[' Class'] = train[' Class'].astype(int)

    # Remove columns that only have zeros
    train.loc[:, (train != 0).any(axis=0)]

    # Shuffle dataset
    train = train.sample(frac = 1)

    y_train = train[' Class']
    captures = train[' Capture']

    x_train = train[train.columns[:LABEL_INDEX]]

    return x_train, y_train, captures


def train(plFileTrain, statsFileTrain):

    print("\n=== Gathering training dataset ...")
    X_train , y_train, _ = gatherDataset(plFileTrain, statsFileTrain)

    print("\n=== Creating model ...")
    model = XGBClassifier()
    print("\n=== Training model ...")
    model.fit(X_train, y_train)
    joblib.dump(model, model_save_file)


def test(plFileTest, statsFileTest):

    if os.isfile(model_save_file):
        print("Gathering trained model ...")
        model = joblib.load(model_save_file)
    else:
        print("You have to train source separation's model first!")
        print("Exiting ...")
        exit()

    print("Gathering testing dataset ...")
    X_test , y_test, test_captures = gatherDataset(plFileTest, statsFileTest)

    # Predicts the probability of each element to belong to a determined class
    probas_ = model.predict_proba(X_test)
    plot_precision_recall_curve(y_test, probas_)

    fpr, tpr, thresholds = roc_curve(y_test, probas_[:, 1], pos_label=1)
    decision_threshold = optimal_threshold(tpr, fpr, thresholds)
    dumpPipelineFeatures(X_test, probas_[:, 1], test_captures, decision_threshold)
    
    return probas_


def dumpPipelineFeatures(features, predictions, captures, decision_threshold):
    print("Dumping features for next stage of the pipeline ...")
    
    outputClientFeatures = {}
    outputOSFeatures = {}

    for i in range(len(predictions)):
        if predictions[i] < decision_threshold:
            # use iloc to access a whole row in the dataframe
            outputClientFeatures[captures.iloc[i]] = features.iloc[i]
        else:
            outputOSFeatures[captures.iloc[i]] = features.iloc[i]

    pickle.dump(outputClientFeatures, open('client_features_source_separation.pickle', 'wb'))
    pickle.dump(outputOSFeatures, open('os_features_source_separation.pickle', 'wb'))