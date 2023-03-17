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

models_folder = 'models/'
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

    results_folder = 'results/'
    if not os.path.exists(results_folder):
        os.makedirs(results_folder)
    plt.savefig(results_folder + 'precision_recall_curve_source_separation.pdf')
    plt.savefig(results_folder + 'precision_recall_curve_source_separation.png')


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

    # Save features names
    model.feature_names = list(X_train.columns.values)

    if not os.path.exists(models_folder):
        os.makedirs(models_folder)
    joblib.dump(model, models_folder+model_save_file)


def test(plFileTest, statsFileTest):

    if os.path.isfile(models_folder+model_save_file):
        print("Gathering trained model ...")
        model = joblib.load(models_folder+model_save_file)
    else:
        print("You have to train source separation's model first!")
        print("Exiting ...")
        exit()

    print("Gathering testing dataset ...")
    X_test , y_test, test_captures = gatherDataset(plFileTest, statsFileTest)

    # Predicts the probability of each element to belong to a determined class
    probas_ = model.predict_proba(X_test)
    plot_precision_recall_curve(y_test, probas_)
    
    return probas_


def test_full_pipeline(plFileTest, statsFileTest, optimalThr=True):

    if os.path.isfile(models_folder+model_save_file):
        print("Gathering trained model ...")
        model = joblib.load(models_folder+model_save_file)
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

    if optimalThr == True:
        decision_threshold = optimal_threshold(tpr, fpr, thresholds)
    else:
        decision_threshold = DECISION_THRESHOLD

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

    features_folder = 'full_pipeline_features/'
    if not os.path.exists(features_folder):
        os.makedirs(features_folder)
    pickle.dump(outputClientFeatures, open(features_folder+'client_features_source_separation_thr_{}.pickle'.format(decision_threshold), 'wb'))
    pickle.dump(outputOSFeatures, open(features_folder+'os_features_source_separation_thr_{}.pickle'.format(decision_threshold), 'wb'))