
import matplotlib.pyplot as plt
import matplotlib as mpl
import os
import numpy as np
import pickle
import os
import sklearn
import joblib
from xgboost import XGBClassifier
from sklearn.metrics import precision_recall_curve, average_precision_score
import pandas as pd


sklearn.set_config(assume_finite=True)


LABEL_INDEX = -2
CAPTURE_INDEX = -1

THRESHOLD = 0.9
model_save_file = 'target_separation_model.joblib'


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


def true_false_positive(threshold_vector, y_test):
    true_positive = np.equal(threshold_vector, 1) & np.equal(y_test, 1)
    true_negative = np.equal(threshold_vector, 0) & np.equal(y_test, 0)
    false_positive = np.equal(threshold_vector, 1) & np.equal(y_test, 0)
    false_negative = np.equal(threshold_vector, 0) & np.equal(y_test, 1)

    tpr = true_positive.sum() / (true_positive.sum() + false_negative.sum())
    fpr = false_positive.sum() / (false_positive.sum() + true_negative.sum())

    precision = true_positive.sum() / (true_positive.sum() + false_positive.sum())
    recall = true_positive.sum() / (true_positive.sum() + false_negative.sum())

    return tpr, fpr, precision, recall


def get_tpr_fpr_threshold_preds(probabilities, y_test):
    #threshold = 0.9
    threshold_vector = np.greater_equal(probabilities, THRESHOLD).astype(int)
    print("---- threshold {}".format(THRESHOLD))
    tpr, fpr, precision, recall = true_false_positive(threshold_vector, y_test)
    print("tpr {}; fpr {}; precision {}; recall {}".format(tpr, fpr, precision, recall))

    print("COUNT OCCURRENCES", np.count_nonzero(threshold_vector == 1))
    return threshold_vector



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

    # Transform dtype object columns to numeric
    cols = stats[stats.columns[:LABEL_INDEX]].select_dtypes(exclude=['float']).columns
    stats[cols] = stats[cols].apply(pd.to_numeric, downcast='float', errors='coerce')

    # drop captures (last column)
    pl = pl[pl.columns[:LABEL_INDEX]]

    # Combine both feature sets side by side
    train = pd.concat([pl, stats], axis=1)
    #print("train", train)
    
    train[' Class'] = train[' Class'].astype(int)

    # Remove columns that only have zeros
    train.loc[:, (train != 0).any(axis=0)]

    # Shuffle dataset
    train = train.sample(frac = 1)

    y_train = train[' Class']

    x_train = train[train.columns[:LABEL_INDEX]]

    cols = x_train.columns.to_list() + [' Class', ' Capture']
    return x_train, y_train



def gatherFullPipelineDataset():
    clientsFullPipeline = pickle.load(open('../source_separation/client_features_source_separation.pickle', 'rb'))
    captures = list(clientsFullPipeline.keys())

    x_train = pd.DataFrame(clientsFullPipeline.values())

    y_train = []
    for capture in captures:
        if 'alexa' in capture:
            label = 0
        elif '_hs' in capture:
            label = 0
        else:
            label = 1
        y_train.append(label)

    cols2 = x_train.columns.to_list()
    for col in cols2:
        if col not in cols:
            x_train.drop(col, inplace=True, axis=1)

    x_train[' Class'] = y_train
    x_train[' Capture'] = captures
    y_train = x_train[' Class']
    x_train = x_train[x_train.columns[:LABEL_INDEX]]

    captures = x_train[' Capture']
            
    return x_train, y_train, captures


def train(plFileTrain, statsFileTrain):

    print("\n=== Gathering training dataset ...")
    X_train , y_train = gatherDataset(plFileTrain, statsFileTrain)

    print("\n=== Creating model ...")
    model = XGBClassifier()
    print("\n=== Training model ...")
    model.fit(np.asarray(X_train), np.asarray(y_train))
    joblib.dump(model, model_save_file)


def test(plFileTest, statsFileTest):

    if os.isfile(model_save_file):
        print("Gathering trained model ...")
        model = joblib.load(model_save_file)
    else:
        print("You have to train target separation's model first!")
        print("Exiting ...")
        exit()

    print("Gathering testing dataset ...")
    X_test , y_test = gatherDataset(plFileTest, statsFileTest)

    # Predicts the probability of each element to belong to a determined class
    probas_ = model.predict_proba(np.asarray(X_test))
    plot_precision_recall_curve(y_test, probas_)

    return probas_


def test_full_pipeline():

    if os.isfile(model_save_file):
        print("Gathering trained model ...")
        model = joblib.load(model_save_file)
    else:
        print("You have to train and test source separation's model and train target separation's model first!")
        print("Exiting ...")
        exit()

    print("Gathering full pipeline testing dataset ...")
    X_test , y_test, test_captures = gatherFullPipelineDataset()

    # Predicts the probability of each element to belong to a determined class
    probas_ = model.predict_proba(np.asarray(X_test))
    plot_precision_recall_curve(y_test, probas_)

    outputClientFeatures = {}
    predictions_final = get_tpr_fpr_threshold_preds(probas_[:, 1], y_test)

    for i in range(len(predictions_final)):
        if predictions_final[i] == 1:     
            outputClientFeatures[test_captures.iloc[i]] = X_test.iloc[i]

    pickle.dump(outputClientFeatures, open('client_features_target_separation.pickle', 'wb'))

    
    return probas_
