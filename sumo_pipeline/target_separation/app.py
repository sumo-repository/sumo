import typer

import classifier
import extract_features


app = typer.Typer()


captures_folder_train = '../OSTrain/TrafficCapturesClient/'
captures_folder_test = '../OSTest/TrafficCapturesClient/'

featureFolderTrain = 'features_train/'
featureFolderTest = 'features_test/'
plFileTrain = featureFolderTrain + 'pl.csv'
statsFileTrain = featureFolderTrain + 'stats.csv'
plFileTest = featureFolderTest + 'pl.csv'
statsFileTest = featureFolderTest + 'stats.csv'


@app.command()
def extract_train_features():
    print("Extracting train features ...")
    extract_features.extract_features_train(captures_folder_train, featureFolderTrain)
    

@app.command()
def extract_test_features():
    print("Extracting test features ...")
    extract_features.extract_features_test(captures_folder_test, featureFolderTest)


@app.command()
def train():
    print("Training model ...")
    classifier.train(plFileTrain, statsFileTrain)


@app.command()
def test_standalone():
    print("Testing model ...")
    classifier.test(plFileTest, statsFileTest)


@app.command()
def test_full_pipeline():
    print("Testing model with full pipeline data ...")
    classifier.test_full_pipeline()


if __name__ == "__main__":
    app()