import typer

import classifier
import extract_features


app = typer.Typer()


#captures_folder_train = 'OSTrain/'
#captures_folder_test = 'OSTest/'
captures_folder_train = '/Volumes/TOSHIBA_EXT/datasets_simulate_user/OSTrain/'
captures_folder_test = '/Volumes/TOSHIBA_EXT/datasets_simulate_user/OSTest/'

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
    classifier.train(featureFolderTrain + plFileTrain, featureFolderTrain + statsFileTrain)


@app.command()
def test_standalone():
    print("Testing model ...")
    classifier.test(featureFolderTest + plFileTest, featureFolderTest + statsFileTest)


@app.command()
def test_full_pipeline():
    print("Testing model with full pipeline data ...")
    classifier.test_full_pipeline()


if __name__ == "__main__":
    app()