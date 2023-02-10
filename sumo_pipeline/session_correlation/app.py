import typer

import sliding_subset_sum
import extract_pair_features


app = typer.Typer()


@app.command()
def extract_pairs_features():
    print("Extracting pairs features ...")
    extract_pair_features.extract_pairs_features()


@app.command()
def correlate_sessions():
    print("Correlating sessions ...")
    sliding_subset_sum.correlate_sessions(is_full_pipeline=False)
    

@app.command()
def correlate_sessions_full_pipeline():
    print("Correlating sessions full pipeline ...")
    sliding_subset_sum.correlate_sessions(is_full_pipeline=True)


if __name__ == "__main__":
    app()