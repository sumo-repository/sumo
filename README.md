# SUMo

## Pre-requisits
```
cd sumo_pipeline/
pip install -r requirements.txt
```

## Download datasets
* OSDeepLearn: https://archive.org/details/OSDeepLearn

* OSTest: https://archive.org/details/OSTest

* OSTrain: https://archive.org/details/OSTrain

## Source separation
```
cd source_separation/
python3 app.py --help

python3 app.py extract-test-features
python3 app.py extract-train-features
python3 app.py train 
python3 app.py test
```

## Target separation
```
cd target_separation/
python3 app.py --help

python3 app.py extract-test-features
python3 app.py extract-train-features
python3 app.py train 
python3 app.py test-standalone
```

## Session correlation
```
cd session_correlation/

g++ -I/usr/local/cuda/include -L/usr/lib/nvidia-current -fopenmp -O3 -std=c++14 -fPIC --shared subsetSum_opencl.cpp -o torpedosubsetsumopencl.so -lOpenCL

python3 app.py --help

python3 app.py extract_pairs_features
python3 app.py correlate-sessions
```

## Execute full pipeline
```
cd source_separation/
python3 app.py extract-test-features
python3 app.py extract-train-features
python3 app.py train 
python3 app.py test-full-pipeline 

cd ../target_separation/
python3 app.py extract-test-features
python3 app.py extract-train-features
python3 app.py train 
python3 app.py test-full-pipeline 

cd ../session_correlation/
python3 app.py correlate-sessions-full-pipeline

```
