# SUMo

## Pre-requisits
```
cd sumo_pipeline/
pip install -r requirements.txt
```

## Download datasets
* OSDeepLearn: https://archive.org/details/osdeep-learn
<!-->```
wget https://archive.org/download/osdeep-learn/OSDeepLearn.zip
unzip OSDeepLearn.zip
```-->

* OSTest: https://archive.org/details/OSTest
```
wget https://archive.org/download/OSTest/OSTest.zip
unzip OSTest.zip
```

* OSTrain: https://archive.org/details/OSTrain
```
wget https://archive.org/download/OSTrain/OSTrain.zip
unzip OSTrain.zip
```

## Source separation
```
cd source_separation/
python3 app.py --help

python3 app.py extract-train-features
python3 app.py extract-test-features
python3 app.py train 
python3 app.py test-standalone
```

Results will be in results/ folder.

Full execution:
```

```

## Target separation
```
cd target_separation/
python3 app.py --help

python3 app.py extract-train-features
python3 app.py extract-test-features
python3 app.py train 
python3 app.py test-standalone
```

Results will be in results/ folder.

## Session correlation
```
cd session_correlation/

g++ -I/usr/local/cuda/include -L/usr/lib/nvidia-current -fopenmp -O3 -std=c++14 -fPIC --shared subsetSum_opencl.cpp -o subsetsumopencl.so -lOpenCL

python3 app.py --help

python3 app.py extract-pairs-features
python3 app.py correlate-sessions
```

## Execute full pipeline
```
cd source_separation/
python3 app.py extract-train-features
python3 app.py extract-test-features
python3 app.py train 
python3 app.py test-full-pipeline 

cd ../target_separation/
python3 app.py extract-train-features
python3 app.py extract-test-features
python3 app.py train 
python3 app.py test-full-pipeline 

cd ../session_correlation/
python3 app.py correlate-sessions-full-pipeline

```
