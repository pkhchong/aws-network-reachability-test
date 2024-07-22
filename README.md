# aws-network-reachability-test




install dependancy
```
pip install -r requirements.txt
```

run the test
```
python3 check_tgw_connectivity.py
```


## cost

cost per analysis $0.1
if you have 10 path to test, each time it analysis 10 path. it cost $1


## deploy

zip the reachability-test-lambda.zip
```
zip reachability-test-lambda.zip lambda_function.py event.json
```

upload reachability-test-lambda.zip to s3 bucket inspector-report-75897 in AWS main account
```
./prod-deploy.sh
```