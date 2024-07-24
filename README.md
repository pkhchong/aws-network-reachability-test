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

create a sns topic, create a suscription on that topic. copy the sns topic arn to event.json 

zip the reachability-test-lambda.zip
```
zip reachability-test-lambda.zip lambda_function.py event.json
```

create a s3 bucket and upload a zip file to the bucket

modify the prod-param.json with the s3 bucket that you store the zip file

deploy the cloudformation stack
```
./prod-deploy.sh
```