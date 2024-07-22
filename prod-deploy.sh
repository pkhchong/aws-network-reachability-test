aws cloudformation deploy \
  --stack-name reachability-test \
  --template-file ./template.yml \
  --capabilities CAPABILITY_NAMED_IAM \
  --parameter-overrides "file://./prod-param.json"
