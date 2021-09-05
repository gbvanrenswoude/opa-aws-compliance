package corp.compliance.corp_aws_landing_zone.aws_best_practices

import input

# [Lambda.4] This control checks whether an AWS Lambda function is configured with a dead-letter queue. The control fails if the Lambda function is not configured with a dead-letter queue.
# MEDIUM

deny[msg] {
	val := input.Resources[key]
	val.Type == "AWS::Lambda::Function"
	not val.Properties.DeadLetterConfig
	msg := sprintf("[Lambda.4] : MEDIUM : Lambda Function %v does not contain DeadLetterConfig, it might not be configured with a dead-letter queue", [key])
}
