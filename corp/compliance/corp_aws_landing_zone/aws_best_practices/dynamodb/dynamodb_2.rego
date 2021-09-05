package corp.compliance.corp_aws_landing_zone.aws_best_practices

import input

# [DynamoDB.2] This control checks whether point-in-time recovery (PITR) is enabled for a DynamoDB table. 
# MEDIUM

deny[msg] {
	val := input.Resources[key]
	val.Type == "AWS::DynamoDB::Table"
	not val.Properties.PointInTimeRecoverySpecification
	msg := sprintf("[DynamoDB.2] : MEDIUM : Table %v does not contain PointInTimeRecoverySpecification", [key])
}
