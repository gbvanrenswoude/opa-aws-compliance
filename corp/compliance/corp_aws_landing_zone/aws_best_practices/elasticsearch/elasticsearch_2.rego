package corp.compliance.corp_aws_landing_zone.aws_best_practices

import input

# [ES.2] This control checks whether Amazon Elasticsearch Service domains are in a VPC.
# CRITICAL

deny[msg] {
	val := input.Resources[key]
	val.Type == "AWS::Elasticsearch::Domain"
	not val.Properties.VPCOptions
	msg := sprintf("[ES.2] : CRITICAL : Elasticsearch Domain %v does not contain VPCOptions, it might contain a public endpoint", [key])
}
