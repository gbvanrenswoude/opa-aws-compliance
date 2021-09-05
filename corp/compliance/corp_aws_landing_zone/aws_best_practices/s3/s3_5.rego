package corp.compliance.corp_aws_landing_zone.aws_best_practices

import input

# [S3.5] This AWS control checks whether S3 buckets have policies that require requests to use Secure Socket Layer (SSL)
# MEDIUM

bucket_has_valid_bucketpolicy(key) {
	val := input.Resources[iterator]
	val.Type == "AWS::S3::BucketPolicy"
	contains(val.Properties.Bucket, key)
	contains(val.Properties.PolicyDocument, "aws:SecureTransport")
}

deny[msg] {
	val := input.Resources[key]
	val.Type == "AWS::S3::Bucket"
	not bucket_has_valid_bucketpolicy(key)
	msg := sprintf("[S3.5] : MEDIUM : In this stack, S3 Bucket %v was detected, it might not have SecureTransport enforced in it's BucketPolicy.", [key])
}
