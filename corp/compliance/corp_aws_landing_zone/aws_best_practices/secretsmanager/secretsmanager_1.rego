package corp.compliance.corp_aws_landing_zone.aws_best_practices

import input

# [SecretsManager.1] This control checks whether a secret stored in AWS Secrets Manager is configured to rotate automatically.
# MEDIUM

key_in_rotationschedules(key) {
	val := input.Resources[iterator]
	val.Type == "AWS::SecretsManager::RotationSchedule"
	contains(val.Properties.SecretId, key)
}

deny[msg] {
	val := input.Resources[key]
	val.Type == "AWS::SecretsManager::Secret"
	not key_in_rotationschedules(key)
	msg := sprintf("[SecretsManager.1] : MEDIUM : In this stack, a RotationPolicy for Secret %v is not found, it might not rotate.", [key])
}
