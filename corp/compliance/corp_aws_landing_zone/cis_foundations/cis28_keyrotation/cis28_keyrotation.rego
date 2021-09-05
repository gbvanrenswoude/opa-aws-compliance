package corp.compliance.corp_aws_landing_zone.cis_foundations

import input

# [CIS.2.8] AWS Key Management Service (KMS) allows customers to rotate the backing key which is key material stored within the KMS which is tied to the key ID of the Customer Created customer master key (CMK). It is the backing key that is used to perform cryptographic operations such as encryption and decryption. It is recommended that CMK key rotation be enabled.
# MEDIUM

deny[msg] {
	val := input.Resources[key]
	val.Type == "AWS::KMS::Key"
	not val.Properties.EnableKeyRotation
	msg := sprintf("[CIS.2.8] : MEDIUM : KMS CMK %v does not contain KeyRotation settings", [key])
}
