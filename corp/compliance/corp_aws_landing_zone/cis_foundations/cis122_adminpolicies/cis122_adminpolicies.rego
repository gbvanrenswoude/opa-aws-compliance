package corp.compliance.corp_aws_landing_zone.cis_foundations

import input

# [CIS.1.22] IAM policies are the means by which privileges are granted to users, groups, or roles. It is recommended and considered a standard security advice to grant least privilege—that is, granting only the permissions required to perform a task. Determine what users need to do and then craft policies for them that let the users perform only those tasks, instead of allowing full administrative privileges
# HIGH

deny[msg] {
	val := input.Resources[key]
	val.Type == "AWS::IAM::Policy"
	statements := val.Properties.PolicyDocument.Statement[iterator]
	statements.Action = "*"
	statements.Resource = "*"
	statements.Effect = "Allow"
	msg := sprintf("[CIS 1.22] : HIGH : In this stack, a statement that allows all actions on all resources is found in the PolicyDocument of Policy %v.", [key])
}

# TODO add the same for inline role policies
