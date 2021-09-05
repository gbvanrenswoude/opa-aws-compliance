package corp.compliance.corp_aws_landing_zone.cis_foundations

import input

# [CIS.4.1] Security groups provide stateful filtering of ingress/egress network traffic to AWS resources. It is recommended that no security group allows unrestricted ingress access to port 22.
# HIGH

deny[msg] {
	val := input.Resources[key]
	val.Type == "AWS::EC2::SecurityGroup"
	ingresses := val.Properties.SecurityGroupIngress[iterator]
	ingresses.FromPort = 22
	contains(ingresses.CidrIp, "0.0.0.0/0")
	msg := sprintf("[CIS 4.1] : HIGH : In this stack, a fully open ingress rule for port 22 was found in %v.", [key])
}
