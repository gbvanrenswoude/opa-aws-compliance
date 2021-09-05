package corp.compliance.corp_aws_landing_zone.cis_foundations

import input

# [CIS.4.2] Security groups provide stateful filtering of ingress/egress network traffic to AWS resources. It is recommended that no security group allows unrestricted ingress access to port 3389
# HIGH

deny[msg] {
	val := input.Resources[key]
	val.Type == "AWS::EC2::SecurityGroup"
	ingresses := val.Properties.SecurityGroupIngress[iterator]
	ingresses.FromPort = 3389
	contains(ingresses.CidrIp, "0.0.0.0/0")
	msg := sprintf("[CIS 4.2] : HIGH : In this stack, a fully open ingress rule for port 3389 was found in %v.", [key])
}
