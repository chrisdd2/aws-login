package main

import (
	"errors"
	"fmt"
	"strings"

	"github.com/chrisdd2/aws-login/internal"
)

func boundaryPolicy(permissionBoundaryArn, bootstrapRoleArn string) string {
	return fmt.Sprintf(`
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "DenyAllIAMUserActions",
      "Effect": "Deny",
      "Action": [
        "iam:CreateUser",
        "iam:DeleteUser"
      ],
      "Resource": "*"
    },
    {
      "Sid": "DenyCreateRoleWithoutBoundary",
      "Effect": "Deny",
      "Action": [
        "iam:CreateRole"
      ],
      "Resource": "*",
      "Condition": {
        "StringNotEqualsIfExists": {
          "iam:PermissionsBoundary": "%s"
        }
      }
    },
    {
      "Sid": "DenyUpdateRoleToRemoveBoundary",
      "Effect": "Deny",
      "Action": [
        "iam:UpdateRole"
      ],
      "Resource": "*",
      "Condition": {
        "StringNotEqualsIfExists": {
          "iam:PermissionsBoundary": "%s"
        }
      }
    },
    {
      "Sid": "DenyBoundaryActions",
      "Effect": "Deny",
      "Action": [
        "iam:*Boundary"
      ],
      "Resource": "*"
    },
    {
      "Sid": "DenyManagementRoleModification",
      "Effect": "Deny",
      "Action": [
        "iam:CreateRole",
        "iam:DeleteRole",
        "iam:UpdateRole"
      ],
      "Resource": "%s"
    },
    {
      "Sid": "AllowEverythingElse",
      "Effect": "Allow",
      "Action": [
        "*"
      ],
      "Resource": "*"
    }
  ]
}`, permissionBoundaryArn, permissionBoundaryArn, bootstrapRoleArn)
}

func trustPolicy(arn string) string {
	return fmt.Sprintf(`{
							"Version": "2012-10-17",
							"Statement": [{
								"Effect": "Allow",
								"Principal": {
								"AWS": "%s"
								},
								"Action": "sts:AssumeRole"
							}]
							}
					`, arn)
}

func ssmPolicy(action internal.SsmAction, accountId string) (string, error) {
	// prepare the statements
	var documentName string
	switch strings.ToLower(action.Action) {
	case "shell":
		documentName = "SSM-SessionManagerRunShell"
	case "portforward":
		documentName = "AWS-StartPortForwardingSession"
	case "portforwardremote":
		documentName = "AWS-StartPortForwardingSessionToRemoteHost"
	default:
		return "", errors.New("unvalid action type")
	}
	documentResource := fmt.Sprintf("\"arn:aws:ssm:%s:%s:document/%s\"", action.Region, accountId, documentName)

	statements := []string{}
	if len(action.Ids) > 0 {
		resources := []string{documentResource}
		for _, id := range action.Ids {
			resources = append(resources, fmt.Sprintf("\"arn:aws:ec2:%s:%s:instance/%s\"", action.Region, accountId, id))
		}
		statements = append(statements, fmt.Sprintf(`{
			"Sid": "StartSessionOnIds",
			"Effect": "Allow",
			"Action": "ssm:StartSession",
			"Resource": [%s]
		}`, strings.Join(resources, ",")))
	}
	if len(action.TagFilter) > 0 {

	}
	if len(statements) == 0 {
		return "", errors.New("no ids or tag filters speficied")
	}

	// add required statements
	messagesStatement := `{
      "Sid": "OpenSessionDataChannel",
      "Effect": "Allow",
      "Action": "ssmmessages:OpenDataChannel",
      "Resource": "arn:aws:ssm:*:*:session/${aws:userid}-*"
    }`
	sessionActionsStatement := `{
      "Sid": "SessionManagement",
      "Effect": "Allow",
      "Action": [
        "ssm:TerminateSession",
        "ssm:ResumeSession"
      ],
      "Resource": "arn:aws:ssm:*:*:session/${aws:userid}-*"
    }`
	describeStatement := `{ 
      "Sid": "DescribeInstances",
      "Effect": "Allow",
      "Action": [
        "ssm:DescribeSessions",
        "ssm:GetConnectionStatus",
        "ssm:DescribeInstanceProperties",
      ],
      "Resource": "*"
    }`

	statements = append(statements, messagesStatement, sessionActionsStatement, describeStatement)

	return fmt.Sprintf(`{
		"Version": "2012-10-17",
		"Statement": [%s]
	}`, strings.Join(statements, ",")), nil

}
