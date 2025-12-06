terraform {
    required_providers {
      aws = {
        source = "hashicorp/aws"
        version = "6.25.0"
      }
    }
}
provider "aws" {
    region = "eu-west-1"
}

variable "aws-login-user" {
    type = string
    default = ""
    description = "principal that will be used to managed remote accounts"
}

locals {
    unique_id = "8db7bc11-acf5-4c7a-be46-967f44e33028"
    ops_role_name = "ops-role-${local.unique_id}"
    stack_name = "aws-login-bootstrap-${local.unique_id}"
}

data "aws_region" "current" {}
data "aws_caller_identity" "current"{ }

data "aws_iam_policy_document" "ops_role_trust_policy" {
  statement {
    actions = ["sts:AssumeRole"]
    principals {
      type        = "AWS"
      identifiers = [var.aws-login-user]
    }
  }
}

data "aws_iam_policy_document" "ops_role_cfn_policy"{
    statement {
        actions = [
            "cloudformation:CreateStack",
            "cloudformation:UpdateStack",
            "cloudformation:DeleteStack",
            "cloudformation:DescribeStacks",
            "cloudformation:DescribeStackEvents"
        ]
        resources = ["arn:aws:cloudformation:${data.aws_region.current.region}:${data.aws_caller_identity.current.account_id}:stack/${local.stack_name}"]
    }

}

resource "aws_iam_policy" "ops_role_policy" {
    policy = data.aws_iam_policy_document.ops_role_cfn_policy.json
}

resource "aws_iam_role" "ops_role"{
    description = "role that will have access to deploy the iam roles by the aws-login app"
    assume_role_policy = data.aws_iam_policy_document.ops_role_trust_policy.json
    name = local.ops_role_name
}

resource "aws_iam_policy_attachment" "ops_role_attach_cfn"{
    name = "attachment"
    roles = [aws_iam_role.ops_role.name]
    policy_arn = aws_iam_policy.ops_role_policy.arn
}


