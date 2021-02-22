terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "3.28.0"
    }
  }
}

provider "aws" {
  profile = "default"
  region  = "ap-southeast-2"
}

resource "aws_iam_policy" "ebs_csi_policy" {
  name        = "saga-ra3-ebs-csi-policy"
  path        = "/"
  description = "EBS CSI driver policy for saga-ra3 EKS cluster"

  policy = jsonencode({
    "Version": "2012-10-17",
    "Statement": [
        {
        "Effect": "Allow",
        "Action": [
            "ec2:AttachVolume",
            "ec2:CreateSnapshot",
            "ec2:CreateTags",
            "ec2:CreateVolume",
            "ec2:DeleteSnapshot",
            "ec2:DeleteTags",
            "ec2:DeleteVolume",
            "ec2:DescribeAvailabilityZones",
            "ec2:DescribeInstances",
            "ec2:DescribeSnapshots",
            "ec2:DescribeTags",
            "ec2:DescribeVolumes",
            "ec2:DescribeVolumesModifications",
            "ec2:DetachVolume",
            "ec2:ModifyVolume"
        ],
        "Resource": "*"
        }
    ]
    })
}

data "aws_eks_cluster" "cluster" {
  name = "saga-ra3-cluster"
}

data "aws_caller_identity" "current" {}

locals {
    cluster_oidc = split("://", data.aws_eks_cluster.cluster.identity[0].oidc[0].issuer)[1]
    account_id = data.aws_caller_identity.current.account_id
}



resource "aws_iam_role" "ebs_csi_role" {
    name = "saga-ra3-csi-role"
    assume_role_policy = jsonencode({
        "Version": "2012-10-17",
        "Statement": [
            {
            "Effect": "Allow",
            "Principal": {
                "Federated": "arn:aws:iam::${local.account_id}:oidc-provider/${local.cluster_oidc}"
            },
            "Action": "sts:AssumeRoleWithWebIdentity",
            "Condition": {
                "StringEquals": {
                "${local.cluster_oidc}:sub": "system:serviceaccount:kube-system:ebs-csi-controller-sa"
                }
            }
            }
        ]
    })
}

resource "aws_iam_role_policy_attachment" "ebs_csi_role_policy" {
  role = aws_iam_role.ebs_csi_role.name
  policy_arn = aws_iam_policy.ebs_csi_policy.arn
}
