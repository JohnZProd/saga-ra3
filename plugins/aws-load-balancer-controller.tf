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

resource "aws_iam_policy" "aws_load_balancer_controller_policy" {
  name        = "saga-ra3-aws-load-balancer-controller-policy"
  path        = "/"
  description = "AWS load balancer controller policy for saga-ra3 EKS cluster"

  policy = jsonencode({
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": [
                "iam:CreateServiceLinkedRole",
                "ec2:DescribeAccountAttributes",
                "ec2:DescribeAddresses",
                "ec2:DescribeInternetGateways",
                "ec2:DescribeVpcs",
                "ec2:DescribeSubnets",
                "ec2:DescribeSecurityGroups",
                "ec2:DescribeInstances",
                "ec2:DescribeNetworkInterfaces",
                "ec2:DescribeTags",
                "ec2:GetCoipPoolUsage",
                "ec2:DescribeCoipPools",
                "elasticloadbalancing:DescribeLoadBalancers",
                "elasticloadbalancing:DescribeLoadBalancerAttributes",
                "elasticloadbalancing:DescribeListeners",
                "elasticloadbalancing:DescribeListenerCertificates",
                "elasticloadbalancing:DescribeSSLPolicies",
                "elasticloadbalancing:DescribeRules",
                "elasticloadbalancing:DescribeTargetGroups",
                "elasticloadbalancing:DescribeTargetGroupAttributes",
                "elasticloadbalancing:DescribeTargetHealth",
                "elasticloadbalancing:DescribeTags"
            ],
            "Resource": "*"
        },
        {
            "Effect": "Allow",
            "Action": [
                "cognito-idp:DescribeUserPoolClient",
                "acm:ListCertificates",
                "acm:DescribeCertificate",
                "iam:ListServerCertificates",
                "iam:GetServerCertificate",
                "waf-regional:GetWebACL",
                "waf-regional:GetWebACLForResource",
                "waf-regional:AssociateWebACL",
                "waf-regional:DisassociateWebACL",
                "wafv2:GetWebACL",
                "wafv2:GetWebACLForResource",
                "wafv2:AssociateWebACL",
                "wafv2:DisassociateWebACL",
                "shield:GetSubscriptionState",
                "shield:DescribeProtection",
                "shield:CreateProtection",
                "shield:DeleteProtection"
            ],
            "Resource": "*"
        },
        {
            "Effect": "Allow",
            "Action": [
                "ec2:AuthorizeSecurityGroupIngress",
                "ec2:RevokeSecurityGroupIngress"
            ],
            "Resource": "*"
        },
        {
            "Effect": "Allow",
            "Action": [
                "ec2:CreateSecurityGroup"
            ],
            "Resource": "*"
        },
        {
            "Effect": "Allow",
            "Action": [
                "ec2:CreateTags"
            ],
            "Resource": "arn:aws:ec2:*:*:security-group/*",
            "Condition": {
                "StringEquals": {
                    "ec2:CreateAction": "CreateSecurityGroup"
                },
                "Null": {
                    "aws:RequestTag/elbv2.k8s.aws/cluster": "false"
                }
            }
        },
        {
            "Effect": "Allow",
            "Action": [
                "ec2:CreateTags",
                "ec2:DeleteTags"
            ],
            "Resource": "arn:aws:ec2:*:*:security-group/*",
            "Condition": {
                "Null": {
                    "aws:RequestTag/elbv2.k8s.aws/cluster": "true",
                    "aws:ResourceTag/elbv2.k8s.aws/cluster": "false"
                }
            }
        },
        {
            "Effect": "Allow",
            "Action": [
                "ec2:AuthorizeSecurityGroupIngress",
                "ec2:RevokeSecurityGroupIngress",
                "ec2:DeleteSecurityGroup"
            ],
            "Resource": "*",
            "Condition": {
                "Null": {
                    "aws:ResourceTag/elbv2.k8s.aws/cluster": "false"
                }
            }
        },
        {
            "Effect": "Allow",
            "Action": [
                "elasticloadbalancing:CreateLoadBalancer",
                "elasticloadbalancing:CreateTargetGroup"
            ],
            "Resource": "*",
            "Condition": {
                "Null": {
                    "aws:RequestTag/elbv2.k8s.aws/cluster": "false"
                }
            }
        },
        {
            "Effect": "Allow",
            "Action": [
                "elasticloadbalancing:CreateListener",
                "elasticloadbalancing:DeleteListener",
                "elasticloadbalancing:CreateRule",
                "elasticloadbalancing:DeleteRule"
            ],
            "Resource": "*"
        },
        {
            "Effect": "Allow",
            "Action": [
                "elasticloadbalancing:AddTags",
                "elasticloadbalancing:RemoveTags"
            ],
            "Resource": [
                "arn:aws:elasticloadbalancing:*:*:targetgroup/*/*",
                "arn:aws:elasticloadbalancing:*:*:loadbalancer/net/*/*",
                "arn:aws:elasticloadbalancing:*:*:loadbalancer/app/*/*"
            ],
            "Condition": {
                "Null": {
                    "aws:RequestTag/elbv2.k8s.aws/cluster": "true",
                    "aws:ResourceTag/elbv2.k8s.aws/cluster": "false"
                }
            }
        },
        {
            "Effect": "Allow",
            "Action": [
                "elasticloadbalancing:ModifyLoadBalancerAttributes",
                "elasticloadbalancing:SetIpAddressType",
                "elasticloadbalancing:SetSecurityGroups",
                "elasticloadbalancing:SetSubnets",
                "elasticloadbalancing:DeleteLoadBalancer",
                "elasticloadbalancing:ModifyTargetGroup",
                "elasticloadbalancing:ModifyTargetGroupAttributes",
                "elasticloadbalancing:DeleteTargetGroup"
            ],
            "Resource": "*",
            "Condition": {
                "Null": {
                    "aws:ResourceTag/elbv2.k8s.aws/cluster": "false"
                }
            }
        },
        {
            "Effect": "Allow",
            "Action": [
                "elasticloadbalancing:RegisterTargets",
                "elasticloadbalancing:DeregisterTargets"
            ],
            "Resource": "arn:aws:elasticloadbalancing:*:*:targetgroup/*/*"
        },
        {
            "Effect": "Allow",
            "Action": [
                "elasticloadbalancing:SetWebAcl",
                "elasticloadbalancing:ModifyListener",
                "elasticloadbalancing:AddListenerCertificates",
                "elasticloadbalancing:RemoveListenerCertificates",
                "elasticloadbalancing:ModifyRule"
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



resource "aws_iam_role" "aws_load_balancer_controller_role" {
    name = "saga-ra3-load-balancer-controller-role"
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
                "${local.cluster_oidc}:sub": "system:serviceaccount:kube-system:aws-load-balancer-controller"
                }
            }
            }
        ]
    })
}

resource "aws_iam_role_policy_attachment" "load_balancer_controller_role_policy" {
  role = aws_iam_role.aws_load_balancer_controller_role.name
  policy_arn = aws_iam_policy.aws_load_balancer_controller_policy.arn
}


provider "kubernetes" {
    config_path    = "~/.kube/config"
}

resource "kubernetes_service_account" "service_account" {
    metadata {
        name = "aws-load-balancer-controller"
        namespace = "kube-system"
        annotations = {
            "eks.amazonaws.com/role-arn" : aws_iam_role.aws_load_balancer_controller_role.arn
        }
    }
}

provider "helm" {
    kubernetes {
        config_path = "~/.kube/config"
    }
}

resource "helm_release" "aws_load_balancer_controller" {
    name = "aws-load-balancer-controller"
    chart = "aws-load-balancer-controller"
    repository = "https://aws.github.io/eks-charts"
    namespace = "kube-system"
    
    set {
        name = "clusterName"
        value = data.aws_eks_cluster.cluster.id
    }
    
    set {
        name = "serviceAccount.create"
        value = "false"
    }

    set {
        name = "serviceAccount.name"
        value = kubernetes_service_account.service_account.metadata[0].name
    }
}

/* 
EXTERNAL DNS
*/

resource "aws_iam_policy" "external_dns_policy" {
  name        = "saga-ra3-external-dns-policy"
  path        = "/"
  description = "External DNS policy for saga-ra3 EKS cluster"

  policy = jsonencode({
    "Version": "2012-10-17",
    "Statement": [
        {
        "Effect": "Allow",
        "Action": [
            "route53:ChangeResourceRecordSets"
        ],
        "Resource": [
            "arn:aws:route53:::hostedzone/*"
        ]
        },
        {
        "Effect": "Allow",
        "Action": [
            "route53:ListHostedZones",
            "route53:ListResourceRecordSets"
        ],
        "Resource": [
            "*"
        ]
        }
    ]
  })
}

resource "aws_iam_role" "external_dns_role" {
    name = "saga-ra3-external-dns-role"
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
                "${local.cluster_oidc}:sub": "system:serviceaccount:default:external-dns"
                }
            }
            }
        ]
    })
}

resource "aws_iam_role_policy_attachment" "external_dns_role_policy" {
  role = aws_iam_role.external_dns_role.name
  policy_arn = aws_iam_policy.external_dns_policy.arn
}

resource "kubernetes_service_account" "external_dns_service_account" {
    metadata {
        name = "external-dns"
        namespace = "default"
        annotations = {
            "eks.amazonaws.com/role-arn" : aws_iam_role.external_dns_role.arn
        }
    }
}

resource "helm_release" "external_dns" {
    name = "external-dns"
    chart = "external-dns"
    repository = "https://charts.bitnami.com/bitnami"
    namespace = "default"
    
    set {
        name = "clusterName"
        value = data.aws_eks_cluster.cluster.id
    }
    
    set {
        name = "serviceAccount.create"
        value = "false"
    }

    set {
        name = "serviceAccount.name"
        value = kubernetes_service_account.external_dns_service_account.metadata[0].name
    }
}