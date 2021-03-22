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

data "aws_region" "current" {}

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

/*
Install prometheus
*/

resource "kubernetes_namespace" "prometheus_namespace" {
    metadata {
        name = "prometheus"
    }
}

resource "helm_release" "prometheus" {
    name = "prometheus"
    chart = "prometheus"
    repository = "https://prometheus-community.github.io/helm-charts"
    namespace = kubernetes_namespace.prometheus_namespace.metadata[0].name

    set {
        name = "alertmanager.persistentVolume.storageClass"
        value = "gp2"
    }

    set {
        name = "server.persistentVolume.storageClass"
        value = "gp2"
    }
}

/*
Install grafana
*/

variable "grafana_password" {
    type = string
}

resource "kubernetes_namespace" "grafana_namespace" {
    metadata {
        name = "grafana"
    }
}

resource "helm_release" "grafana" {
    name = "grafana"
    chart = "grafana"
    repository = "https://grafana.github.io/helm-charts"
    namespace = kubernetes_namespace.grafana_namespace.metadata[0].name

    set {
        name = "persistence.storageClassName"
        value = "gp2"
    }

    set {
        name = "persistence.enabled"
        value = "true"
    }

    set {
        name = "adminPassword"
        value = var.grafana_password
    }

    set {
        name = "service.type"
        value = "LoadBalancer"
    }

    values = [
        "${file("grafana.yaml")}"
    ]
}

/*
Install fluentbit
*/

variable "es_domain_name" {
    type = string
}

variable "es_domain_user" {
    type = string
}

variable "es_domain_password" {
    type = string 
}

data "aws_elasticsearch_domain" "es" {
    domain_name = var.es_domain_name
}

resource "aws_iam_policy" "fluent_bit_policy" {
    name = "saga-ra3-fluent-bit-policy"
    path        = "/"
    description = "Policy for the fluentbit log aggregator"
    policy = jsonencode({
        "Version": "2012-10-17",
        "Statement": [
            {
                "Action": [
                    "es:ESHttp*"
                ],
                "Resource": "arn:aws:es:${data.aws_region.current.name}:${data.aws_caller_identity.current.account_id}:domain/${var.es_domain_name}",
                "Effect": "Allow"
            }
        ]
    })
}

resource "kubernetes_namespace" "logging_namespace" {
    metadata {
        name = "logging"
    }
}

resource "aws_iam_role" "fluent_bit_role" {
    name = "saga-ra3-fluent-bit-role"
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
                "${local.cluster_oidc}:sub": "system:serviceaccount:logging:fluent-bit"
                }
            }
            }
        ]
    })
}

resource "aws_iam_role_policy_attachment" "fluent_bit_role_policy" {
    role = aws_iam_role.fluent_bit_role.name
    policy_arn = aws_iam_policy.fluent_bit_policy.arn

    provisioner "local-exec" {
        command = "curl -sS -u \"${var.es_domain_user}:${var.es_domain_password}\" -X PATCH https://${data.aws_elasticsearch_domain.es.endpoint}/_opendistro/_security/api/rolesmapping/all_access?pretty -H 'Content-Type: application/json' -d '[{\"op\": \"add\", \"path\": \"/backend_roles\", \"value\": [\"'${aws_iam_role.fluent_bit_role.name}'\"]}]'"
    }
}

resource "kubernetes_service_account" "fleunt_bit_service_account" {
    metadata {
        name = "fleunt-bit"
        namespace = "logging"
        annotations = {
            "eks.amazonaws.com/role-arn" : aws_iam_role.fluent_bit_role.arn
        }
    }
}

resource "helm_release" "fluent_bit" {
    name = "fluent_bit"
    chart = "aws-for-fluent-bit"
    repository = "https://aws.github.io/eks-charts"
    namespace = "logging"
    
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
        value = kubernetes_service_account.fleunt_bit_service_account.metadata[0].name
    }
}