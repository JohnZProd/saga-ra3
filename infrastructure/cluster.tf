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

data "aws_caller_identity" "current" {}

data "aws_region" "current" {}

variable "cluster_role_arn" {
    type = string
}

variable "private_subnet_1" {
    type = string
}

variable "private_subnet_2" {
    type = string
}

variable "public_subnet_1" {
    type = string
}

variable "public_subnet_2" {
    type = string
}

variable "cluster_name" {
    type = string
}

variable "worker_ssh_key" {
    type = string
}

resource "aws_eks_cluster" "cluster" {
  name     = var.cluster_name
  role_arn = var.cluster_role_arn

  vpc_config {
    subnet_ids = [
        var.private_subnet_1,
        var.private_subnet_2,
        var.public_subnet_1,
        var.public_subnet_2
    ]
    endpoint_private_access = true
    endpoint_public_access = true
  }

  kubernetes_network_config {
    service_ipv4_cidr = "172.20.0.0/16"
  }

  version = "1.18"
}

resource "aws_iam_role" "worker_role" {
    name = "saga-ra3-worker-role"
    
    assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Sid    = ""
        Principal = {
          Service = "ec2.amazonaws.com"
        }
      },
    ]
  })
}

resource "aws_iam_role_policy_attachment" "worker-node-eks-policy" {
  role = aws_iam_role.worker_role.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonEKSWorkerNodePolicy"
}

resource "aws_iam_role_policy_attachment" "worker-node-ecr-policy" {
  role = aws_iam_role.worker_role.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonEC2ContainerRegistryReadOnly"
}

resource "aws_iam_role_policy_attachment" "worker-node-cni-policy" {
  role = aws_iam_role.worker_role.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonEKS_CNI_Policy"
}

resource "aws_eks_node_group" "nodegroup" {
    cluster_name = aws_eks_cluster.cluster.name
    node_group_name = "nodegroup"
    node_role_arn = aws_iam_role.worker_role.arn
    subnet_ids = [
        var.private_subnet_1,
        var.private_subnet_2
    ]
    
    scaling_config {
        desired_size = 2
        max_size     = 2
        min_size     = 2
    }

    remote_access {
        ec2_ssh_key = var.worker_ssh_key
    }

    depends_on = [
        aws_iam_role_policy_attachment.worker-node-eks-policy,
        aws_iam_role_policy_attachment.worker-node-ecr-policy,
        aws_iam_role_policy_attachment.worker-node-cni-policy
  ]
}

data "tls_certificate" "thumbprint" {
  url = aws_eks_cluster.cluster.identity[0].oidc[0].issuer
}

resource "aws_iam_openid_connect_provider" "cluster_oidc" {
    url = aws_eks_cluster.cluster.identity[0].oidc[0].issuer
    client_id_list = ["sts.amazonaws.com"]
    thumbprint_list = [data.tls_certificate.thumbprint.certificates[0].sha1_fingerprint]
}

/*
Elasticsearch Cluster
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

resource "aws_elasticsearch_domain" "es_domain" {
    domain_name = var.es_domain_name
    elasticsearch_version = "7.4"

    cluster_config {
        instance_type = "t3.small.elasticsearch"
        instance_count = 1
        dedicated_master_enabled = "false"
        zone_awareness_enabled = "false"
        warm_enabled = "false"
    }

    ebs_options {
        ebs_enabled = "true"
        volume_type = "gp2"
        volume_size = 100
    }

    access_policies = <<POLICY
    {
        "Version":"2012-10-17",
        "Statement":[{
            "Effect": "Allow",
            "Principal":{
                "AWS":"*"
            },
            "Action": "es:ESHttp*",
            "Resource": "arn:aws:es:${data.aws_region.current.name}:${data.aws_caller_identity.current.account_id}:domain/${var.es_domain_name}/*"
        }]
    }
    POLICY

    encrypt_at_rest {
        enabled = "true"
    }

    node_to_node_encryption {
        enabled = "true"
    }

    domain_endpoint_options {
        enforce_https = "true"
        tls_security_policy = "Policy-Min-TLS-1-0-2019-07"
    }

    advanced_security_options {
        enabled = "true"
        internal_user_database_enabled = "true"
        master_user_options {
            master_user_name = var.es_domain_user
            master_user_password = var.es_domain_password
        }
    }
}