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

  version = "1.17"
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
        desired_size = 1
        max_size     = 1
        min_size     = 1
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