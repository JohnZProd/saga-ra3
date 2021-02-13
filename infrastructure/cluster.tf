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


