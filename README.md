# Saga reference architecture v3

This repository contains infrastructure configurations for running the saga application's v3 architecture design.

The main features of this application contains
* A kubernetes cluster for running the API and jobs
* An elasticsearch cluster for logging
* Codebuild projects to run GitOps workflows in AWS

The database remains as the standalone mongodb instance running on EC2

## Components

### /infrastructure

A terraform module that contains the following basic infrastructure resources:

| Resource      | Name           | Description  |
| ------------- |:-------------:| :----:|
| aws_eks_cluster     | cluster | The EKS cluster that all workloads (except for DB) would be running on |
| aws_iam_role      | worker_role      | |
| aws_iam_role_policy_attachment | worker-node-eks-policy      | |
| aws_iam_role_policy_attachment | worker-node-ecr-policy      | |
| aws_iam_role_policy_attachment | worker-node-cni-policy      | |
| aws_eks_node_group | nodegroup     | |
| aws_iam_openid_connect_provider | cluster_oidc     | |
| aws_elasticsearch_domain | es_domain     | |

### /plugins

### saga-recommender-api-cicd.yaml

### saga-recommender-api-pipeline.yaml