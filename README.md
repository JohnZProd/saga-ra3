# Saga reference architecture v3

This repository contains infrastructure configurations for running the saga application's v3 architecture design in AWS.

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
| aws_iam_role      | worker_role      | The IAM role attached to the worker nodes as an instance profile (see https://docs.aws.amazon.com/eks/latest/userguide/create-node-role.html) - Note that this role includes the CNI policy |
| aws_iam_role_policy_attachment | worker-node-eks-policy      | Attachment of the EKS node policy onto the role |
| aws_iam_role_policy_attachment | worker-node-ecr-policy      | Attachment of the ECR read-only policy onto the role |
| aws_iam_role_policy_attachment | worker-node-cni-policy      | Attachment of the CNI policy onto the role|
| aws_eks_node_group | nodegroup     | The main nodegroup of the EKS cluster |
| aws_iam_openid_connect_provider | cluster_oidc     | The IAM OIDC provider that enables IAM service accounts for workloads (see https://docs.aws.amazon.com/eks/latest/userguide/iam-roles-for-service-accounts.html) |
| aws_elasticsearch_domain | es_domain     | The managed elasticsearch domain in AWS that allows for log analysis |

### /plugins

### saga-recommender-api-cicd.yaml

### saga-recommender-api-pipeline.yaml