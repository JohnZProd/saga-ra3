# Saga reference architecture v3

This repository contains infrastructure configurations for running the saga application's v3 architecture design in AWS.

The main features of this application contains
* A kubernetes cluster for running the API and jobs
* An elasticsearch cluster for logging
* Codebuild projects to run GitOps workflows in AWS

The database remains as the standalone mongodb instance running on EC2

## Components

### infrastructure/

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

### plugins/

A terraform moule that contains all required plugins and integrations to setup the cluster platform

| Resource      | Name           | Description  |
| ------------- |:-------------:| :----:|
| aws_iam_policy     | aws_load_balancer_controller_policy | The IAM policy that outlines the AWS permissions granted to the load balancer controller (see https://docs.aws.amazon.com/eks/latest/userguide/aws-load-balancer-controller.html) |
| aws_iam_role     | aws_load_balancer_controller_role | The IAM role attached to the service account provided to the load balancer controller (see https://docs.aws.amazon.com/eks/latest/userguide/aws-load-balancer-controller.html) |
| aws_iam_role_policy_attachment     | load_balancer_controller_role_policy | Attachment of the load balancer controller policy to role |
| kubernetes_service_account     | service_account | AWS load balancer controller service account in the cluster with an IRSA on the above role (see https://docs.aws.amazon.com/eks/latest/userguide/aws-load-balancer-controller.html) |
| helm_release     | aws_load_balancer_controller | Helm release of the load balancer controller |
| aws_iam_policy     | external_dns_policy | The IAM policy that outlines the AWS permissions granted to the External DNS plugin (see https://github.com/kubernetes-sigs/external-dns/blob/master/docs/tutorials/aws.md) |
| aws_iam_role     | external_dns_role |  The role attached to the service account provided to exernal DNS |
| aws_iam_role_policy_attachment     | external_dns_role_policy | Attachment of the external DNS policy to role |
| kubernetes_service_account     | external_dns_service_account | External DNS service account in the cluster with an IRSA on its role |
| helm_release     | external_dns | Helm release of external DNS (see https://artifacthub.io/packages/helm/bitnami/external-dns) |
| kubernetes_namespace     | prometheus_namespace | The Kubernetes namespace used for prometheus cluster monitoring |
| helm_release     | prometheus | The Helm chart installing the prometheus application on the cluster |
| kubernetes_namespace     | grafana_namespace | The Kubernetes namespace used for grafana metric visualisation |
| helm_release     | grafana | The Helm chart installing the grafana application on the cluster, will create an AWS CLB to expose the grafana endpoint |
| aws_iam_policy     | fluent_bit_policy | The IAM policy that outlines the AWS permissions granted to the fluentbit pods |
| kubernetes_namespace     | logging_namespace | The Kubernetes namespace used for fluent logging capability |
| aws_iam_role     | fluent_bit_role | The IAM role attached to the service account provided to the fluentbit pods |
| aws_iam_role_policy_attachment     | fluent_bit_role_policy | Attachment of the fluentbit policy to role |
| kubernetes_service_account     | fluent_bit_service_account | Fluentbit service account in the cluster with an IRSA on the above role |
| helm_release     | fluent_bit | Helm release of the fluentbit daemonset |

This directory also includes a grafana.yaml file which the Helm release for grafana uses to set out parameters to setup the grafana datasource

### saga-recommender-api-cicd.yaml

### saga-recommender-api-pipeline.yaml