# Saga reference architecture v3

This repository contains infrastructure configurations for running the saga application's v3 architecture design.

THe main features of this application contains
* A kubernetes cluster for running the API and jobs
* An elasticsearch cluster for logging
* Codebuild projects to run GitOps workflows in AWS

The database remains as the standalone mongodb instance running on EC2

## Components

### /infrastructure

### /plugins

### saga-recommender-api-cicd.yaml

### saga-recommender-api-pipeline.yaml