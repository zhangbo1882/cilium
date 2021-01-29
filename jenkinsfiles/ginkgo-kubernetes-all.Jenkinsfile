@Library('cilium') _

pipeline {
    agent any

    parameters {
        string(defaultValue: '${ghprbPullDescription}', name: 'ghprbPullDescription')
        string(defaultValue: '${ghprbActualCommit}', name: 'ghprbActualCommit')
        string(defaultValue: '${ghprbTriggerAuthorLoginMention}', name: 'ghprbTriggerAuthorLoginMention')
        string(defaultValue: '${ghprbPullAuthorLoginMention}', name: 'ghprbPullAuthorLoginMention')
        string(defaultValue: '${ghprbGhRepository}', name: 'ghprbGhRepository')
        string(defaultValue: '${ghprbPullLongDescription}', name: 'ghprbPullLongDescription')
        string(defaultValue: '${ghprbCredentialsId}', name: 'ghprbCredentialsId')
        string(defaultValue: '${ghprbTriggerAuthorLogin}', name: 'ghprbTriggerAuthorLogin')
        string(defaultValue: '${ghprbPullAuthorLogin}', name: 'ghprbPullAuthorLogin')
        string(defaultValue: '${ghprbTriggerAuthor}', name: 'ghprbTriggerAuthor')
        string(defaultValue: '${ghprbCommentBody}', name: 'ghprbCommentBody')
        string(defaultValue: '${ghprbPullTitle}', name: 'ghprbPullTitle')
        string(defaultValue: '${ghprbPullLink}', name: 'ghprbPullLink')
        string(defaultValue: '${ghprbAuthorRepoGitUrl}', name: 'ghprbAuthorRepoGitUrl')
        string(defaultValue: '${ghprbTargetBranch}', name: 'ghprbTargetBranch')
        string(defaultValue: '${ghprbPullId}', name: 'ghprbPullId')
        string(defaultValue: '${ghprbActualCommitAuthor}', name: 'ghprbActualCommitAuthor')
        string(defaultValue: '${ghprbActualCommitAuthorEmail}', name: 'ghprbActualCommitAuthorEmail')
        string(defaultValue: '${ghprbTriggerAuthorEmail}', name: 'ghprbTriggerAuthorEmail')
        string(defaultValue: '${GIT_BRANCH}', name: 'GIT_BRANCH')
        string(defaultValue: '${ghprbPullAuthorEmail}', name: 'ghprbPullAuthorEmail')
        string(defaultValue: '${sha1}', name: 'sha1')
        string(defaultValue: '${ghprbSourceBranch}', name: 'ghprbSourceBranch')
    }

    environment {
        BAREMETAL_K8S_JOB = "/baremetal/baremetal-k8s"
    }

    options {
        timeout(time: 540, unit: 'MINUTES')
        timestamps()
        ansiColor('xterm')
    }

    stages {
        stage('Trigger parallel baremetal k8s builds') {
            parallel {
                stage('1.14') {
                    steps {
                        build(job: "${BAREMETAL_K8S_JOB}", parameters: [
                            string(name: 'K8S_VERSION', value: "1.14"),
                            string(name: 'GIT_BRANCH', value: "${GIT_BRANCH}")
                        ])
                    }
                }

                stage('1.15') {
                    steps {
                        build(job: "${BAREMETAL_K8S_JOB}", parameters: [
                            string(name: 'K8S_VERSION', value: "1.15"),
                            string(name: 'GIT_BRANCH', value: "${GIT_BRANCH}")
                        ])
                    }
                }

                stage('1.16') {
                    steps {
                        build(job: "${BAREMETAL_K8S_JOB}", parameters: [
                            string(name: 'K8S_VERSION', value: "1.16"),
                            string(name: 'GIT_BRANCH', value: "${GIT_BRANCH}")
                        ])
                    }
                }

                stage('1.17') {
                    steps {
                        build(job: "${BAREMETAL_K8S_JOB}", parameters: [
                            string(name: 'K8S_VERSION', value: "1.17"),
                            string(name: 'GIT_BRANCH', value: "${GIT_BRANCH}")
                        ])
                    }
                }

                stage('1.18') {
                    steps {
                        build(job: "${BAREMETAL_K8S_JOB}", parameters: [
                            string(name: 'K8S_VERSION', value: "1.18"),
                            string(name: 'GIT_BRANCH', value: "${GIT_BRANCH}")
                        ])
                    }
                }

                stage('1.19') {
                    steps {
                        build(job: "${BAREMETAL_K8S_JOB}", parameters: [
                            string(name: 'K8S_VERSION', value: "1.19"),
                            string(name: 'GIT_BRANCH', value: "${GIT_BRANCH}")
                        ])
                    }
                }
            }
        }
    }
    post {
        success {
            Status("SUCCESS", "${env.JOB_NAME}")
        }
        failure {
            Status("FAILURE", "${env.JOB_NAME}")
        }
    }
}
