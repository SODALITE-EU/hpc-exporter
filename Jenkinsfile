pipeline {
    agent { label 'docker-slave' }
    environment {
        // CI-CD vars
        docker_registry_ip = credentials('jenkins-docker-registry-ip')
        // When triggered from git tag, $BRANCH_NAME is actually GIT's tag_name
        TAG_SEM_VER_COMPLIANT = """${sh(
                returnStdout: true,
                script: './docker/validate_tag.sh SemVar $BRANCH_NAME'
            )}"""

        TAG_MAJOR_RELEASE = """${sh(
                returnStdout: true,
                script: './docker/validate_tag.sh MajRel $BRANCH_NAME'
            )}"""

        TAG_PRODUCTION = """${sh(
                returnStdout: true,
                script: './docker/validate_tag.sh production $BRANCH_NAME'
            )}"""

        TAG_STAGING = """${sh(
                returnStdout: true,
                script: './docker/validate_tag.sh staging $BRANCH_NAME'
            )}"""
   }
    stages {
        stage ('Pull repo code from github') {
            steps {
                checkout scm
            }
        }
        stage('Inspect GIT TAG'){
            steps {
                sh """ #!/bin/bash
                echo 'TAG: $BRANCH_NAME'
                echo 'Tag is compliant with SemVar 2.0.0: $TAG_SEM_VER_COMPLIANT'
                echo 'Tag is Major release: $TAG_MAJOR_RELEASE'
                echo 'Tag is production: $TAG_PRODUCTION'
                echo 'Tag is staging: $TAG_STAGING'
                """
            }
        }
        stage('Build HPC-exporter') {
            when {
                allOf {
                    // Triggered on every tag, that is considered for staging or production
                    expression{tag "*"}
                    expression{
                        TAG_STAGING == 'true' || TAG_PRODUCTION == 'true'
                    }
                }
             }
            steps {
                sh "cd docker && ./make_docker.sh build hpc-exporter"
            }
        }
        stage('Push HPC-exporter to DockerHub for staging') {
            when {
                allOf {
                    expression{tag "*"}
                    expression{
                        TAG_STAGING == 'true'
                    }
                }
            }
            steps {
                withDockerRegistry(credentialsId: 'jenkins-sodalite.docker_token', url: '') {
                    sh  """#!/bin/bash
                        ./docker/make_docker.sh push hpc-exporter sodaliteh2020 staging
                        """
                }
            }
        }
        stage('Push HPC-exporter to DockerHub') {
            when {
                allOf {
                    expression{tag "*"}
                    expression{
                        TAG_PRODUCTION == 'true'
                    }
                }
             }
            steps {
                withDockerRegistry(credentialsId: 'jenkins-sodalite.docker_token', url: '') {
                    sh "./docker/make_docker.sh push hpc-exporter sodaliteh2020 production"
                }
            }
        }
    }
}
