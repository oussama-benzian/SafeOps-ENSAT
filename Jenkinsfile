pipeline {
    agent any
    
    environment {
        IMAGE_TAG = "${BUILD_NUMBER}"
        SONAR_HOST_URL = 'http://sonarqube:9000'
    }
    
    options {
        buildDiscarder(logRotator(numToKeepStr: '10'))
        timestamps()
        timeout(time: 30, unit: 'MINUTES')
        disableConcurrentBuilds()
    }
    
    stages {
        stage('Checkout') {
            steps {
                checkout scm
                sh 'git log -1 --pretty=format:"%h - %s (%an, %ar)"'
            }
        }
        
        stage('SonarQube Analysis') {
            steps {
                withCredentials([string(credentialsId: 'sonar-token', variable: 'SONAR_TOKEN')]) {
                    sh '''
                        sonar-scanner \
                            -Dsonar.host.url=${SONAR_HOST_URL} \
                            -Dsonar.token=${SONAR_TOKEN}
                    '''
                }
            }
        }
        
        stage('Build Docker Images') {
            parallel {
                stage('log-collector') {
                    steps {
                        dir('services/log-collector') {
                            sh "docker build -t safeops-log-collector:${IMAGE_TAG} ."
                        }
                    }
                }
                stage('log-parser') {
                    steps {
                        dir('services/log-parser') {
                            sh "docker build -t safeops-log-parser:${IMAGE_TAG} ."
                        }
                    }
                }
                stage('vuln-detector') {
                    steps {
                        dir('services/vuln-detector') {
                            sh "docker build -t safeops-vuln-detector:${IMAGE_TAG} ."
                        }
                    }
                }
                stage('fix-suggester') {
                    steps {
                        dir('services/fix-suggester') {
                            sh "docker build -t safeops-fix-suggester:${IMAGE_TAG} ."
                        }
                    }
                }
                stage('anomaly-detector') {
                    steps {
                        dir('services/anomaly-detector') {
                            sh "docker build -t safeops-anomaly-detector:${IMAGE_TAG} ."
                        }
                    }
                }
                stage('report-generator') {
                    steps {
                        dir('services/report-generator') {
                            sh "docker build -t safeops-report-generator:${IMAGE_TAG} ."
                        }
                    }
                }
                stage('dashboard') {
                    steps {
                        dir('services/dashboard') {
                            sh "docker build -t safeops-dashboard:${IMAGE_TAG} ."
                        }
                    }
                }
            }
        }
    }
    
    post {
        success {
            echo "Pipeline completed successfully! Build: ${BUILD_NUMBER}"
            sh 'docker images | grep safeops || true'
        }
        failure {
            echo "Pipeline failed! Check the logs for details."
        }
        always {
            cleanWs()
        }
    }
}
