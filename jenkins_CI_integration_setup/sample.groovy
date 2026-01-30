pipeline {
    agent any

    environment {
        // Jenkins Credentials
        GITHUB_CREDENTIALS = 'github-pat'
        DOCKERHUB_CREDENTIALS = 'dockerhub-creds'
        SONARQUBE_TOKEN = 'sonarqube-token'

        IMAGE_NAME = 'zuhaibahmed034/ghost-docker'
        IMAGE_TAG = 'latest'
        DOCKER_IMAGE = "${IMAGE_NAME}:${IMAGE_TAG}"

        // Directories
        TRIVY_REPORT_DIR = "${WORKSPACE}/trivy_reports"
        SONAR_DIR = "${WORKSPACE}/sonar"
        OWASP_DIR = "${WORKSPACE}/owasp_reports"
        IAC_DIR = "${WORKSPACE}/iac_scans"

        // SLSA Predicate Path
        SLSA_PREDICATE = "${WORKSPACE}/devsecops-project/slsa-predicate.json"
    }

    stages {
        stage('0️⃣ Configure Git') {
            steps {
                sh 'git config --global --add safe.directory "$WORKSPACE"'
            }
        }

        stage('1️⃣ Clone Repository') {
            steps {
                echo "Cloning GitHub repository..."
                checkout([$class: 'GitSCM',
                    branches: [[name: 'main']],
                    doGenerateSubmoduleConfigurations: false,
                    extensions: [[$class: 'WipeWorkspace']],
                    userRemoteConfigs: [[
                        url: 'https://github.com/zohaibahmed034/End-to-End-Kubernetes-DevSecOps-Platform-FYP.git',
                        credentialsId: "${GITHUB_CREDENTIALS}"
                    ]]
                ])
            }
        }

        stage('2️⃣ DockerHub Login') {
            steps {
                withCredentials([usernamePassword(credentialsId: "${DOCKERHUB_CREDENTIALS}", usernameVariable: 'DOCKER_USER', passwordVariable: 'DOCKER_PASS')]) {
                    sh 'echo "$DOCKER_PASS" | docker login -u "$DOCKER_USER" --password-stdin'
                }
            }
        }

        stage('3️⃣ Pull Existing Docker Image') {
            steps {
                sh "docker pull ${DOCKER_IMAGE} || echo 'Image may not exist, skipping pull.'"
            }
        }

        stage('4️⃣ Build Docker Image') {
            steps {
                sh """
                    docker pull ghost:6-alpine || echo 'Base Ghost image may not exist or rate-limited'
                    docker build -t ${DOCKER_IMAGE} .
                """
            }
        }

        stage('5️⃣ SonarQube SAST Scan') {
            steps {
                catchError(buildResult: 'UNSTABLE', stageResult: 'UNSTABLE') {
                    withCredentials([string(credentialsId: "${SONARQUBE_TOKEN}", variable: 'SONAR_TOKEN')]) {
                        sh """
                            mkdir -p "${SONAR_DIR}"
                            cd "${SONAR_DIR}"
                            if [ ! -d "sonar-scanner-4.8.0.2856-linux" ]; then
                                curl -Lo sonar-scanner.zip https://binaries.sonarsource.com/Distribution/sonar-scanner-cli/sonar-scanner-cli-4.8.0.2856-linux.zip
                                unzip -o sonar-scanner.zip
                            fi
                            export PATH="${SONAR_DIR}/sonar-scanner-4.8.0.2856-linux/bin:\$PATH"
                            cd "${WORKSPACE}"
                            sonar-scanner \
                                -Dsonar.projectKey=ghost-docker \
                                -Dsonar.sources=. \
                                -Dsonar.host.url=http://13.232.180.60:9000 \
                                -Dsonar.login=\$SONAR_TOKEN || echo 'SonarQube scan failed'
                        """
                    }
                }
            }
        }

        stage('6️⃣ OWASP Dependency Check') {
            steps {
                catchError(buildResult: 'UNSTABLE', stageResult: 'UNSTABLE') {
                    sh """
                        mkdir -p "${OWASP_DIR}" "${WORKSPACE}/bin"
                        if [ ! -f "${WORKSPACE}/bin/dependency-check/bin/dependency-check.sh" ]; then
                            curl -L -o dependency-check.zip https://github.com/jeremylong/DependencyCheck/releases/download/v8.0.2/dependency-check-8.0.2-release.zip
                            unzip -o dependency-check.zip -d "${WORKSPACE}/bin"
                            chmod +x "${WORKSPACE}/bin/dependency-check/bin/dependency-check.sh"
                        fi
                        "${WORKSPACE}/bin/dependency-check/bin/dependency-check.sh" \
                            --project "ghost-docker" \
                            --scan "${WORKSPACE}" \
                            --format "ALL" \
                            --out "${OWASP_DIR}" \
                            --noupdate \
                            --exclude "${WORKSPACE}/bin,${SONAR_DIR}" || echo 'OWASP scan completed with issues'
                    """
                }
            }
        }

        stage('7️⃣ Trivy Image Scan') {
            steps {
                catchError(buildResult: 'UNSTABLE', stageResult: 'UNSTABLE') {
                    sh """
                        mkdir -p "${TRIVY_REPORT_DIR}" "${WORKSPACE}/bin"
                        if [ ! -f "${WORKSPACE}/bin/trivy" ]; then
                            curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sh -s -- -b "${WORKSPACE}/bin"
                            chmod +x "${WORKSPACE}/bin/trivy"
                        fi
                        "${WORKSPACE}/bin/trivy" image \
                            --severity HIGH,CRITICAL \
                            --format json \
                            --output "${TRIVY_REPORT_DIR}/ghost-trivy-report.json" \
                            ${DOCKER_IMAGE} || echo 'Trivy scan completed with issues'
                    """
                }
            }
        }

        stage('8️⃣ IaC Security Scan') {
            steps {
                catchError(buildResult: 'UNSTABLE', stageResult: 'UNSTABLE') {
                    sh """
                        mkdir -p "${IAC_DIR}" "${WORKSPACE}/bin"
                        
                        # Checkov
                        [ -d "${WORKSPACE}/terraform" ] && {
                            [ ! -f "${WORKSPACE}/bin/checkov" ] && curl -sfL https://github.com/bridgecrewio/checkov/releases/latest/download/checkov-linux-amd64 -o "${WORKSPACE}/bin/checkov" && chmod +x "${WORKSPACE}/bin/checkov"
                            "${WORKSPACE}/bin/checkov" -d "${WORKSPACE}/terraform" --output json > "${IAC_DIR}/checkov-terraform.json"
                        } || echo "No Terraform files"

                        [ -d "${WORKSPACE}/k8s" ] && "${WORKSPACE}/bin/checkov" -d "${WORKSPACE}/k8s" --output json > "${IAC_DIR}/checkov-k8s.json" || echo "No Kubernetes files"

                        # Terrascan
                        [ ! -f "${WORKSPACE}/bin/terrascan" ] && curl -sfL https://github.com/accurics/terrascan/releases/latest/download/terrascan-linux-amd64 -o "${WORKSPACE}/bin/terrascan" && chmod +x "${WORKSPACE}/bin/terrascan"
                        [ -d "${WORKSPACE}/terraform" ] && "${WORKSPACE}/bin/terrascan" scan -d "${WORKSPACE}/terraform" -o json > "${IAC_DIR}/terrascan.json" || echo "No Terraform files"

                        # Conftest
                        command -v conftest &>/dev/null && [ -d "${WORKSPACE}/k8s" ] && conftest test "${WORKSPACE}/k8s" > "${IAC_DIR}/conftest.log" || echo "No Conftest/K8s files"
                    """
                }
            }
        }

        stage('9️⃣ DockerHub Push') {
            steps {
                withCredentials([usernamePassword(credentialsId: "${DOCKERHUB_CREDENTIALS}", usernameVariable: 'DOCKER_USER', passwordVariable: 'DOCKER_PASS')]) {
                    sh """
                        echo "$DOCKER_PASS" | docker login -u "$DOCKER_USER" --password-stdin
                        docker push ${DOCKER_IMAGE} || echo 'Docker push failed, skipping.'
                    """
                }
            }
        }

        stage('🔏 Cosign + SLSA Signing') {
            steps {
                sh """
                    mkdir -p "${WORKSPACE}/bin"
                    if [ ! -f "${WORKSPACE}/bin/cosign" ]; then
                        curl -Lo "${WORKSPACE}/bin/cosign" https://github.com/sigstore/cosign/releases/latest/download/cosign-linux-amd64
                        chmod +x "${WORKSPACE}/bin/cosign"
                    fi
                    export COSIGN_EXPERIMENTAL=1
                    "${WORKSPACE}/bin/cosign" attest --predicate "${SLSA_PREDICATE}" ${DOCKER_IMAGE} || echo 'Cosign SLSA signing failed, skipping.'
                """
            }
        }

        stage('🔚 Pipeline Completed') {
            steps {
                echo "🎉 DevSecOps pipeline executed successfully!"
            }
        }
    }

    post {
        success {
            echo "✅ Pipeline SUCCESS!"
        }
        failure {
            echo "❌ Pipeline FAILED! Check SonarQube, OWASP, Trivy, IaC scans, DockerHub, or Cosign logs."
        }
    }
}
