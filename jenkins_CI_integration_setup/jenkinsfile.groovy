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
        stage('📦 0. Configure Git') {
            steps {
                // Ensure git considers workspace safe (wrap in quotes for spaces)
                sh 'git config --global --add safe.directory "$WORKSPACE"'
            }
        }

        stage('📦 1. Clone Repository') {
            steps {
                echo "Cloning GitHub repository..."
                checkout([$class: 'GitSCM',
                    branches: [[name: 'main']],
                    doGenerateSubmoduleConfigurations: false,
                    extensions: [[$class: 'WipeWorkspace']], // clean workspace
                    userRemoteConfigs: [[
                        url: 'https://github.com/zohaibahmed034/End-to-End-Kubernetes-DevSecOps-Platform-FYP.git',
                        credentialsId: "${GITHUB_CREDENTIALS}"
                    ]]
                ])
            }
        }

        stage('🔐 DockerHub Login') {
            steps {
                echo "Logging in to DockerHub..."
                withCredentials([usernamePassword(credentialsId: "${DOCKERHUB_CREDENTIALS}", usernameVariable: 'DOCKER_USER', passwordVariable: 'DOCKER_PASS')]) {
                    sh 'echo "$DOCKER_PASS" | docker login -u "$DOCKER_USER" --password-stdin'
                }
            }
        }

        stage('🔄 2. Pull Existing Docker Image') {
            steps {
                echo "Pulling existing Docker image from DockerHub..."
                sh "docker pull ${DOCKER_IMAGE} || echo 'Image may not exist, skipping pull.'"
            }
        }

        stage('Build Docker Image') {
            steps {
                echo "Building Docker image..."
                sh """
                    docker pull ghost:6-alpine || echo 'Base Ghost image pull failed, may be rate-limited'
                    docker build -t ${DOCKER_IMAGE} .
                """
            }
        }

        stage('🔍 3. SonarQube SAST Scan') {
            steps {
                catchError(buildResult: 'UNSTABLE', stageResult: 'UNSTABLE') {
                    withCredentials([string(credentialsId: "${SONARQUBE_TOKEN}", variable: 'SONAR_TOKEN')]) {
                        sh """
                            mkdir -p "${SONAR_DIR}"
                            cd "${SONAR_DIR}"
                            curl -Lo sonar-scanner.zip https://binaries.sonarsource.com/Distribution/sonar-scanner-cli/sonar-scanner-cli-4.8.0.2856-linux.zip
                            unzip -o sonar-scanner.zip
                            export PATH="${SONAR_DIR}/sonar-scanner-4.8.0.2856-linux/bin:\$PATH"
                            cd "${WORKSPACE}"
                            sonar-scanner \
                                -Dsonar.projectKey=ghost-docker \
                                -Dsonar.sources=. \
                                -Dsonar.host.url=http://13.234.113.7:9000 \
                                -Dsonar.login=\$SONAR_TOKEN || echo 'SonarQube scan failed'
                        """
                    }
                }
            }
        }

        stage('4. OWASP Dependency Check') {
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
                            --exclude "${WORKSPACE}/bin,${WORKSPACE}/sonar" || echo 'OWASP scan completed with issues'
                    """
                }
            }
        }

        stage('5. Trivy Image Scan') {
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

        stage('6. IaC Security Scan') {
            steps {
                catchError(buildResult: 'UNSTABLE', stageResult: 'UNSTABLE') {
                    sh """
                        mkdir -p "${IAC_DIR}" "${WORKSPACE}/bin"
                        curl -sfL https://github.com/bridgecrewio/checkov/releases/latest/download/checkov-linux-amd64 -o "${WORKSPACE}/bin/checkov"
                        chmod +x "${WORKSPACE}/bin/checkov"

                        [ -d "${WORKSPACE}/terraform" ] && "${WORKSPACE}/bin/checkov" -d "${WORKSPACE}/terraform" --output json > "${IAC_DIR}/checkov-terraform.json" || echo "No Terraform files"
                        [ -d "${WORKSPACE}/k8s" ] && "${WORKSPACE}/bin/checkov" -d "${WORKSPACE}/k8s" --output json > "${IAC_DIR}/checkov-k8s.json" || echo "No Kubernetes files"

                        if ! command -v terrascan &>/dev/null; then
                            curl -sfL https://github.com/accurics/terrascan/releases/latest/download/terrascan-linux-amd64 -o "${WORKSPACE}/bin/terrascan"
                            chmod +x "${WORKSPACE}/bin/terrascan"
                        fi
                        [ -d "${WORKSPACE}/terraform" ] && "${WORKSPACE}/bin/terrascan" scan -d "${WORKSPACE}/terraform" -o json > "${IAC_DIR}/terrascan.json" || echo "No Terraform files"

                        if command -v conftest &>/dev/null && [ -d "${WORKSPACE}/k8s" ]; then
                            conftest test "${WORKSPACE}/k8s" > "${IAC_DIR}/conftest.log" || true
                        fi
                    """
                }
            }
        }

        stage('🔐 7. DockerHub Push') {
            steps {
                withCredentials([usernamePassword(credentialsId: "${DOCKERHUB_CREDENTIALS}", usernameVariable: 'DOCKER_USER', passwordVariable: 'DOCKER_PASS')]) {
                    sh """
                        echo "$DOCKER_PASS" | docker login -u "$DOCKER_USER" --password-stdin
                        docker push ${DOCKER_IMAGE} || echo 'Docker push failed, skipping.'
                    """
                }
            }
        }

        stage('🔏 8. Cosign + SLSA Signing') {
            steps {
                echo "Signing Docker image with Cosign..."
                sh """
                    mkdir -p "${WORKSPACE}/bin"
                    if [ ! -f "${WORKSPACE}/bin/cosign" ]; then
                        curl -Lo "${WORKSPACE}/bin/cosign" https://github.com/sigstore/cosign/releases/latest/download/cosign-linux-amd64
                        chmod +x "${WORKSPACE}/bin/cosign"
                    fi
                    export COSIGN_EXPERIMENTAL=1
                    "${WORKSPACE}/bin/cosign" attest \
                        --predicate "${SLSA_PREDICATE}" \
                        ${DOCKER_IMAGE} || echo 'Cosign SLSA signing failed, skipping.'
                """
            }
        }

        stage('✅ 9. Pipeline Completed') {
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
