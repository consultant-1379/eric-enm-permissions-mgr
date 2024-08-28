#!/usr/bin/env groovy

/* IMPORTANT:
 *
 * In order to make this pipeline work, the following configuration on Jenkins is required:
 * - slave with a specific label (see pipeline.agent.label below)
 * - credentials plugin should be installed and have the secrets with the following names:
 *   + lciadm100credentials (token to access Artifactory)
 */

def defaultBobImage = 'armdocker.rnd.ericsson.se/sandbox/adp-staging/adp-cicd/bob.2.0:1.7.0-52'
def bob = new BobCommand()
        .bobImage(defaultBobImage)
        .envVars([ISO_VERSION: '${ISO_VERSION}'])
        .needDockerSocket(true)
        .toString()
def GIT_COMMITTER_NAME = 'enmadm100'
def GIT_COMMITTER_EMAIL = 'enmadm100@ericsson.com'
def failedStage = ''

def emailReport() {
    def mail_list = ["eric-enm-omnidaemon":"PDLTORDEPL@pdl.internal.ericsson.com","eric-enmsg-elex":"EricssonHyderabad.ENMMisty@tcs.com"]
        mail_list.each { each_repo,each_email ->
            if (each_repo == env.Repo.split('/').last()) {
                def Repo_Mail = each_email;
                try {
                    mail to: "${Repo_Mail}",
                    subject: "Failed Pipeline: ${currentBuild.fullDisplayName}",
                    body: "Failure on ${env.BUILD_URL}"
                } catch( err ){
                     echo "$err"
                }
            }
        };
}

pipeline {
    agent {
        label 'Cloud-Native'
    }
    parameters {
        string(name: 'ISO_VERSION', description: 'The ENM ISO version (e.g. 1.65.77)')
        string(name: 'SPRINT_TAG', description: 'Tag for GIT tagging the repository after build')
        string(name: 'PRODUCT_SET', description: 'cENM product set (e.g. 21.1.13-1)')
    }
    environment {
        GERRIT_HTTP_CREDENTIALS_FUser = credentials('FUser_gerrit_http_username_password')
    }
    stages {
        stage('Clean') {
            steps {
                deleteDir()
            }
        }
        stage('Inject Credential Files') {
            steps {
                withCredentials([file(credentialsId: 'lciadm100-docker-auth', variable: 'dockerConfig')]) {
                    //sh "install -m 600 ${dockerConfig} ${HOME}/.docker/config.json"
                    sh '''    
                        if [ ! -f ${HOME}/.docker/config.json ]; then
                            echo "File not found!  Installing permission change file"
                            install -m 600 ${dockerConfig} ${HOME}/.docker/config.json
                        else
                            echo "Config.json file exists . Moving to next stage"
                        fi
                    '''
                }
            }
        }
        stage('Checkout Cloud-Native SG Git Repository') {
            steps {
                git branch: 'master',
                    credentialsId: 'enmadm100_private_key',
                     url: '${GERRIT_MIRROR}/'+env.REPO
                sh '''
                    git remote set-url origin --push https://${GERRIT_HTTP_CREDENTIALS_FUser}@${GERRIT_CENTRAL_HTTP_E2E}/${REPO}
                '''
            }
        }
        stage('Helm Dep Up ') {
            steps {
                sh "${bob} -r bob/ruleset2.0.yaml helm-dep-up-predeploy"
                sh "${bob} -r bob/ruleset2.0.yaml helm-dep-up-stateless"
            }
            post {
                failure {
                    script {
                        failedStage = env.STAGE_NAME
                    }
                }
            }
        }
        stage('Helm Lint') {
            steps {
                sh "${bob} -r bob/ruleset2.0.yaml lint-helm-predeploy"
                sh "${bob} -r bob/ruleset2.0.yaml lint-helm-stateless"
            }
            post {
                failure {
                    script {
                        failedStage = env.STAGE_NAME
                    }
                }
            }
        }
        stage('Linting Dockerfile') {
            steps {
                sh "${bob} -r bob/ruleset2.0.yaml lint-dockerfile"
                archiveArtifacts 'dockerfilelint.log'
            }
            post {
                failure {
                    script {
                        failedStage = env.STAGE_NAME
                    }
                }
            }
        }
        stage('ADP Helm Design Rule Check') {
            steps {
                sh "${bob} -r bob/ruleset2.0.yaml test-helm-predeploy || true"
                sh "${bob} -r bob/ruleset2.0.yaml test-helm-stateless || true"
                archiveArtifacts 'design-rule-check-report.*'
            }
            post {
                failure {
                    script {
                        failedStage = env.STAGE_NAME
                    }
                }
            }
        }
        stage('Swap versions in Dockerfile and values.yaml file') {
            steps{
                echo sh(script: 'env', returnStdout:true)
                step ([$class: 'CopyArtifact', projectName: 'sync-build-trigger', filter: "*"]);
                sh "${bob} -r bob/ruleset2.0.yaml swap-latest-versions-with-numbers"
                sh '''
                     if git status | grep 'Dockerfile\\|values.yaml' > /dev/null; then
                         git commit -m "NO JIRA - Updating Dockerfile and Values.yaml files with base images version"
                         git push origin HEAD:master
                    else
                        echo `date` > timestamp
                        git add timestamp
                        git commit -m "NO JIRA - Time Stamp "
                        git push origin HEAD:master
                     fi
                 '''
            }
        }
        stage('Build Image and Chart') {
            steps {
                sh "${bob} -r bob/ruleset2.0.yaml generate-new-version build-helm-predeploy build-helm-stateless build-image-with-all-tags"
            }
            post {
                failure {
                    script {
                        failedStage = env.STAGE_NAME
                        sh "${bob} -r bob/ruleset2.0.yaml remove-image-with-all-tags"
                    }
                }
            }
        }
        stage('Retrieve image version') {
            steps {
                script {
                    env.IMAGE_TAG = sh(script: "cat .bob/var.version", returnStdout:true).trim()
                    echo "${IMAGE_TAG}"
                }
            }
            post {
                failure {
                    script {
                        failedStage = env.STAGE_NAME
                        sh "${bob} -r bob/ruleset2.0.yaml remove-image-with-all-tags"
                    }
                }
            }
        }
        stage('Generate ADP Parameters Predeploy') {
            steps {
                sh "${bob} -r bob/ruleset2.0.yaml generate-output-parameters-predeploy"
                archiveArtifacts 'artifact.properties'
            }
            post {
                failure {
                    script {
                        failedStage = env.STAGE_NAME
                    }
                }
            }
        }
        stage('Generate ADP Parameters Stateless') {
            steps {
                sh "${bob} -r bob/ruleset2.0.yaml generate-output-parameters-stateless"
                archiveArtifacts 'artifact.properties'
            }
            post {
                failure {
                    script {
                        failedStage = env.STAGE_NAME
                    }
                }
            }
        }
        stage('Publish Images to Artifactory') {
            steps {
                sh "${bob} -r bob/ruleset2.0.yaml push-image-with-all-tags"
            }
            post {
                failure {
                    script {
                        failedStage = env.STAGE_NAME
                        sh "${bob} -r bob/ruleset2.0.yaml remove-image-with-all-tags"
                    }
                }
                always {
                    sh "${bob} -r bob/ruleset2.0.yaml remove-image-with-all-tags"
                }
            }
        }
        stage('Publish Helm Chart') {
            steps {
                script {
                    withCredentials([string(credentialsId: 'lciadm100', variable: 'HELM_REPO_TOKEN')]) {
                        def bobWithHelmToken = new BobCommand()
                                .bobImage(defaultBobImage)
                                .needDockerSocket(true)
                                .envVars(['HELM_REPO_TOKEN': env.HELM_REPO_TOKEN])
                                .toString()
                        sh "${bobWithHelmToken} -r bob/ruleset2.0.yaml push-helm-predeploy"
                        sh "${bobWithHelmToken} -r bob/ruleset2.0.yaml push-helm-stateless"
                    }
                }
            }
        }
        stage('Tag Cloud-Native SG Git Repository') {
            steps {
                wrap([$class: 'BuildUser']) {
                    script {
                        def bobWithCommitterInfo = new BobCommand()
                                .bobImage(defaultBobImage)
                                .needDockerSocket(true)
                                .envVars([
                                        'AUTHOR_NAME'        : "\${BUILD_USER:-${GIT_COMMITTER_NAME}}",
                                        'AUTHOR_EMAIL'       : "\${BUILD_USER_EMAIL:-${GIT_COMMITTER_EMAIL}}",
                                        'GIT_COMMITTER_NAME' : "${GIT_COMMITTER_NAME}",
                                        'GIT_COMMITTER_EMAIL': "${GIT_COMMITTER_EMAIL}"
                                ])
                                .toString()
                        sh "${bobWithCommitterInfo} -r bob/ruleset2.0.yaml create-git-tag"
                        sh """
                            tag_id=\$(cat .bob/var.version)
                            git push origin \${tag_id}
                        """
                    }
                }
            }
            post {
                failure {
                    script {
                        failedStage = env.STAGE_NAME
                    }
                }
                always {
                    script {
                        sh "${bob} -r bob/ruleset2.0.yaml remove-git-tag"
                    }
                }
            }
        }
        stage('Generate Metadata Parameters') {
            steps {
                sh "${bob} -r bob/ruleset2.0.yaml generate-metadata-parameters-predeploy"
                sh "${bob} -r bob/ruleset2.0.yaml generate-metadata-parameters-stateless"
                archiveArtifacts 'image-metadata-artifact.json'
            }
        }
    }
    post {
        success {
            script {
                sh '''
                    set +x
                    git tag --annotate --message "Tagging latest in sprint" --force $SPRINT_TAG HEAD
                    git push --force origin $SPRINT_TAG
                    git tag --annotate --message "Tagging latest in sprint with ISO version" --force ${SPRINT_TAG}_iso_${ISO_VERSION} HEAD
                    git push --force origin ${SPRINT_TAG}_iso_${ISO_VERSION}
                    git tag --annotate --message "Tagging latest in sprint with Product Set version" --force ps_${PRODUCT_SET} HEAD
                    git push --force origin ps_${PRODUCT_SET}
                '''
            }
        }
        failure {
            script {
                emailReport()
            }
        }
    }
}

// More about @Builder: http://mrhaki.blogspot.com/2014/05/groovy-goodness-use-builder-ast.html
import groovy.transform.builder.Builder
import groovy.transform.builder.SimpleStrategy

@Builder(builderStrategy = SimpleStrategy, prefix = '')
class BobCommand {
    def bobImage = 'bob.2.0:latest'
    def envVars = [:]
    def needDockerSocket = false

    String toString() {
        def env = envVars
                .collect({ entry -> "-e ${entry.key}=\"${entry.value}\"" })
                .join(' ')

        def cmd = """\
            |docker run
            |--init
            |--rm
            |--workdir \${PWD}
            |--user \$(id -u):\$(id -g)
            |-v \${PWD}:\${PWD}
            |-v /home/enmadm100/doc_push/group:/etc/group:ro
            |-v /home/enmadm100/doc_push/passwd:/etc/passwd:ro
            |-v \${HOME}/.m2:\${HOME}/.m2
            |-v \${HOME}/.docker:\${HOME}/.docker
            |${needDockerSocket ? '-v /var/run/docker.sock:/var/run/docker.sock' : ''}
            |${env}
            |\$(for group in \$(id -G); do printf ' --group-add %s' "\$group"; done)
            |--group-add \$(stat -c '%g' /var/run/docker.sock)
            |${bobImage}
            |"""
        return cmd
                .stripMargin()           // remove indentation
                .replace('\n', ' ')      // join lines
                .replaceAll(/[ ]+/, ' ') // replace multiple spaces by one
    }
}

