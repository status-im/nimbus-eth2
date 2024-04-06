#!/usr/bin/env groovy
/* beacon_chain
 * Copyright (c) 2019-2024 Status Research & Development GmbH
 * Licensed and distributed under either of
 *   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
 *   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
 * at your option. This file may not be copied, modified, or distributed except according to those terms.
 */
library 'status-jenkins-lib@nix/flake-build'

pipeline {
  /* This way we run the same Jenkinsfile on different platforms. */
  agent { label params.AGENT_LABEL }

  parameters {
    string(
      name: 'AGENT_LABEL',
      description: 'Label for targetted CI slave host: linux/macos',
      defaultValue: params.AGENT_LABEL ?: getAgentLabel(),
    )
    choice(
      name: 'VERBOSITY',
      description: 'Value for the V make flag to increase log verbosity',
      choices: [0, 1, 2]
    )
  }

  options {
    timestamps()
    ansiColor('xterm')
    /* This also includes wait time in the queue. */
    timeout(time: 1, unit: 'HOURS')
    /* Limit builds retained. */
    buildDiscarder(logRotator(
      numToKeepStr: '5',
      daysToKeepStr: '30',
    ))
    /* Abort old builds for non-main branches. */
    disableConcurrentBuilds(
      abortPrevious: !isMainBranch()
    )
  }

  stages {
    stage('Beacon Node') {
      steps { script {
        nix.flake('beacon_node')
      } }
    }

    stage('Version check') {
      steps { script {
        sh 'result/bin/nimbus_beacon_node --version'
      } }
    }
  }

  post {
    always {
      cleanWs(
        disableDeferredWipeout: true,
        deleteDirs: true
      )
    }
  }
}

def isMainBranch() {
  return ['stable', 'testing', 'unstable'].contains(env.BRANCH_NAME)
}

/* This allows us to use one Jenkinsfile and run
 * jobs on different platforms based on job name. */
def getAgentLabel() {
    if (params.AGENT_LABEL) { return params.AGENT_LABEL }
    /* We extract the name of the job from currentThread because
     * before an agent is picket env is not available. */
    def tokens = Thread.currentThread().getName().split('/')
    def labels = []
    /* Check if the job path contains any of the valid labels. */
    ['linux', 'macos', 'x86_64', 'aarch64', 'arm64'].each {
        if (tokens.contains(it)) { labels.add(it) }
    }
    return labels.join(' && ')
}
