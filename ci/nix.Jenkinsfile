#!/usr/bin/env groovy
/* beacon_chain
 * Copyright (c) 2019-2026 Status Research & Development GmbH
 * Licensed and distributed under either of
 *   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
 *   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
 * at your option. This file may not be copied, modified, or distributed except according to those terms.
 */
library 'status-jenkins-lib@v1.9.45'

def result = ''

pipeline {
  agent {
    docker {
      label 'linuxcontainer'
      image 'harbor.status.im/infra/ci-build-containers:linux-base-1.0.0'
      args '--volume=/nix:/nix ' +
           '--volume=/etc/nix:/etc/nix '
    }
  }

  parameters {
    choice(
      name: 'VERBOSITY',
      description: 'Value for the V make flag to increase log verbosity',
      choices: [0, 1, 2]
    )
    choice(
      name: 'NIX_TARGET',
      description: 'Nix flake target to build',
      choices: ['beacon_node', 'validator_client']
    )
  }

  options {
    disableRestartFromStage()
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
    stage('Build') {
      steps { script {
        def gitRef = env.BRANCH_NAME ==~ /PR-\d+/
          ? "refs/pull/${env.BRANCH_NAME.replace('PR-', '')}/head"
          : env.BRANCH_NAME
    
        result = nix.flake(params.NIX_TARGET, [
            path: "git+https://github.com/status-im/nimbus-eth2?ref=${gitRef}&submodules=1",
            noWriteLockFile: true,
        ])
      } }
    }

    stage('Version check') {
      steps { script {
        sh "${result}/bin/nimbus_${params.NIX_TARGET} --version"
      } }
    }

    stage('Push to Nix cache') {
      when {
        expression {
          env.JOB_NAME.toLowerCase().contains('nightly')
        }
      }
      steps { script {
        nix.copyToCache(derivations: [result])
      } }
    }

    stage('Service check') {
      steps { script {
        sh 'nix run ".#checks.x86_64-linux.beacon-node.driver"'
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
