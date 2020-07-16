pipeline {
  /* By parametrizing this we can run the same Jenkinsfile or different platforms */
  agent { label getAgentLabel() }

  parameters {
    string(
      name: 'AGENT_LABEL',
      description: 'Label for targetted CI slave host: linux/macos',
      defaultValue: '',
    )
  }

  options {
    timestamps()
    /* Prevent Jenkins jobs from running forever */
    timeout(time: 70, unit: 'MINUTES')
    /* Limit builds retained */
    buildDiscarder(logRotator(
      numToKeepStr: '10',
      daysToKeepStr: '30',
      artifactNumToKeepStr: '10',
    ))
  }

  environment {
    NPROC = Runtime.getRuntime().availableProcessors()
    MAKEFLAGS = "-j${env.NPROC}"
  }

  stages {
    stage('Clone') {
      steps {
        /* Abort older jobs if this is a PR build */
        abortPreviousRunningBuilds()
        /* Checkout the source code */
        checkout scm
        sh 'echo "$MAKEFLAGS"'
        /* We need to update the submodules before caching kicks in */
        sh 'git submodule update --init --recursive'
      }
    }

    stage('Build') {
      steps {
        cache(maxCacheSize: 250, caches: [
          [ $class: 'ArbitraryFileCache',
            includes: '**/*',
            path: "${WORKSPACE}/vendor/nimbus-build-system/vendor/Nim/bin" ],
          [ $class: 'ArbitraryFileCache',
            includes: '**/*',
            path: "${WORKSPACE}/jsonTestsCache" ],
        ]) {
          /* Allow a newer Nim version to be detected */
          sh 'make update'
          /* Allow the following parallel stages */
          sh 'make deps'
          sh 'V=1 ./scripts/setup_official_tests.sh jsonTestsCache'
        }
      }
    }

    stage('Tests') {
      parallel {
        stage('Tools') {
          steps {
            sh 'make'
            sh 'make beacon_node LOG_LEVEL=TRACE NIMFLAGS="-d:testnet_servers_image"'
          }
        }
        stage('Test suite') {
          steps {
            sh 'make test DISABLE_TEST_FIXTURES_SCRIPT=1'
          }
        }
      }
    }

    stage("testnet0 finalization") {
      steps { script {
        timeout(time: 10, unit: 'MINUTES') {
          launchLocalTestnet(0)
        }
      } }
    }
    stage("testnet1 finalization") {
      steps { script {
        timeout(time: 40, unit: 'MINUTES') {
          launchLocalTestnet(1)
        }
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

/* This allows us to use one Jenkinsfile and run
 * jobs on different platforms based on job name. */
def getAgentLabel() {
    if (params.AGENT_LABEL) {
        return params.AGENT_LABEL
    } else {
        /* We extract the name of the job from currentThread because
         * before an agent is picket env is not available. */
        def tokens = Thread.currentThread().getName().split('/')
        def jobIdentifiers = tokens.take(tokens.size())
        if (jobIdentifiers.contains('linux')) {
            env.AGENT_LABEL = 'linux'
        } else if (jobIdentifiers.contains('macos')) {
            env.AGENT_LABEL = 'macos'
        } else {
          throw new Exception('No agent provided or found in path!')
        }
        return env.AGENT_LABEL
    }
}

def launchLocalTestnet(Integer testnetNum) {
  /* EXECUTOR_NUMBER will be 0 or 1, since we have 2 executors per node */
  def listenPort = 9000 + (env.EXECUTOR_NUMBER.toInteger() * 100)
  def metricsPort = 8008 + (env.EXECUTOR_NUMBER.toInteger() * 100)
  def flags = [
    "--nodes 4",
    "--log-level INFO",
    "--disable-htop",
    "--data-dir local_testnet${testnetNum}_data",
    "--base-port ${listenPort}",
    "--base-metrics-port ${metricsPort}",
    "-- --verify-finalization --stop-at-epoch=5"
  ]

  try {
    sh "./scripts/launch_local_testnet.sh --testnet ${testnetNum} ${flags.join(' ')}"
  } catch(ex) {
    println("Failed the launch of local testnet${testnetNum}")
    println(ex.toString());
  } finally {
    /* Archive test results regardless of outcome */
    def dirName = "local_testnet${testnetNum}_data"
    sh "tar cjf ${dirName}.tar.bz2 ${dirName}/*.txt"
    archiveArtifacts("${dirName}.tar.bz2")
  }
}

import jenkins.model.CauseOfInterruption.UserInterruption
import hudson.model.Result
import hudson.model.Run
@NonCPS
def abortPreviousRunningBuilds() {
  /* Aborting makes sense only for PR builds, since devs start so many of them */
  if (env.CHANGE_ID == null) {
    println ">> Not aborting any previous jobs. Not a PR build."
    return
  }
  Run previousBuild = currentBuild.rawBuild.getPreviousBuildInProgress()

  while (previousBuild != null) {
    if (previousBuild.isInProgress()) {
      def executor = previousBuild.getExecutor()
      if (executor != null) {
        println ">> Aborting older build #${previousBuild.number}"
        executor.interrupt(Result.ABORTED, new UserInterruption(
          "newer build #${currentBuild.number}"
        ))
      }
    }
    previousBuild = previousBuild.getPreviousBuildInProgress()
  }
}
