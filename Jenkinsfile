// https://stackoverflow.com/questions/40760716/jenkins-abort-running-build-if-new-one-is-started
// We should only abort older jobs in PR branches, so we have a nice CI history in "stable",
// "testing", and "unstable".
if (env.BRANCH_NAME != "stable" && env.BRANCH_NAME != "testing" && env.BRANCH_NAME != "unstable") {
	def buildNumber = env.BUILD_NUMBER as int
	if (buildNumber > 1) {
		milestone(buildNumber - 1)
	}
	milestone(buildNumber)
}

def runStages(nodeDir) {
	sh "mkdir -p ${nodeDir}"
	dir(nodeDir) {
		try {
			stage("Clone") { timeout(15) {
				/* source code checkout */
				checkout scm
				/* we need to update the submodules before caching kicks in */
				sh "git submodule update --init --recursive"
			} }

			stage("Preparations") { timeout(10) {
				sh """#!/bin/bash
				set -e
				# macOS shows scary warnings if there are old libraries and object files laying around
				make clean
				# to allow the following parallel stages
				make -j${env.NPROC} QUICK_AND_DIRTY_COMPILER=1 update
				./scripts/setup_scenarios.sh
				"""
			} }

			stage("Tools") { timeout(30) {
				sh """#!/bin/bash
				set -e
				make -j${env.NPROC} LOG_LEVEL=TRACE
				"""
			} }

			stage("Test suite") { timeout(60) {
				sh "make -j${env.NPROC} DISABLE_TEST_FIXTURES_SCRIPT=1 test"
			} }
		} catch(e) {
			// we need to rethrow the exception here
			throw e
		} finally {
			try {
				archiveArtifacts("*.tar.gz")
			} catch(e) {
				println("Couldn't archive artefacts.")
				println(e.toString());
				// we don't need to re-raise it here; it might be a PR build being cancelled by a newer one
			}
			// clean the workspace
			cleanWs(disableDeferredWipeout: true, deleteDirs: true)
		}
	} // dir(...)
}

parallel(
	"Linux": {
		throttle(['nimbus-eth2']) {
			timeout(time: 24, unit: 'HOURS') { // includes time in build queue
				node("linux") {
					withEnv(["NPROC=${sh(returnStdout: true, script: 'nproc').trim()}"]) {
						runStages("linux")
					}
				}
			}
		}
	},
	"macOS (AMD64)": {
		throttle(['nimbus-eth2']) {
			timeout(time: 24, unit: 'HOURS') { // includes time in build queue
				node("macos && x86_64") {
					withEnv(["NPROC=${sh(returnStdout: true, script: 'sysctl -n hw.logicalcpu').trim()}"]) {
						runStages("macos_amd64")
					}
				}
			}
		}
	},
	"macOS (ARM64)": {
		throttle(['nimbus-eth2']) {
			timeout(time: 24, unit: 'HOURS') { // includes time in build queue
				node("macos && arm64") {
					withEnv(["NPROC=${sh(returnStdout: true, script: 'sysctl -n hw.logicalcpu').trim()}"]) {
						runStages("macos_arm64")
					}
				}
			}
		}
	},
)
