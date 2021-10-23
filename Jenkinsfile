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

def runStages() {
	try {
		stage("Clone") {
			/* source code checkout */
			checkout scm
			/* we need to update the submodules before caching kicks in */
			sh "git submodule update --init --recursive"
		}

		cache(maxCacheSize: 250, caches: [
			[$class: "ArbitraryFileCache", excludes: "", includes: "**/*", path: "${WORKSPACE}/vendor/nimbus-build-system/vendor/Nim/bin"],
			[$class: "ArbitraryFileCache", excludes: "", includes: "**/*", path: "${WORKSPACE}/jsonTestsCache"]
		]) {
			stage("Build") {
				sh """#!/bin/bash
				set -e
				# to allow the following parallel stages
				make -j${env.NPROC} QUICK_AND_DIRTY_COMPILER=1 deps
				./scripts/setup_scenarios.sh jsonTestsCache
				"""
			}
		}

		stage("Tools") {
			sh """#!/bin/bash
			set -e
			make -j${env.NPROC}
			make -j${env.NPROC} LOG_LEVEL=TRACE
			"""
		}

		stage("Test suite") {
			sh "make -j${env.NPROC} DISABLE_TEST_FIXTURES_SCRIPT=1 test"
		}
	} catch(e) {
		// we need to rethrow the exception here
		throw e
	} finally {
		// clean the workspace
		cleanWs(disableDeferredWipeout: true, deleteDirs: true)
	}
}

parallel(
	"Linux": {
		throttle(['nimbus-eth2']) {
			timeout(time: 4, unit: 'HOURS') {
				node("linux") {
					withEnv(["NPROC=${sh(returnStdout: true, script: 'nproc').trim()}"]) {
						runStages()
					}
				}
			}
		}
	},
	"macOS": {
		throttle(['nimbus-eth2']) {
			timeout(time: 4, unit: 'HOURS') {
				node("macos && x86_64") {
					withEnv(["NPROC=${sh(returnStdout: true, script: 'sysctl -n hw.logicalcpu').trim()}"]) {
						runStages()
					}
				}
			}
		}
	},
)
