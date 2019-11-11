def runStages() {
	stage("Clone") {
		/* The Git repo seems to be cached in some Jenkins plugin, so this is not always a clean clone. */
		checkout scm
		sh "make build-system-checks || true"
	}
	stage("Build") {
		sh "make -j${env.NPROC} update" /* to allow a newer Nim version to be detected */
		sh "make -j${env.NPROC} V=1 deps" /* to allow the following parallel stages */
	}
	stage("Test") {
		parallel(
			"tools": {
				stage("Tools") {
					sh "make -j${env.NPROC}"
				}
			},
			"test suite": {
				stage("Test suite") {
					sh "make -j${env.NPROC} test"
				}
			}
		)
	}
}

parallel(
	"Linux": {
		node("linux") {
			withEnv(["NPROC=${sh(returnStdout: true, script: 'nproc').trim()}"]) {
				runStages()
			}
		}
	},
	"macOS": {
		node("macos") {
			withEnv(["NPROC=${sh(returnStdout: true, script: 'sysctl -n hw.logicalcpu').trim()}"]) {
				runStages()
			}
		}
	}
)

