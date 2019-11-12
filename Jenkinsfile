node('linux') {
	stage('Clone') {
		env.GIT_LFS_SKIP_SMUDGE = 1
		checkout scm
	}
	stage('Build') {
		sh 'echo "nproc:"; nproc'
	}
}

