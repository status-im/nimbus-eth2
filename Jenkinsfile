node('linux') {
	stage('Clone') {
		checkout scm
	}
	stage('Build') {
		sh 'echo "nproc:"; nproc'
	}
}

