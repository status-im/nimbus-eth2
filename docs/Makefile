mkdocs: mkdocs/bin/mkdocs

mkdocs/pyenv.cfg:
	test -d mkdocs || python3 -m venv mkdocs
	. mkdocs/bin/activate; pip install -r requirements.txt

compile:
	pip-compile requirements.in

sync:
	pip-sync requirements.txt

serve: mkdocs
	. mkdocs/bin/activate; cd the_nimbus_book; mkdocs serve

book: mkdocs
	. mkdocs/bin/activate; cd the_nimbus_book; mkdocs build
