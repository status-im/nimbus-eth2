# Updating this guide

We use [Material for MkDocs](https://squidfunk.github.io/mkdocs-material/) to produce our documentation.

## Before You Start

1. Clone the repository by `git clone https://github.com/status-im/nimbus-eth2.git`.
2. Go to the `docs` folder and type `make` to install `mkdocs`
3. Activate mkdocs: `. mkdocs/bin/activate`
3. Go to where the Markdown files are located by `cd the_nimbus_book/`.

## Real-Time Update and Preview Changes

1. Run `mkdocs serve` in the terminal.
2. Preview the book at [http://localhost:8000](http://localhost:8000).

## Build and Deploy

The first step is to submit a pull request to the [unstable branch](https://github.com/status-im/nimbus-eth2/tree/unstable).
Then, after it is merged, do the following under our main repository:

```sh
cd nimbus-eth2
git checkout unstable
git pull
make update # (This is to update the submodules to the latest version)
make publish-book
```

## Troubleshooting

If you see file conflicts in the pull request, this may due to that you have created your new branch from an old version of the `unstable` branch.
Update your new branch using the following commands:

```sh
git checkout unstable
git pull
make update
git checkout readme
git merge unstable
# use something like "git mergetool" to resolve conflicts, then read the instructions for completing the merge (usually just a `git commit`)
# check the output of "git diff unstable"
```

Thank you so much for your help to the decentralized and open source community. :)
