# Contribute

Follow these steps to contribute to this book!

We use an utility tool called mdBook to create online books from Markdown files.

## Before You Start

1. Install mdBook from [here](https://github.com/rust-lang/mdBook).
2. Clone the repository by `git clone https://github.com/status-im/nimbus-eth2.git`.
3. Go to where the Markdown files are located by `cd docs`.

## Real-Time Update and Preview Changes

1. Run `mdbook serve` in the terminal.
2. Preview the book at [http://localhost:3000](http://localhost:3000).

## Build and Deploy

The first step is to submit a pull request to the [unstable branch](https://github.com/status-im/nimbus-eth2/tree/unstable).
Then, after it is merged, do the following under our main repository:

1. `cd nimbus-eth2`
2. `git checkout unstable`
3. `git pull`
4. `make update` (This is to update the submodules to the latest version)
5. `make publish-book`

## Troubleshooting

If you see file conflicts in the pull request, this may due to that you have created your new branch from an old version of the `unstable` branch. Update your new branch using the following commands:

```
git checkout unstable
git pull
make update
git checkout readme
git merge unstable
# use something like "git mergetool" to resolve conflicts, then read the instructions for completing the merge (usually just a `git commit`)
# check the output of "git diff unstable"
```

Thank you so much for your help to the decentralized and open source community. :)
