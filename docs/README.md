# Documentation

## material for mkdocs

The Nimbus guide is generated using [Material for mkdocs](https://squidfunk.github.io/mkdocs-material/), and installed using a python VENV (see Makefile).

## mdbook

Some books in this folder were produced using [mdBook](https://github.com/rust-lang/mdBook) - see installation guide.

```bash
# Install or update tooling (make sure you add "~/.cargo/bin" to PATH):
cargo install mdbook --version 0.4.18
cargo install mdbook-toc --version 0.8.0
cargo install mdbook-open-on-gh --version 2.1.0
cargo install mdbook-admonish --version 1.7.0

# Work on the book locally - open "http://localhost:4000" for live version
cd docs/the_nimbus_book
mdbook serve -p 4000

# Create a local copy of the book
make book

# Publish book using makefile (in the top-level dir)
make publish-book
```
