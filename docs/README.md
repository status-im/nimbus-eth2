The books in this folder were produced using [mdBook](https://github.com/rust-lang/mdBook) - see installation guide.

Some books also use [mdbook-toc](https://github.com/badboy/mdbook-toc) for tables of contents.

```bash
# Install or update tooling (make sure you add "~/.cargo/bin" to PATH):
cargo install mdbook mdbook-toc mdbook-open-on-gh

# Work on the book locally - open "http://localhost:4000" for live version
cd docs/the_nimbus_book
mdbook serve -p 4000

# Publish book using makefile (in top-level)
make publish-book
```

