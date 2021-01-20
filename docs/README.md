The books in this folder were produced using [mdBook](https://github.com/rust-lang/mdBook) - see installation guide.

Some books also use [mdbook-toc](https://github.com/badboy/mdbook-toc) for tables of contents.

```bash
# Install tooling
cargo install mdbook mdbook-toc

# Work on the book locally - open "http://localhost:3000" for live version
cd the_style_book
mdbook serve

# Publish book using makefile (in top-level)
make publish-book
```
