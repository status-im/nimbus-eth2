# Run nimbus state sim in a browser

Simple runners for in-browser running of WASM versions of applications - based
on emscripten-generated code.

```
# Make sure you have built nim-beacon-chain with make first!
./build.sh

# Run a http server here (wasm + file:/// apparently don't mix)
python -m SimpleHTTPServer

# Open http://localhost:8000/index.html
```
