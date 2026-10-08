# Node.js example

A small Express app used to try devkit.

```bash
cd examples/nodejs-app
devkit init --force     # detects Node 22 from .nvmrc
devkit up               # creates the VM, copies this directory, runs npm install
devkit shell            # inside: npm start, then open http://127.0.0.1:3000 on the Mac
devkit logs             # registry.npmjs.org allowed; anything else blocked
devkit rm
```

Try blocking something: run `devkit shell curl -I https://example.com` and
watch it fail, then look at `devkit logs`.
