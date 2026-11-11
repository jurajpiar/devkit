# A quick walkthrough: contributing to a project you do not trust yet

Ten minutes, start to finish: take a repository from the internet, build and
test it, change it, and get your commits to a pull request, without its code,
its dependencies or a coding agent ever running on your Mac. Each step says
what to type, what you should see, and what it protects you from.

The example contributes to devkit itself. Any repository works the same way.
The output below is from a real run, shortened.

Before you start: `brew install lima`, build devkit (`make install`), and run
`devkit doctor`. See the [README](../README.md#quick-start).

## 1. Get the code, without checking it out

```console
$ devkit clone github.com/jurajpiar/devkit
Cloning https://github.com/jurajpiar/devkit on your Mac (bare: nothing is checked out here)
Wrote .../devkit/devkit.yaml

  name:       devkit
  source:     git
  toolchains: mise: go 1.23
  network:    allowlist
  ssh port:   2225

Next: cd devkit && devkit up
```

Your Mac clones with your own git credentials, so private repositories work,
but the clone is bare: the directory holds `devkit.yaml` and `.devkit/` and
none of the project's files. Nothing in the repository can run on your Mac
through a checkout, a hook or an editor opening the folder.

This walkthrough is for a project made by `devkit clone`. A directory you
already have on your Mac works too (`devkit init` inside it), but it flows
the other way and some steps differ:

- The directory is copied into the VM on every `devkit up` and `devkit
  sync`, over the files already there. A file you edited in the VM is
  replaced by the Mac's copy, so either edit on the Mac and sync, or work in
  the VM and use `devkit up --no-sync` when you change `devkit.yaml`.
- `devkit sync` copies your directory again; it does not fetch upstream.
- There is no `.devkit/repo.git`: the commits `devkit push` brings out are
  stored in your own checkout, and plain `git` commands see them.

## 2. Read the one file that decides everything

```console
$ cd devkit && cat devkit.yaml
```

Three things are worth a look before the first boot:

- **`network.allow`** is every host the sandbox may reach. devkit filled it in
  from what it detected (here GitHub, the Go module proxy and the hosts the Go
  toolchain is downloaded from). Nothing else is reachable.
- **`tools.versions`** is the toolchain, read from the project's own version
  files (here `go.mod`).
- **`sudo`** is off, and should stay off: root inside the VM can remove the
  firewall.

## 3. Bring the sandbox up

```console
$ devkit up
...
Added .git as a fresh clone would have it: commit a20fdc9a6d80 on main, no history, hooks or credentials
Installing toolchains and recording their checksums
Recorded toolchain checksums in the VM; later runs refuse anything else
Installing dependencies

Trust audit
  reference: Mozilla root store, 110 roots trusted for TLS, 2 distrusted
  ...
  ! examples/hostile-project/certs/vendored-ca-bundle.pem: root Izenpe.com not in the reference store (stale, or a private CA)
  container images: no compose files or Dockerfiles

Ready. Network: allowlist (8 hosts), audited
  Shell:   devkit shell
  IDE:     ssh devkit-devkit   (VS Code / Cursor Remote-SSH, folder ~/workspace)
  Audit:   devkit logs
```

The first run takes a few minutes; later ones take seconds. What happened:

- A new Ubuntu VM was created for this project alone, with no shared folders.
- The firewall and the allowlist proxy were put in place by root before the
  project's code was given any network at all.
- The toolchain was installed and its checksums recorded; dependencies were
  installed from the lockfile and nothing newer.
- The audit named what the project trusts that it should not. Here it found a
  certificate bundle the example project vendors on purpose. It also lists
  container images that are not pinned by digest, when there are any.

## 4. Work in it

```console
$ devkit shell
~/workspace$ git status -sb
## main
~/workspace$ go test ./internal/project/
ok  	github.com/jurajpiar/devkit/internal/project	0.002s
```

Or connect your editor: VS Code, Cursor and Zed open `ssh devkit-devkit`
with Remote-SSH, folder `~/workspace`; `devkit connect` prints the steps. The
editor's terminal, language server and extensions then run in the VM too.

A web app the project serves is not forwarded to your Mac by devkit until you
list its port: add `forward: [3000]` under `network` and run `devkit up`
again. An editor connected over SSH is a second way in that devkit does not
control: VS Code and Cursor forward ports through their own SSH tunnel,
often automatically when something starts listening. Turn automatic port
forwarding off in the editor (in VS Code, `remote.autoForwardPorts`), and
forward only what you mean to open. A page served by untrusted code and
opened in your browser runs with your browser's network, not the VM's.

A coding agent belongs in here as well: install and run it inside the VM, and
add the host its API uses to `network.allow`. Whatever key you give it is
readable by everything else that runs in the VM, so use one you can revoke.

## 5. See what the sandbox does when code misbehaves

Try, from the shell in the VM, what a malicious dependency would:

```console
~/workspace$ curl -m 8 https://example.org/            # a host not on the list
curl: (56) CONNECT tunnel failed, response 403
~/workspace$ curl -m 5 --noproxy '*' https://example.org/   # around the proxy
curl: (6) Could not resolve host: example.org
~/workspace$ sudo -n true                              # become root
sudo: a password is required
~/workspace$ ls /Users                                 # your files
ls: cannot access '/Users': No such file or directory
```

And from your Mac, what the proxy saw:

```console
$ devkit logs -n 3
... [EGRESS] ALLOWED CONNECT proxy.golang.org:443 (matched: proxy.golang.org)
... [EGRESS] ALLOWED CONNECT raw.githubusercontent.com:443 (matched: **.githubusercontent.com)
... [EGRESS] BLOCKED CONNECT example.org:443
```

Read this log after an install. A dependency that reaches for a host you did
not expect is the thing to notice, whether it was allowed or blocked. When a
build genuinely needs another host, add it to `network.allow` and run
`devkit up`; the change is one line you can see in a diff.

`examples/hostile-project` runs a fuller set of these attempts and reports
each as held or leaked.

## 6. Commit in the VM, push from your Mac

Commit inside the VM as you would anywhere:

```console
~/workspace$ git checkout -b fix-typo
~/workspace$ git commit -am "Docs: fix a typo"
```

The VM has no credentials, on purpose: a token in there would be usable by
every dependency. Your Mac pushes instead, after showing you what it is about
to push:

```console
$ devkit push
fix-typo does not exist on origin yet; the push creates it

Commits from the VM for origin fix-typo (stored at refs/devkit/devkit/fix-typo):
  3017c3e83599 Your Name <you@example.com>  Docs: fix a typo

CONTRIBUTING.md | 2 ++
 1 file changed, 2 insertions(+)

Inspect in full with: git --git-dir .devkit/repo.git log -p refs/devkit/devkit/fix-typo

Push 1 commit(s) to origin fix-typo? [y/N]
```

This review is the gate, and the only one. Read it:

- **Every commit and the diffstat.** A dependency can change files that you
  or an agent then commit without noticing.
- **Flagged files.** Changed files that run outside the VM (CI workflows,
  git and editor hooks, `.envrc`, `package.json` scripts) are listed
  separately. Those are how code from the VM would run somewhere else.
- **The full diff**, when in doubt, with the command the review prints. The
  commits are already on your Mac, in the bare repository, outside any
  branch; reading them runs nothing.

Say no and nothing is pushed; the commits stay where they are. Say yes and
your Mac pushes with your normal credentials. No git hooks run on the Mac.
Then open the pull request as usual, from the branch on the remote.

To push to your fork rather than the upstream, add the remote on the Mac
(`git --git-dir .devkit/repo.git remote add fork <url>`) and use
`devkit push --remote fork`.

## 7. Keep up with upstream

```console
$ devkit sync
Keeping the VM's own git repository
Fetching main on your Mac
Up to date with origin/main
```

Your Mac fetches; the VM is fast-forwarded. The VM never talks to the remote
itself.

## 8. Tighten it when you can

- **Air-gap once dependencies are in.** `devkit up --network none` leaves the
  VM with no network at all, DNS included. Most builds and tests do not need
  one. `devkit up --network allowlist` brings it back.
- **Have the Mac enforce the network too.** With `enforce: host` under
  `network`, the allowlist also holds on your Mac, where root in the VM cannot
  reach it. Worth it when an agent runs unattended. See
  [Enforcement on the Mac](../README.md#enforcement-on-the-mac-networkenforce-host).
- **A database without Docker.** `services: [postgres]` gives the project a
  PostgreSQL inside the VM, reachable only from the VM.

## 9. Throw it away

```console
$ devkit rm
Deleted VM devkit-devkit
```

The VM and everything any dependency did inside it are gone. `devkit up`
builds a clean one. Do this without hesitation whenever something looks odd:
an unexplained host in the log, a kernel crash report (`devkit up` and
`devkit audit` show them), or simply a branch you are done with.

## The habits that keep this safe

devkit keeps untrusted code off your Mac; these keep you from carrying it
across yourself.

1. **Do not run the project's tooling on your Mac.** Not `npm install`, not
   its tests, not an editor opened on a checkout. That is the VM's job.
2. **Treat `devkit push` as code review.** Push to a feature branch and merge
   through a pull request. Do not expose CI secrets to branches from the VM.
3. **Do not merge `refs/devkit/...` into a checkout on your Mac** and then
   run that checkout's tooling, unless you have read what changed.
4. **Keep `sudo: false`,** and leave `allow_host` off unless the project
   needs a service on your Mac.
5. **Add hosts one at a time,** and only ones you would trust with the
   project's source: an allowed host is also somewhere data can go.
6. **Read `devkit logs` after installs,** and `devkit audit` now and then.
7. **Delete VMs freely.** They are meant to be disposable.

What each control does and does not guarantee is in
[SECURITY.md](../SECURITY.md).
