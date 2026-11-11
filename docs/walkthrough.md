# A quick walkthrough: developing and contributing safely

Ten minutes, start to finish: build and test a project, change it, and get
your commits to a pull request, while its code, its dependencies and any
coding agent run in a VM instead of on your Mac. Each step says what to type,
what you should see, and what it protects you from.

There are two ways in, and they differ in one important respect, so pick one:

| | **A. A repository you already have** | **B. A repository you do not have yet** |
|---|---|---|
| Start with | `devkit init` in your checkout | `devkit clone <url>` |
| Project files on your Mac | Yes, your checkout | None: the clone is bare |
| Where you edit | On your Mac, or in the VM. Pick one (step 4) | In the VM |
| How code reaches the VM | Your directory is copied in | The VM checks out what your Mac fetched |
| How commits leave | From your Mac as usual, or `devkit push` | `devkit push` |

Most people start with A, on a project already on disk. B is the stricter
one, and the one to use for a repository you have never looked at.

The example is a Go project called `widgets`, at
`github.com/example-org/widgets`; put your own in its place. Your VM is named
after your project (`devkit-widgets` here), and so are the refs `devkit push`
stores. The output is adapted from real runs on another Go project:
shortened, and with names and paths changed to this one's.

Before you start: `brew install lima`, build devkit (`make install`), and run
`devkit doctor`. See the [README](../README.md#quick-start).

## 1. Create the project

### A. From a checkout you already have

```console
$ cd ~/code/widgets
$ devkit init
Wrote devkit.yaml

  name:       widgets
  source:     copy
  toolchains: mise: go 1.23
  network:    allowlist
  ssh port:   2225

Next: devkit up
```

`devkit init` reads the project's version files and writes one file,
`devkit.yaml`. Nothing of the project runs. The file shows up as untracked in
`git status`: commit it if the project wants it, or list it in
`.git/info/exclude`.

The project's files are on your Mac in this mode, so the VM only protects you
from what you run in it. From here on, do not run the project on the Mac: no
`npm install`, no test run, no build. Three things run a project's code
without being asked, and are worth a look in a checkout that predates devkit:

- **Your editor.** Opening the folder can start the project's tasks, its
  language-server plugins and its linters. Keep the folder in the editor's
  restricted mode on the Mac, or edit in the VM (step 4).
- **Git hooks.** Anything in `.git/hooks`, or where `core.hooksPath` points,
  runs on `git commit` and `git push`. Tools such as husky install them when
  dependencies are installed.
- **Your shell.** `direnv` runs a project's `.envrc` when you `cd` into it.

### B. From a URL, without checking it out

```console
$ devkit clone github.com/example-org/widgets
Cloning https://github.com/example-org/widgets on your Mac (bare: nothing is checked out here)
Wrote .../widgets/devkit.yaml

  name:       widgets
  source:     git
  toolchains: mise: go 1.23
  network:    allowlist
  ssh port:   2225

Next: cd widgets && devkit up
```

Your Mac clones with your own git credentials, so private repositories work,
but the clone is bare: the directory holds `devkit.yaml` and `.devkit/` and
none of the project's files. Nothing in the repository can run on your Mac
through a checkout, a hook or an editor opening the folder.

## 2. Read the one file that decides everything

```console
$ cat devkit.yaml
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
  project files: 0 certificate files scanned, 0 untrusted roots
  container images: no compose files or Dockerfiles

Ready. Network: allowlist (8 hosts), audited
  Shell:   devkit shell
  IDE:     ssh devkit-widgets   (VS Code / Cursor Remote-SSH, folder ~/workspace)
  Audit:   devkit logs
```

The first run takes a few minutes; later ones take seconds. What happened:

- A new Ubuntu VM was created for this project alone, with no shared folders.
- The firewall and the allowlist proxy were put in place by root before the
  project's code was given any network at all.
- The code went in. In A, your directory was copied (without your `.git`:
  the VM gets one commit, as a fresh clone would, with no history, hooks or
  credentials). In B, the VM checked out what your Mac had fetched.
- The toolchain was installed and its checksums recorded; dependencies were
  installed from the lockfile and nothing newer.
- The audit looked for trust the project should not have: root certificates
  that browsers no longer trust, in the VM and in any bundle the project
  carries, and container images that are not pinned by digest. A finding is
  printed with a `!` and the file it is in.

## 4. Work in it

```console
$ devkit shell
~/workspace$ go test ./...
ok  	github.com/example-org/widgets/internal/config	0.002s
```

`devkit shell <command>` runs one command and returns.

**Where to edit.** In B there is only one place: the VM. Connect your editor
with Remote-SSH to `ssh devkit-widgets`, folder `~/workspace` (`devkit
connect` prints the steps); its terminal, language server and extensions then
run in the VM too.

In A you have two copies, and devkit copies one way only, from your Mac into
the VM. So choose a side and stay on it:

- **Edit on your Mac, run in the VM.** The simplest. After a change,
  `devkit sync` copies the directory in again, and you run the tests there:

  ```console
  $ devkit sync
  Copying /Users/you/code/widgets into the VM
  Keeping the VM's own git repository
  $ devkit shell go test ./...
  ```

  You commit and push on your Mac as you always have.

- **Edit in the VM**, over Remote-SSH, as in B. Then stop syncing: `devkit
  sync`, and a plain `devkit up`, replace every file in the VM that also
  exists on your Mac with the Mac's copy. An uncommitted edit in the VM is
  gone; a committed one is still in the VM's git (`git checkout -- <file>`
  brings it back). Use `devkit up --no-sync` when you change `devkit.yaml`,
  and get your work out with `devkit push` (step 6).

**Ports.** A web app the project serves is not forwarded to your Mac by
devkit until you list its port: add `forward: [3000]` under `network` and run
`devkit up` again. An editor connected over SSH is a second way in that
devkit does not control: VS Code and Cursor forward ports through their own
SSH tunnel, often automatically when something starts listening. Turn
automatic port forwarding off in the editor (in VS Code,
`remote.autoForwardPorts`), and forward only what you mean to open. A page
served by untrusted code and opened in your browser runs with your browser's
network, not the VM's.

**Agents.** A coding agent belongs in the VM as well: install and run it
there, and add the host its API uses to `network.allow`. Whatever key you
give it is readable by everything else that runs in the VM, so use one you
can revoke.

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
`devkit up` (in A, `devkit up --no-sync` if you edit in the VM); the change
is one line you can see in a diff.

`examples/hostile-project` runs a fuller set of these attempts and reports
each as held or leaked.

## 6. Get your commits to a pull request

**If you edit on your Mac (A):** nothing changes. Commit and push from your
Mac with git, as before. The VM was only where the code ran.

**If you commit in the VM (A or B):** the VM has no credentials, on purpose:
a token in there would be usable by every dependency. Your Mac pushes
instead, after showing you what it is about to push.

```console
~/workspace$ git checkout -b fix-typo
~/workspace$ git commit -am "Docs: fix a typo"
```

```console
$ devkit push
fix-typo does not exist on origin yet; the push creates it

Commits from the VM for origin fix-typo (stored at refs/devkit/widgets/fix-typo):
  3017c3e83599 Your Name <you@example.com>  Docs: fix a typo

README.md | 2 ++
 1 file changed, 2 insertions(+)

Inspect in full with: git log -p refs/devkit/widgets/fix-typo

Push 1 commit(s) to origin fix-typo? [y/N]
```

This review is the gate, and the only one. Read it:

- **Every commit and the diffstat.** A dependency can change files that you
  or an agent then commit without noticing.
- **Flagged files.** Changed files that run outside the VM (CI workflows,
  git and editor hooks, `.envrc`, `package.json` scripts) are listed
  separately. Those are how code from the VM would run somewhere else.
- **The full diff**, when in doubt, with the command the review prints (in
  B it names the bare copy: `git --git-dir .devkit/repo.git log -p ...`).
  The commits are already on your Mac, stored outside your branches and your
  work tree; reading them runs nothing.

Say no and nothing is pushed; the commits stay where they are. Say yes and
your Mac pushes with your normal credentials. No git hooks run on the Mac.
Then open the pull request as usual, from the branch on the remote.

In A, your checkout on the Mac does not have those commits on a branch.
`git pull` or `git fetch` brings them from the remote like anyone else's; see
the third habit below before you run anything there.

To push to your fork rather than the upstream, add the remote on the Mac
(in B: `git --git-dir .devkit/repo.git remote add fork <url>`) and use
`devkit push --remote fork`.

## 7. Keep up with upstream

**A:** pull on your Mac, then copy the result in: `git pull && devkit sync`.
Mind the rule from step 4 if you edit in the VM.

**B:**

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
- **Move from A to B.** Once a project matters, clone it again with `devkit
  clone` and delete the checkout: then none of its files are on your Mac.

## 9. Throw it away

```console
$ devkit rm
Deleted VM devkit-widgets
```

The VM and everything any dependency did inside it are gone. `devkit up`
builds a clean one. Do this without hesitation whenever something looks odd:
an unexplained host in the log, a kernel crash report (`devkit up` and
`devkit audit` show them), or simply a branch you are done with. Push or
copy out what you want to keep first: work that exists only in the VM goes
with it.

## The habits that keep this safe

devkit keeps untrusted code off your Mac; these keep you from carrying it
across yourself.

1. **Do not run the project's tooling on your Mac.** Not `npm install`, not
   its tests, not its build. That is the VM's job. In A, that includes what
   your editor, your git hooks and `direnv` would run for you.
2. **Treat `devkit push` as code review.** Push to a feature branch and merge
   through a pull request. Do not expose CI secrets to branches from the VM.
3. **Code written in the VM is untrusted on your Mac too.** Pulling it into a
   checkout there is safe; running that checkout's tooling afterwards is not,
   unless you have read what changed.
4. **Keep `sudo: false`,** and leave `allow_host` off unless the project
   needs a service on your Mac.
5. **Add hosts one at a time,** and only ones you would trust with the
   project's source: an allowed host is also somewhere data can go.
6. **Read `devkit logs` after installs,** and `devkit audit` now and then.
7. **In A, edit on one side.** `devkit sync` overwrites the VM from the Mac.
8. **Delete VMs freely.** They are meant to be disposable.

What each control does and does not guarantee is in
[SECURITY.md](../SECURITY.md).
