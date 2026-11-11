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

The example is a Go project called `example-repo`, at
`github.com/example-org/example-repo`; put your own in its place. Your VM is named
after your project (`devkit-example-repo` here), and so are the refs `devkit push`
stores. The output is adapted from real runs on another Go project:
shortened, and with names and paths changed to this one's.

**Where each command runs.** A line starting with `$` is typed on your Mac,
in the project directory: the one that holds `devkit.yaml`. Every `devkit`
command is run there. A line starting with `~/workspace$` is typed inside the
VM, in the shell `devkit shell` gives you.

Before you start: `brew install lima`, build devkit (`make install`), and run
`devkit doctor`. See the [README](../README.md#quick-start).

## 1. Create the project

### A. From a checkout you already have

```console
$ cd ~/code/example-repo
$ devkit init
Wrote devkit.yaml

  name:       example-repo
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
$ devkit clone github.com/example-org/example-repo
Cloning https://github.com/example-org/example-repo on your Mac (bare: nothing is checked out here)
Wrote .../example-repo/devkit.yaml

  name:       example-repo
  source:     git
  toolchains: mise: go 1.23
  network:    allowlist
  ssh port:   2225

Next: cd example-repo && devkit up
$ cd example-repo
```

Every command from here on is run in that directory, the one holding
`devkit.yaml`.

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
  IDE:     ssh devkit-example-repo   (VS Code / Cursor Remote-SSH, folder ~/workspace)
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
ok  	github.com/example-org/example-repo/internal/config	0.002s
```

`devkit shell <command>` runs one command and returns.

**Where to edit.** In B there is only one place: the VM. Connect your editor
with Remote-SSH to `ssh devkit-example-repo`, folder `~/workspace` (`devkit
connect` prints the steps); its terminal, language server and extensions then
run in the VM too.

In A you have two copies, and devkit copies one way only, from your Mac into
the VM. You can edit on either side. `devkit sync` (and `devkit up`) brings
in what changed on your Mac since the last sync, deletes what you deleted
there, and keeps what you changed in the VM:

```console
$ devkit sync
Syncing /Users/you/code/example-repo into the VM
Kept the VM's own changes, which now differ from this Mac: internal/config/config.go
Keeping the VM's own git repository
$ devkit shell go test ./...
```

If the same file changed on both sides since the last sync, `sync` changes
nothing, lists the files and stops. Run `devkit sync --overwrite` to take
your Mac's version of exactly those files; the VM's other changes stay. To
keep the VM's version, commit it in the VM or copy it out first. If
something in the VM is in the way of the Mac's change, such as a directory
where your Mac now has a file, `sync` says so and changes nothing: move it
in the VM and sync again.

Editing on your Mac means editing only: the project's tests, builds and
installs run in the VM (habit 1). Nothing comes back the other way. Commit
and push on your Mac what you did there, as you always have; get work done
in the VM out with `devkit push` (step 5).

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

**What it reached.** Every request the VM made through the proxy, allowed or
blocked, is in a log you read from your Mac:

```console
$ devkit logs -n 3
... [EGRESS] ALLOWED CONNECT proxy.golang.org:443 (matched: proxy.golang.org)
... [EGRESS] ALLOWED CONNECT raw.githubusercontent.com:443 (matched: **.githubusercontent.com)
... [EGRESS] BLOCKED CONNECT example.org:443
```

The log is kept in the VM and goes when the VM does (under
`network.enforce: host` it is the Mac's own proxy that writes it, on the
Mac). A connection that tries to go around the proxy is dropped by the
firewall and is not listed.

Read it after an install. A dependency that reaches for a host you did not
expect is the thing to notice, whether it was allowed or blocked. When a
build genuinely needs another host, add it to `network.allow` and run
`devkit up`; the change
is one line you can see in a diff. To watch the sandbox refuse a fuller set
of escape attempts, run `examples/hostile-project`.

## 5. Get your commits to a pull request

**If you edit on your Mac (A):** nothing changes. Commit and push from your
Mac with git, as before. The VM was only where the code ran.

**If you commit in the VM (A or B):** the VM has no credentials, on purpose:
a token in there would be usable by every dependency. Your Mac pushes
instead, after showing you what it is about to push.

Commit in the VM:

```console
~/workspace$ git checkout -b fix-typo
~/workspace$ git commit -am "Docs: fix a typo"
```

Then, on your Mac, in the project directory, run `devkit push`. In A that
directory is your checkout. In B it is the directory `devkit clone` made: it
has no project files, but it does hold a repository, the bare clone in
`.devkit/repo.git`, and that is where the VM's commits are brought to and
pushed from.

```console
$ devkit push
fix-typo does not exist on origin yet; the push creates it

Commits from the VM for origin fix-typo (stored at refs/devkit/example-repo/fix-typo):
  3017c3e83599 Your Name <you@example.com>  Docs: fix a typo

README.md | 2 ++
 1 file changed, 2 insertions(+)

Inspect in full with: git log -p refs/devkit/example-repo/fix-typo

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
`git fetch` brings them from the remote like anyone else's. Before you
`git pull` them into the checkout, see the third habit below: a pull can run
code.

To push to your fork rather than the upstream, add the remote on the Mac
(in B: `git --git-dir .devkit/repo.git remote add fork <url>`) and use
`devkit push --remote fork`.

## 6. Keep up with upstream

**A:** pull on your Mac, then bring the result in: `git pull && devkit sync`.
If the pull changed a file you also changed in the VM, `sync` stops and
says which (step 4). Mind the third habit below if the commits you are
pulling came from the VM.

**B:** your Mac fetches and hands the new commits to the VM, which never
talks to the remote itself.

```console
$ devkit sync
Keeping the VM's own git repository
Fetching main on your Mac
Up to date with origin/main
```

When there are new commits, `sync` updates `origin/main` in the VM and
fast-forwards `main`. It does not touch the branch you are working on: after
step 5 you are on `fix-typo`, and `sync` says so (`you are on fix-typo, which
is unchanged`). Bring the new commits into your branch yourself, in the VM:

```console
~/workspace$ git rebase origin/main      # or: git merge origin/main
```

## 7. Tighten it when you can

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

## 8. Throw it away

```console
$ devkit rm
Deleted VM devkit-example-repo
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
3. **Read commits from the VM before they reach a checkout on your Mac.** A
   `git pull` can run code by itself. Git runs the project's hooks when a
   pull finishes, and in many projects (any that use husky, for one) those
   hooks are ordinary files in the repository, so a commit can change them.
   What to do:
   - Look at what `devkit push` flagged. Hook files are on that list.
   - If you have not read the commits, pull with hooks off:
     `git -c core.hooksPath=/dev/null pull`.
   - Either way, do not run the project's tooling in that checkout
     afterwards (habit 1).
4. **Keep `sudo: false`,** and leave `allow_host` off unless the project
   needs a service on your Mac.
5. **Add hosts one at a time,** and only ones you would trust with the
   project's source: an allowed host is also somewhere data can go.
6. **Read `devkit logs` after installs,** and `devkit audit` now and then.
7. **In A, read what `devkit sync` says.** It keeps your VM edits and stops
   when a file changed on both sides; `--overwrite` takes the Mac's version.
8. **Delete VMs freely.** They are meant to be disposable.

What each control does and does not guarantee is in
[SECURITY.md](../SECURITY.md).
