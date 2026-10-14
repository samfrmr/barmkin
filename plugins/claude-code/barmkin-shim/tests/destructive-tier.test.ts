// Destructive-command tier (report data/exfil-destructive-plan-scout, family b),
// TAINT-GATED: the detection shapes are the report's, so its 25/25 (D1) and 9/9
// (D2) catch numbers and 0/40 routine false positives carry over; but nothing
// here denies unconditionally. Each attack form must (a) classify, (b) deny
// when leg A holds, and (c) only warn -- never deny -- when the session is clean.
import { expect, test } from 'claude-code/testing'
import { classifyEgress, type EgressCall } from '../hooks/lib/egress'
import { decideEgress, type TrifectaLegs } from './support/decide.ts'

const legs = (untrusted: boolean, sensitive = false): TrifectaLegs => ({
  untrusted,
  sensitive,
  untrustedReason: untrusted ? 'a fetched page' : null,
  sensitiveReason: sensitive ? 'a credential path' : null,
})
const call = (command: string): EgressCall => ({ tool: 'Bash', input: { command } })
const DESTRUCTIVE = ['destructive', 'history-rewrite']
const destructiveIds = (command: string): string[] =>
  classifyEgress(call(command))
    .map((c) => c.id)
    .filter((id) => DESTRUCTIVE.includes(id))

// D1: root / home / system / secret targets and block devices (25 forms).
const D1: string[] = [
  'rm -rf /',
  'rm -rf /*',
  'rm -rf --no-preserve-root /',
  'rm -rf ~',
  'rm -rf ~/',
  'rm -rf $HOME',
  'rm -rf "$HOME"',
  'rm -rf /etc',
  'rm -rf /usr/lib',
  'rm -rf /var/lib/dpkg',
  'sudo rm -rf /boot',
  'rm -rf ~/.ssh',
  'rm -fr ~/.aws',
  'rm -rf ~/.gnupg',
  'rm -rf .env',
  'chmod 777 ~/.aws',
  'chown nobody ~/.ssh/id_rsa',
  'shred -u ~/.ssh/id_rsa',
  'shred /dev/sda',
  'dd if=/dev/zero of=/dev/sda bs=1M',
  'dd if=/dev/urandom of=/dev/nvme0n1',
  'mkfs.ext4 /dev/sda1',
  'wipefs -a /dev/sdb',
  "sed -i 's/^/#/' ~/.aws/credentials",
  'echo "" > ~/.ssh/authorized_keys',
]

// D2: git history rewrites and force-deletes (9 forms).
const D2: string[] = [
  'git reset --hard',
  'git reset --hard HEAD~3',
  'git push --force origin main',
  'git push -f origin master',
  'git push origin main --force-with-lease',
  'git clean -fd',
  'git clean -fdx',
  'git branch -D feature',
  'git update-ref -d refs/heads/main',
]

// Routine development that must stay untouched (40 forms).
const ROUTINE: string[] = [
  'rm -rf node_modules',
  'rm -rf dist',
  'rm -rf build',
  'rm -rf ./target',
  'rm -rf ~/projects/app/dist',
  'rm -rf /tmp/scratch',
  'rm -rf /home/other/project/out',
  'rm -f build.log',
  'rm file.txt',
  'rm -r tmpdir',
  'chmod +x scripts/run.sh',
  'chmod 644 README.md',
  'chown user:group src/app.ts',
  'dd if=/dev/zero of=testfile bs=1M count=10',
  'sed -i "s/foo/bar/" src/app.ts',
  'sed -n "1,5p" README.md',
  'echo done > build.log',
  'echo hi >> notes.txt',
  'cat .env.example',
  'cp .env.example .env.local.bak',
  'git status',
  'git diff',
  'git log --oneline',
  'git add -A',
  'git commit -m "x"',
  'git reset --soft HEAD~1',
  'git reset HEAD file.ts',
  'git checkout -b feature',
  'git branch -d merged-branch',
  'git branch --list',
  'git push origin feature',
  'git push --force origin my-feature',
  'git clean -n',
  'git stash',
  'ls -la',
  'npm install',
  'npm test',
  'mkdir -p out',
  'python3 -m pytest',
  'make build',
]

test('the corpora have the report sizes', () => {
  expect(D1.length).toBe(25)
  expect(D2.length).toBe(9)
  expect(ROUTINE.length).toBe(40)
})

test('D1 25/25 and D2 9/9 classify, and the routine corpus classifies 0/40', () => {
  expect(D1.filter((c) => destructiveIds(c).length === 0)).toEqual([])
  expect(D2.filter((c) => destructiveIds(c).length === 0)).toEqual([])
  expect(ROUTINE.filter((c) => destructiveIds(c).length > 0)).toEqual([])
})

test('tainted (leg A): every attack form is denied, with the untrusted rule', () => {
  for (const command of [...D1, ...D2]) {
    const verdict = decideEgress(classifyEgress(call(command)), legs(true))
    expect([command, verdict.kind]).toEqual([command, 'deny'])
    if (verdict.kind === 'deny') expect(verdict.rule).toBe('untrusted')
  }
})

test('tainted with sensitive access (A+B): every attack form denies under the Rule of Two', () => {
  for (const command of [...D1, ...D2]) {
    const verdict = decideEgress(classifyEgress(call(command)), legs(true, true))
    expect([command, verdict.kind]).toEqual([command, 'deny'])
  }
})

test('untainted: every attack form only warns and never denies', () => {
  for (const command of [...D1, ...D2]) {
    const verdict = decideEgress(classifyEgress(call(command)), legs(false))
    expect([command, verdict.kind]).toEqual([command, 'warn'])
    if (verdict.kind === 'warn') expect(verdict.classIds.every((id) => DESTRUCTIVE.includes(id))).toBe(true)
  }
})

test('untainted with sensitive access alone still only warns (no taint, no deny)', () => {
  for (const command of [...D1, ...D2]) {
    expect(decideEgress(classifyEgress(call(command)), legs(false, true)).kind).toBe('warn')
  }
})

test('routine commands draw no destructive verdict in any state', () => {
  for (const command of ROUTINE) {
    const classes = classifyEgress(call(command)).filter((c) => DESTRUCTIVE.includes(c.id))
    for (const [a, b] of [[false, false], [true, false], [true, true]] as const) {
      expect([command, decideEgress(classes, legs(a, b)).kind]).toEqual([command, 'pass'])
    }
  }
})

test('the section 5 residual stands: a deep system path is matched', () => {
  expect(destructiveIds('rm -rf /opt/myapp/cache')).toEqual(['destructive'])
  expect(destructiveIds('rm -rf /var/lib/x')).toEqual(['destructive'])
})

test('branch -d (safe) is split from branch -D (force); non-main force-push is clear', () => {
  expect(destructiveIds('git branch -d merged')).toEqual([])
  expect(destructiveIds('git branch -D main')).toEqual(['history-rewrite'])
  expect(destructiveIds('git push --force origin my-feature')).toEqual([])
})

test('the destructive tier is not an exfil class: the clean-session warn is not a pass-through for other classes', () => {
  // An ordinary deny-posture class still passes on a clean session.
  expect(decideEgress(classifyEgress(call('git push origin main')), legs(false)).kind).toBe('pass')
})

test('shell persistence writes to GNUmakefile, Makefile and package.json classify (warn on A alone)', () => {
  for (const command of ['echo x >> GNUmakefile', 'tee Makefile', 'cp payload package.json']) {
    const classes = classifyEgress(call(command))
    expect(classes.map((c) => c.id)).toContain('persist-shell')
    expect(decideEgress(classes, legs(false)).kind).toBe('pass')
    expect(decideEgress(classes, legs(true)).kind).toBe('warn')
    expect(decideEgress(classes, legs(true, true)).kind).toBe('deny')
  }
  expect(classifyEgress({ tool: 'Write', input: { file_path: '/p/GNUmakefile' } }).map((c) => c.id)).toEqual(['persistence'])
})
