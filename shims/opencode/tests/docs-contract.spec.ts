// T-SEAT, documentation half: the shipped wording the port contract says never to soften.
// A README or checklist edit that drops one of these lines fails here, not in review.

import { describe, expect, test } from 'bun:test'
import { readFileSync } from 'node:fs'
import { join } from 'node:path'

const OPENCODE_DIR = join(import.meta.dir, '..')
const readme = readFileSync(join(OPENCODE_DIR, 'README.md'), 'utf8')
const checklist = readFileSync(join(OPENCODE_DIR, 'RELEASE-CHECKLIST.md'), 'utf8')

// Collapse markdown line wrapping so a reflowed paragraph still matches.
const flat = (text: string) => text.replace(/\s+/g, ' ')

const POSTURE_LINE =
  '🏰 barmkin-opencode 0.1.0 (core <git-sha>) · partial port, not equivalent to barmkin-mod for Claude Code · ' +
  'OpenCode 2 has no administrator-locked plugin seat · not covered: <per-seat gaps>'

// Re-scout section 2.2, "Honest P3 wording for the README and posture line".
const P3_WORDING =
  'Outward-effect tools (shell, web fetch, file writes) are refused while the session is tainted, **provided this guard is loaded**. ' +
  "The refusal is re-checked at OpenCode's permission step against the final command, URL or path, so another plugin cannot rewrite its way past it. " +
  'It does **not** cover MCP tool arguments, Code Mode `fetch`, or command-template shell. ' +
  "**OpenCode 2 has no administrator-locked plugin seat:** a repository's `opencode.json` can unload this guard unless project config is disabled or the guard is seated through `OPENCODE_CONFIG_CONTENT`. " +
  '**No posture line means no guard.**'

const SHELL_LAYER_LIMITATION =
  'OpenCode 2 does not give plugins the session identity of a shell call, so a session taint can restrict shell commands in unrelated sessions on the same instance, ' +
  'and a shell not launched through a tool call bypasses the shell gate entirely.'

describe('README non-equivalence contract', () => {
  test('carries the re-scout section 2.2 wording verbatim', () => {
    expect(flat(readme)).toContain(flat(P3_WORDING))
  })

  test('says plainly that OpenCode 2 has no administrator-locked plugin seat, and never softens it', () => {
    expect(flat(readme)).toContain('OpenCode 2 has no administrator-locked plugin seat')
    expect(readme).toContain('not equivalent to barmkin-mod for Claude Code')
    expect(readme).toContain('not administrator-enforced')
    expect(readme).not.toMatch(/\b(mostly|largely|nearly|almost) (equivalent|the same)\b/i)
  })

  test('shows the binding posture line', () => {
    expect(readme).toContain(POSTURE_LINE)
  })

  test('names the four NOT-covered items', () => {
    const text = flat(readme)
    expect(text).toContain('Evidence stays in stored transcripts')
    expect(text).toContain('MCP tool descriptions are only as clean as the neutraliser')
    expect(text).toContain('No protection when the guard is absent')
    expect(text).toContain('The repo-plugin surround')
  })

  test('documents the human-origin, command-template and shell-layer limitations', () => {
    const text = flat(readme)
    expect(text).toContain('Human-origin clearing')
    expect(text).toContain('Command-template shell')
    expect(text).toContain(flat(SHELL_LAYER_LIMITATION))
    expect(text).toContain('`shell.create.before` carries no session in its inputs')
  })

  test('says the taint is sticky and has no clear command', () => {
    const text = flat(readme)
    expect(text).toContain('The taint is therefore sticky: nothing clears it')
    expect(text).toContain('there is no clear command')
    expect(readme).not.toContain('/barmkin-mod-clear-taint')
  })

  test('says an unsandboxed OpenCode is refused by the monitor, and when to set sandboxed', () => {
    const text = flat(readme)
    expect(text).toContain('with OpenCode as it ships, the monitor refuses every session and every guarded call is denied.')
    expect(text).toContain('Set the `sandboxed` option only when OpenCode itself runs inside an OS sandbox whose tools cannot reach the monitor socket')
  })

  test('documents the shell-layer rule for an ambiguous session (C5)', () => {
    expect(flat(readme)).toContain('denies it only when every one of them would deny it')
  })
})

describe('README seat recipe, install and tested range', () => {
  test('names all three parts of the recipe', () => {
    expect(readme).toContain('OPENCODE_CONFIG_CONTENT')
    expect(readme).toContain('experimental.policies')
    expect(readme).toContain('deny `plugin:*`')
    expect(readme).toContain('OPENCODE_DISABLE_PROJECT_CONFIG=1')
  })

  test('has install steps and starts the tested range at 2.0.28', () => {
    expect(readme).toMatch(/^## Install$/m)
    expect(readme).toContain('Starts at OpenCode 2.0.28')
  })
})

describe('release checklist', () => {
  test('pins the tested range start version', () => {
    expect(checklist).toContain('2.0.28')
  })

  test('covers every T-SEAT claim by its re-scout check id', () => {
    for (const id of ['V1', 'V2', 'V6', 'V7', 'V8', 'V9', 'V10', 'V14', 'V15', 'V16', 'V38']) {
      expect(checklist).toMatch(new RegExp(`\\*\\*[^*]*\\b${id}\\b`))
    }
  })

  test('requires the fixed posture wording and the README wording to stay verbatim', () => {
    expect(checklist).toContain(POSTURE_LINE)
  })
})
