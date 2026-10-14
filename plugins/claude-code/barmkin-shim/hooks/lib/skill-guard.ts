// Pure helpers for the skill-content guards. No `$` use here: register.ts
// makes the screen, redaction and taint calls and uses these for the text it
// hands back.

import { neutralizeDescription } from './mcp-guard'

// The text that replaces a skill body the screen denied, or that could not be
// checked. The event's `skill` name stays unchanged (the dispatcher rejects a
// changed name), so only the body is replaced.
export function skillBodyWithheldText(reason: string): string {
  return "barmkin: withheld this skill's body (" + reason + '). Ask the user before retrying.'
}

// The replacement for a whole skill listing the neutraliser could not check.
export function skillListingWithheldText(reason: string): string {
  return 'barmkin: withheld the skill listing (' + reason + '). Ask the user before retrying.'
}

// A listing entry is `- <name>: <description>`. A name can itself hold a colon
// (plugin skills are `plugin:skill`), so the split is on the first colon that
// is followed by a space, which a name's own colon never is.
const LISTING_ENTRY = /^- (.+?): ([\s\S]*)$/

// Every line that begins with a bullet starts a new chunk. Any other line is a
// continuation of the chunk above it.
const ENTRY_START = /\n(?=- )/

// Sentence punctuation and any whitespace run become single spaces, so a phrase
// is matched between its words whatever separates them.
function flatten(text: string): string {
  return text.replace(/[.!?]/g, ' ').replace(/\s+/g, ' ')
}

// Whether an instruction-like phrase appears in the text once sentence
// punctuation and whitespace are normalised.
function hasPhrase(text: string): boolean {
  const flat = flatten(text)
  return neutralizeDescription(flat).description !== flat
}

function firstCompletingIndex(sentences: string[]): number {
  for (let end = 0; end < sentences.length; end++) {
    if (hasPhrase(sentences.slice(0, end + 1).join(' '))) return end
  }
  return -1
}

// Neutralises one description on its own. A sentence that holds an instruction-
// like phrase is removed. A phrase that still appears across the kept sentences
// is removed by dropping the sentence that completes it, so a phrase split by
// sentence punctuation is handled like any other. A description with no kept
// sentence is withheld. Nothing is checked across entries.
function neutralizeEntry(description: string): string {
  const sentences = description.split(/(?<=[.!?])\s+/)
  const kept = sentences.filter((sentence) => !hasPhrase(sentence))
  let end = hasPhrase(kept.join(' ')) ? firstCompletingIndex(kept) : -1
  while (end >= 0) {
    kept.splice(end, 1)
    end = firstCompletingIndex(kept)
  }
  if (kept.length === sentences.length) return description
  return kept.join(' ').trim() || neutralizeDescription(flatten(description)).description
}

// Neutralises a skill listing. A name is never rewritten: an entry whose name
// holds an instruction-like phrase is not listed, and the number of such entries
// is returned. Each remaining description is neutralised on its own. A clean
// listing comes back byte-identical.
export function neutralizeSkillListing(text: string): { text: string; withheld: number } {
  const pieces: string[] = []
  let withheld = 0
  for (const chunk of text.split(ENTRY_START)) {
    const match = LISTING_ENTRY.exec(chunk)
    if (!match) {
      const bullet = chunk.startsWith('- ') ? '- ' : ''
      pieces.push(bullet + neutralizeEntry(chunk.slice(bullet.length)))
      continue
    }
    const [, name, description] = match
    const flatName = flatten(name)
    if (neutralizeDescription(flatName).description !== flatName) {
      withheld++
      continue
    }
    pieces.push('- ' + name + ': ' + neutralizeEntry(description))
  }
  return { text: pieces.join('\n'), withheld }
}
