#!/usr/bin/env node
// Copies every note with `publish: true` from the Obsidian vault into content/,
// along with the attachments those notes embed. Nothing else leaves the vault.
//
// This repo lives in the vault as the hidden folder .blog/, so the vault is the parent
// directory. Usage: npm run sync [-- /path/to/vault]

import fs from "node:fs"
import os from "node:os"
import path from "node:path"
import matter from "gray-matter"

const VAULT = path.resolve(process.argv[2] ?? path.join(import.meta.dirname, ".."))
const CONTENT = path.resolve(import.meta.dirname, "content")
// content/index.md is the homepage and is maintained in this repo, not the vault
const KEEP = new Set(["index.md"])

function walk(dir, out = []) {
  for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
    if (entry.isDirectory()) {
      // dot-folders hold app and tool state; Templates hold unfilled placeholders
      if (!entry.name.startsWith(".") && entry.name !== "Templates") {
        walk(path.join(dir, entry.name), out)
      }
    } else {
      out.push(path.relative(VAULT, path.join(dir, entry.name)))
    }
  }
  return out
}

if (!fs.existsSync(path.join(VAULT, ".obsidian"))) {
  console.error(`Not an Obsidian vault: ${VAULT}`)
  process.exit(1)
}

const files = walk(VAULT)
const notes = new Map() // rel path -> { published }
const byName = new Map() // lowercased basename (md files without extension) -> [rel paths]
for (const rel of files) {
  const isMd = rel.endsWith(".md")
  if (isMd) {
    const { data } = matter(fs.readFileSync(path.join(VAULT, rel), "utf8"))
    notes.set(rel, { published: data.publish === true || data.publish === "true" })
  }
  const key = (isMd ? path.basename(rel, ".md") : path.basename(rel)).toLowerCase()
  byName.set(key, [...(byName.get(key) ?? []), rel])
}

// Resolve a link target the way Obsidian's "shortest path" setting does
function resolve(target, fromRel) {
  target = decodeURIComponent(target.trim())
  if (!target) return undefined
  const candidates = [target, `${target}.md`]
  for (const c of candidates) {
    for (const base of [path.dirname(fromRel), ""]) {
      const rel = path.normalize(path.join(base, c))
      if (files.includes(rel)) return rel
    }
  }
  const key = (target.endsWith(".md") ? target.slice(0, -3) : path.basename(target)).toLowerCase()
  return byName.get(key)?.[0]
}

function linkTargets(text) {
  // ignore links inside code so CTF payloads like [[x]] don't count
  const prose = text.replace(/```[\s\S]*?```/g, "").replace(/`[^`\n]*`/g, "")
  const targets = []
  for (const m of prose.matchAll(/\[\[([^\]|#^]*)/g)) targets.push(m[1])
  for (const m of prose.matchAll(/\]\(([^)\s]+)\)/g)) {
    if (!/^[a-z]+:|^#|^\//i.test(m[1])) targets.push(m[1].split("#")[0])
  }
  return targets
}

const published = [...notes].filter(([, n]) => n.published).map(([rel]) => rel)
const toCopy = new Set(published)
const warnings = []
for (const rel of published) {
  const text = fs.readFileSync(path.join(VAULT, rel), "utf8")
  if (text.includes(os.homedir())) {
    warnings.push(`${rel}: contains your home directory path`)
  }
  for (const target of linkTargets(text)) {
    if (!target.trim()) continue
    const hit = resolve(target, rel)
    if (!hit) {
      warnings.push(`${rel}: link to missing "${target}"`)
    } else if (!hit.endsWith(".md")) {
      toCopy.add(hit)
    } else if (!notes.get(hit).published) {
      warnings.push(`${rel}: links to private note "${hit}" (its name will be public)`)
    }
  }
}

fs.mkdirSync(CONTENT, { recursive: true })
for (const entry of fs.readdirSync(CONTENT)) {
  if (!KEEP.has(entry)) fs.rmSync(path.join(CONTENT, entry), { recursive: true })
}
for (const rel of toCopy) {
  if (KEEP.has(rel)) {
    warnings.push(`${rel}: skipped, would overwrite the homepage`)
    continue
  }
  fs.mkdirSync(path.join(CONTENT, path.dirname(rel)), { recursive: true })
  if (rel.endsWith(".md")) {
    // vault tags are a private taxonomy; the site only gets `blog-tags`
    const note = matter(fs.readFileSync(path.join(VAULT, rel), "utf8"))
    note.data.tags = note.data["blog-tags"] ?? []
    delete note.data["blog-tags"]
    fs.writeFileSync(path.join(CONTENT, rel), matter.stringify(note.content, note.data))
  } else {
    // write rather than copy so vault file modes (often +x) don't leak into git
    fs.writeFileSync(path.join(CONTENT, rel), fs.readFileSync(path.join(VAULT, rel)))
  }
}

console.log(`Synced ${published.length} notes and ${toCopy.size - published.length} attachments`)
for (const rel of published.sort()) console.log(`  ${rel}`)
for (const w of warnings) console.warn(`warning: ${w}`)
