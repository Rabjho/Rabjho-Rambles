# Rabjho-Rambles

Blog at https://0065537.xyz, built with [Quartz](https://quartz.jzhao.xyz/) from notes in my Obsidian vault.

## Writing a post

1. In the vault, create a note in `Posts/` from `Templates/Post.md`.
2. Set `publish: true` when it's ready. Only notes with `publish: true` (and the attachments they embed) ever leave the vault.
3. `blog-tags` become the tags on the site; the vault's own `tags` are dropped when syncing.

## Publishing

```bash
npm run sync              # copy published notes from the vault into content/
npx quartz build --serve  # preview at http://localhost:8080
git add content && git commit -m "Publish <post>" && git push
```

Put the vault path in `.env` as `VAULT=/path/to/vault` (gitignored, so your local paths stay off GitHub), or pass it with `npm run sync -- /path/to/vault`. Each sync wipes `content/` apart from `index.md`, so don't edit files there by hand. It warns when a post links to a private note or a missing file, or contains your home directory path. `content/index.md` is the homepage and lives in this repo, not the vault.

Cloudflare Pages builds the site with `npx quartz build`, output directory `public`, and `NODE_VERSION=22`.

## Updating Quartz

```bash
git fetch upstream && git merge upstream/v4
```
