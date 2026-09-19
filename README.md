# Personal webpage

A single-page personal site with plain HTML, CSS, and a small theme switcher.

Edit `home.html` to update the bio, portrait, links, or styling. `index.html`
redirects the site root to that page. Images live in `images/`.

Blog links and dates are in the section with `id="blogs"`. Add another `<li>`
to its list for a new post. Reading titles, authors, and links are in the section
with `id="recommended-readings"`, grouped by subject. Copy a `<li>` into the
appropriate `.reading-group` list to add a book, then update its `.reading-count`
text. Group names are in `.reading-group-title` spans inside `<summary>` elements.
The native `<details>` groups start collapsed and work with the keyboard and with
JavaScript disabled. The visible `(link)` text stays the same for every book.

Downloadable PDFs live in `books/`. A local PDF link uses `href="books/filename.pdf"`
and the `download` attribute; other recommendations link to an official website
or author-hosted PDF. Sources, editions, and redistribution notices are recorded
in `books/README.md`.

To shrink the name, increase `--name-size-reduction` in `home.html`. This one
setting applies to both desktop and mobile.

The top-right theme button switches between dark and light mode. Dark is the
default; `theme.js` saves the choice in browser storage and restores it before
the page renders. Edit the color variables in `home.html` to adjust either palette.

Preview locally:

```sh
python3 -m http.server 8000
```

Open http://localhost:8000.
