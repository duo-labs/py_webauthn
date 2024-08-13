# py_webauthn Docs Site

A proper attempt at documenting the intended use of **py_webauthn**.

Currently hosted via GitHub pages at **TBD**

The **docs** branch this site exists as code in SHOULD NEVER BE
REBASED ON THE MASTER BRANCH.

## Requirements

- Python 3.11

## Development

This site uses Sphinx to generate docs. To get started, install dependencies then launch the live
development server:

```sh
$> pip install -r requirements.txt
$> make livehtml
```

Pages are authored in Markdown with a few MyST plugins activated. See **source/conf.py** for more
info.

## Deployment

Deployed via GitHub Actions.
