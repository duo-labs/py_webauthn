# py_webauthn Docs Site

A proper attempt at documenting the intended use of **py_webauthn**.

Currently hosted via GitHub pages at https://duo-labs.github.io/py_webauthn

The **docs** branch this site exists as code in SHOULD NEVER BE
REBASED ON THE MASTER BRANCH.

## Requirements

- Python 3.12
- [uv](https://docs.astral.sh/uv/)

## Development

This site uses Sphinx to generate docs. To get started, install dependencies then launch the live
development server:

```sh
$> uv sync
$> uv run make livehtml
```

Pages are authored in Markdown with a few MyST plugins activated. See **source/conf.py** for more
info.

## Deployment

Deployed via GitHub Actions.
