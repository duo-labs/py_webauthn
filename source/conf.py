# Configuration file for the Sphinx documentation builder.
#
# For the full list of built-in configuration values, see the documentation:
# https://www.sphinx-doc.org/en/master/usage/configuration.html

# -- Project information -----------------------------------------------------
# https://www.sphinx-doc.org/en/master/usage/configuration.html#project-information

project = "py_webauthn"
copyright = "2020, Duo Labs"
author = "Duo Labs"
release = "v2.2.0"

# -- General configuration ---------------------------------------------------
# https://www.sphinx-doc.org/en/master/usage/configuration.html#general-configuration

extensions = ["myst_parser"]

templates_path = ["_templates"]
exclude_patterns = []
html_copy_source = False


# -- Options for HTML output -------------------------------------------------
# https://www.sphinx-doc.org/en/master/usage/configuration.html#options-for-html-output

html_static_path = ["_static"]
html_css_files = ["styles.css"]

# -- Theme configuration -----------------------------------------------------
# https://alabaster.readthedocs.io/en/latest/customization.html

html_theme = "alabaster"
html_theme_options = {
    "github_user": "duo-labs",
    "github_repo": "py_webauthn",
    "description": "Pythonic WebAuthn 🐍",
    "github_button": True,
    "show_powered_by": False,
    "show_relbar_bottom": True,
}
html_sidebars = {
    "**": [
        "about.html",
        "searchfield.html",
        "navigation.html",
        "relations.html",
    ]
}

# -- Extension Configuration - MyST Parser -----------------------------------
# https://myst-parser.readthedocs.io/en/latest/configuration.html

myst_enable_extensions = [
    "colon_fence",
    "strikethrough",
]
myst_heading_anchors = 3
