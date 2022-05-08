# Configuration file for the Sphinx documentation builder.
#
# This file only contains a selection of the most common options. For a full
# list see the documentation:
# https://www.sphinx-doc.org/en/master/usage/configuration.html

# -- Path setup --------------------------------------------------------------

# If extensions (or modules to document with autodoc) are in another directory,
# add these directories to sys.path here. If the directory is relative to the
# documentation root, use os.path.abspath to make it absolute, like shown here.
#
import os
import sys

sys.path.insert(0, os.path.abspath('..'))

from scf import __version__  # noqa: E402


# -- Project information -----------------------------------------------------

project = 'scf'
copyright = '2022, dadav'
author = 'dadav'

release = __version__.split("+")[0]
version = release

# -- General configuration ---------------------------------------------------

# Add any Sphinx extension module names here, as strings. They can be
# extensions coming with Sphinx (named 'sphinx.ext.*') or your custom
# ones.
extensions = [
    'sphinx.ext.autodoc',
    'sphinx.ext.coverage',
    'sphinxcontrib.programoutput',
    'sphinx_copybutton',
    'myst_parser',
]

needs_extensions = {"myst_parser": "0.13.7"}

# Add any paths that contain templates here, relative to this directory.
templates_path = ['_templates']

source_suffix = [".rst", ".md"]

master_doc = "index"

# Custom sidebar templates, must be a dictionary that maps document names
# to template names.
#
# The default sidebars (for documents that don't match any pattern) are
# defined by theme itself. Builtin themes are using these templates by
# default: ``['localtoc.html', 'relations.html', 'sourcelink.html',
# 'searchbox.html']``.
#
# html_sidebars = {
#     '**': ['sidebarintro.html'],
# }

# List of patterns, relative to source directory, that match files and
# directories to ignore when looking for source files.
# This pattern also affects html_static_path and html_extra_path.
exclude_patterns = ['_build', 'Thumbs.db', '.DS_Store']

# The name of the Pygments (syntax highlighting) style to use.
pygments_style = 'sphinx'

# We need headers to be linkable to so ask MyST-Parser to autogenerate anchor IDs for
# headers up to and including level 3.
myst_heading_anchors = 3

# Prettier support formatting some MyST syntax but not all, so let's disable the
# unsupported yet still enabled by default ones.
myst_disable_syntax = [
    "colon_fence",
    "myst_block_break",
    "myst_line_comment",
    "math_block",
]

# Optional MyST Syntaxes
myst_enable_extensions = []

# -- Options for HTML output -------------------------------------------------

htmlhelp_basename = 'scfdoc'

# The theme to use for HTML and HTML Help pages.  See the documentation for
# a list of builtin themes.
#
html_theme = 'furo'
html_logo = '_static/scf_no_text.png'

# Add any paths that contain custom static files (such as style sheets) here,
# relative to this directory. They are copied after the builtin static files,
# so a file named "default.css" will overwrite the builtin "default.css".
html_static_path = ['_static']

# -- Options for copybutton
copybutton_prompt_text = "$ "
