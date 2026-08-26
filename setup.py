"""Packaging metadata lives in pyproject.toml; this shim keeps
`pip install -e .` working on older toolchains."""

from setuptools import setup

setup()
