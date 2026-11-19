"""Packaging configuration for angry-cli (installs the `ipscan` command)."""

from setuptools import find_packages, setup

setup(
    name="angry-cli",
    version="1.1.1",
    description="Headless CLI and interactive REPL powered by the real Angry IP Scanner Java engine.",
    packages=find_packages(include=["angry_cli*"]),
    package_data={
        "angry_cli": [
            "libs/*.jar",
            "bridge/*.java",
            "bridge/classes/.bridge_hash",
            "bridge/classes/org/angrycli/bridge/*.class",
        ],
    },
    include_package_data=True,
    install_requires=[
        "click>=6.7",
        "prompt-toolkit>=2.0.0",
    ],
    entry_points={
        "console_scripts": [
            "ipscan=angry_cli.cli:main",
        ],
    },
    python_requires=">=3.6",
)
