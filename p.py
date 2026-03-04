#!/usr/bin/env python3
from dprojectstools.commands import command, CommandsManager
from dprojectstools.git import GitManager
from xvault import XVault
import subprocess
import sys
import os
import shutil

# # prepare environment:
# pip install --upgrade build
# py -m pip install --upgrade twine
#
# # increase version
# ... manuallly

# # build:
# py -m build
#
# # publish package to index
# py -m twine upload dist/*

# install as development package:
# pip install -e .
# # manually add to the path c:\users\myuser\appdata\local\programs\python\python3....\...\scripts

# xvault
xvault = XVault("default")
print(xvault.getValue("PYPI_AUTH_TOKEN"))

# controllers
@command("Package build", index = 10)
def package_build():
    if os.path.exists("./dist"):
        shutil.rmtree("./dist")
    subprocess.run("py -m build")

@command("Package build and publish")
def package_publish():
    # build
    package_build()
    # publish
    myenv = os.environ.copy()
    myenv["TWINE_PASSWORD"] = xvault.getValue("PYPI_AUTH_TOKEN")
    subprocess.run("py -m twine upload dist/*", env = myenv)

@command("Package install as development package", index = 15)
def package_install():
    # install
    subprocess.run("pip install -e .") 

# execute
commandsManager = CommandsManager()
commandsManager.register()
commandsManager.register(GitManager())
commandsManager.execute(sys.argv)
