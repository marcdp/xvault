from pprint import pformat
import cryptography
import sys
import os
from dotenv import dotenv_values
from typing import Annotated
from .xvault import XVault
from dprojectstools.commands import command, Argument, Flag, CommandsManager
from dprojectstools.utils.env import format_env_line
from dprojectstools.console import read_password
from importlib.metadata import version, PackageNotFoundError


# utils
def get_app_version() -> str:
    try:
        return version("xvault")
    except PackageNotFoundError:
        return "0.0.0+dev"
    
def error(message: str) -> None:
    RED = "\033[31m"
    RESET = "\033[0m"
    print(f"{RED}{message}{RESET}", file=sys.stderr, flush=True)

def ask_password(confirm: bool = False, min_length: int = 8, message: str = "Enter password") -> str:
    if not sys.stdin.isatty():
        error("Password is required but cannot be entered in non-interactive mode.")
        exit(-1)
    result = read_password(message + ": ", mask="*")
    if confirm:
        if len(result) < min_length:
            error(f"Password must be at least {min_length} characters long.")
            sys.exit(1)
        result_confirm = read_password("Confirm password: ", mask="*")
        if result != result_confirm:
            error("Passwords do not match.")
            sys.exit(1)
    return result


# edit
@command("Edit file", examples=[
    "xvault edit ./dev.json",
    "xvault edit ./dev.yaml",
    "xvault edit ./dev.env",
])
def edit(
        path: Annotated[str,  Argument("PATH")],
        key: Annotated[str,  Argument("KEY")] = "",
        no_cache_key: Annotated[bool,  Flag('n', "no-cache-key")] = False
    ):
    # validate
    if not os.path.exists(path):
        error(f"File '{path}' not found.")
        return -1
    # ask for password if interactive and not provided
    password = None
    if no_cache_key or XVault.is_locked_file(path) or XVault.is_uninitialized_file(path):
        password = ask_password()
    # create instance
    xvault = XVault(path, password = password, no_cache_key = no_cache_key)
    # action
    if key:
        xvault.edit_secret(key)
    else:
        xvault.edit()



# show
@command("Get value from file", examples=[
    "xvault get ./dev.json VAR1",
    "xvault get ./dev.yaml DB.VAR2",
])
def get(
        path: Annotated[str,  Argument("PATH")],
        key: Annotated[str,  Argument("KEY")],
        resolve: Annotated[bool,  Flag('r', "resolve")] = False,
        no_cache_key: Annotated[bool,  Flag('n', "no-cache-key")] = False
    ):
    # validate
    if not os.path.exists(path):
        error(f"File '{path}' not found.")
        return -1
    # ask for password if interactive and not provided
    password = None
    if no_cache_key or XVault.is_locked_file(path) or XVault.is_uninitialized_file(path):
        password = ask_password()
    # create instance
    xvault = XVault(path, password = password, no_cache_key = no_cache_key)
    # action
    value = xvault.get(key, resolve = resolve)
    # print
    if value == None:
        error(f"Key '{key}' not found.") 
        return -1
    print(value)


# version
@command("Show xvault version", alias=["version"], examples=[
    "xvault version"
])
def versioncmd(
    ):
    print(f"xvault {get_app_version()}")


# unlock
@command("Unlock file", examples=[
    "xvault unlock ./dev.json"
])
def unlock(
        path: Annotated[str,  Argument("PATH")]
    ):
    # validate
    if not os.path.exists(path):
        error(f"File '{path}' not found.")
        return -1
    if not XVault.is_locked_file(path):
        error(f"File '{path}' is not locked.")
        return -1
    # ask for password if interactive and not provided
    password = ask_password()
    # create instance 
    xvault = XVault(path, password = password)
    # action
    xvault.unlock()
    # log
    print(f"File '{path}' unlocked.")

# lock
@command("Lock file", examples=[
    "xvault lock ./dev.json"
])
def lock(
        path: Annotated[str,  Argument("PATH")]
    ):
    # validation
    if not os.path.exists(path):
        error(f"File '{path}' not found.")
        return -1
    if XVault.is_uninitialized_file(path):
        error(f"File '{path}' is not initialized.")
        return -1
    if XVault.is_locked_file(path):
        error(f"File '{path}' is already locked.")
        return -1    
    # create instance 
    xvault = XVault(path)
    # action
    xvault.lock()
    # log
    print(f"File '{path}' locked.")

# export
@command("Export file", examples=[
    "xvault export ./dev.json",
])
def export(
        path: Annotated[str,  Argument("PATH")],
        resolve: Annotated[bool,  Flag('r', "resolve")] = False,
        no_cache_key: Annotated[bool,  Flag('n', "no-cache-key")] = False
    ):
    # export
    if not os.path.exists(path):
        error(f"File '{path}' not found.")
        return -1
    # ask for password if interactive and not provided
    password = None
    if no_cache_key or XVault.is_locked_file(path) or XVault.is_uninitialized_file(path):
        password = ask_password()
    # create instance
    xvault = XVault(path, password = password, no_cache_key = no_cache_key)
    # action
    print(xvault.export(resolve=resolve))
    

# info
@command("Show file info", examples=[
    "xvault info dev.json"
])
def info(
        path: Annotated[str,  Argument("PATH")]
    ):
    # validate
    if not os.path.exists(path):
        error(f"File '{path}' not found.")
        return -1
    # create instance 
    xvault = XVault(path)
    # action
    info = xvault.info()
    # print
    width = max(len(k) for k in info.keys())
    print(f"File info:")
    print("-" * (width + 2))
    for k, v in info.items():
        print(f"{k:<{width}} : {v}")

# rekey
@command("Rekey file", examples=[
    "xvault rekey ./dev.json",
])
def rekey(
        path: Annotated[str,  Argument("PATH")],
        no_cache_key: Annotated[bool,  Flag('n', "no-cache-key")] = False
    ):
    # export
    if not os.path.exists(path):
        error(f"File '{path}' not found.")
        return -1
    # ask for password if interactive and not provided
    password = None
    if no_cache_key or XVault.is_locked_file(path) or XVault.is_uninitialized_file(path):
        password = ask_password()
    #
    new_password = ask_password(message = "New password", confirm=True)
    # create instance
    xvault = XVault(path, password = password, no_cache_key = no_cache_key)
    # action
    xvault.rekey(new_password)
    

# validate
@command("Validate file", examples=[
    "xvault validate ./dev.json",
])
def validate(
        path: Annotated[str,  Argument("PATH")],
        verbose: Annotated[bool, Flag('v', "verbose")] = False,
        no_cache_key: Annotated[bool,  Flag('n', "no-cache-key")] = False
    ):
    # export
    if not os.path.exists(path):
        error(f"File '{path}' not found.")
        return -1
    # ask for password if interactive and not provided
    password = None
    if no_cache_key or XVault.is_locked_file(path) or XVault.is_uninitialized_file(path):
        password = ask_password()
    # action
    try:
        xvault = XVault(path, password = password, no_cache_key = no_cache_key)
        result = xvault.validate()
    except Exception as e:
        result = {
            "checks":[
                {"name": "load", "severity": "error", "message": f"error: {str(e)}"}
            ],
            "status": "error"
        }
        error(f"Error: {str(e)}")
        return -1
    # action    
    width = max(len(check["name"]) for check in result["checks"]) if result["checks"] else 0
    for check in result["checks"]:
        print(f"- {check['name']:<{width}} : {check['message']}")
    print("Status: " + result["status"])

# TODO
# x env format
# x when edit: only reencrypt changed values
# x validate command
# x remove v1:
# x create scafolding for md, xml, yaml
# x md format
# x yaml format
# x get
# x xedit editor bar bottom
# x xedit should use fileextension as "format"
# x xvault get file.env PATH -> should show unescaped value
# x xvault get file.json PATH -> should show unescaped and undecoded
# x xvault get file.yaml PATH -> should show unescaped and undecoded
# x xedit PATH ---- over unexisting file should initialize it on save
# x xedit search
# x xedit ro
# x xedit help
# x xvault edit over unexisting file should ask for password and initialize it on save
# x xeditor: colorize env
# x xeditor: colorize md
#x  xeditor: colorize json
# replace inner variables format



# main
def main():
    commandsManager = CommandsManager()
    commandsManager.register(module = sys.modules[__name__])
    try:
        commandsManager.execute(sys.argv, default_show_help = True)
    except cryptography.exceptions.InvalidTag as ee:
        raise
    except Exception as e:        
        error(f"{e}")
        sys.exit(1)
if __name__ == "__main__":
    main()



