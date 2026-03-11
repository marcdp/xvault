from pprint import pformat
import cryptography
import sys
import os
import json
from dotenv import dotenv_values
import secrets as secrets_module
from typing import Annotated
from .xvault import XVault
from .xvaultstore import XVaultStore 
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
    value = xvault.get(key)
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
    print(xvault.export())
    

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

# xedit editor bar bottom
# xedit help
# xedit search

# xedit PATH ---- over unexisting file should initialize it on save
# xedit should use fileextension as "format"

# xvault get file.env PATH -> should show unescaped value
# xvault get file.json PATH -> should show unescaped and undecoded
# xvault get file.yaml PATH -> should show unescaped and undecoded

# xvault edit over unexisting file should ask for password and initialize it on save
# xeditor: colorize env
# xeditor: colorize md
# xeditor: colorize yaml
# xeditor: colorize yaml
# xeditor: colorize json

# replace inner variables format











# main
@command("Create xvault db", examples=[
    "xvault create dev",
    "xvault create dev --force"
])
def store_create(
        dbname: Annotated[str,  Argument("NAME")],
        force: Annotated[bool,  Flag('f', "force")] = False
    ):
    # validation
    if XVaultStore.exists_db(dbname):
        if not force:
            confirm = input(f"Secrets db '{dbname}' already exists. Do you want to overwrite it? [y/n] ")
            if confirm.strip().lower() not in ("y", "yes"):
                error("Aborting creation.")
                return -1
        XVaultStore.delete_db(dbname)
    # ask for password 
    password = ask_password(confirm=True) 
    # create instance (will create empty store if not exists)
    xvault = XVaultStore(dbname, password = password, create = True)    
    # print
    info = xvault.info()
    print(f"Store created: {dbname}")
    print(f"Path: {xvault.getPath()}")
    print(f"Status: {'locked' if xvault.is_locked() else 'unlocked'}")


@command("List secrets dbs", alias=["store","list"], examples=[
    "xvault list",
    "xvault list dev"
])
def store_listcmd(
    dbname: Annotated[str,  Argument("NAME")] = None
    ):
    if dbname:
        if XVaultStore.exists_db(dbname):
            xvault = XVaultStore(dbname)
            keys = xvault.keys()
            width = max(len(key) for key in keys) if keys else 0
            for key in keys:
                entry = xvault.get(key)
                print(f"{key:<{width}}   {entry.type}")
        else:
            error(f"Secrets db '{dbname}' not found.")
    else:
        db_names = XVaultStore.get_db_names()
        width = max(len(db_name) for db_name in db_names) if db_names else 0
        for db_name in db_names:
            
            xvault = XVaultStore(db_name)
            keys_count = len(xvault.keys())
            locked = xvault.is_locked()
            print(f"{db_name:<{width}}   {keys_count} {'key ' if keys_count == 1 else 'keys'}  {'locked' if locked else 'unlocked'}")


@command("Edit secrets dbs", examples=[
    "xvault edit",
    "xvault edit dev"
])
def store_edit(
        dbname: Annotated[str,  Argument("NAME")],
        key: Annotated[str,  Argument("KEY")] = ""
    ):
    if not XVaultStore.exists_db(dbname):
        error(f"Secrets db '{dbname}' not found.")
        return -1
    # ask for password if interactive and not provided
    password = None
    if XVaultStore.is_locked_db(dbname):
        password = ask_password()
    # create instance
    secrets = XVaultStore(dbname, password = password)
    # action
    if key:
        secrets.edit_secret(key)
    else:
        secrets.edit()


@command("Get secret value from db", examples=[
    "xvault get dev mysecret"
])
def store_get(
        dbname: Annotated[str,  Argument("NAME")],
        key: Annotated[str,  Argument("KEY")]
    ):
    if not XVaultStore.exists_db(dbname):
        error(f"Secrets db '{dbname}' not found.")
        return -1
    # ask for password if interactive and not provided
    password = None
    if XVaultStore.is_locked_db(dbname):
        password = ask_password()
    # create instance
    xvault = XVaultStore(dbname, password = password)
    # action
    if xvault.exists(key):
        value = xvault.getValue(key)
        if value == None:
            error(f"Secret '{key}' not found.") 
            return -1
        else:
            print(value)
    else:
        error(f"Secret '{key}' not found.") 
        return -1


@command("Set secret value from db", examples=[
    "xvault set dev mysecret",
    "xvault set dev mysecret myvalue",
    "xvault set dev mysecret myvalue --description 'My secret' --services api1,backend1 --type password --force",
    "xvault set dev mysecret --generate --length 64",
    "xvault set dev mysecret {\"username\": \"user1\", \"password\": \"pass123\"} --type object",
    "echo myvalue | xvault set dev mysecret"
])
def store_set(
        dbname: Annotated[str,  Argument("NAME")],
        key: Annotated[str,  Argument("KEY")],
        value: Annotated[str,  Argument("VALUE")] = None,
        type_name: Annotated[str,  Flag('t', "type", alias="type")] = "",
        services: Annotated[str,  Flag('s', "services")] = "",
        description: Annotated[str,  Flag('d', "description")] = "",
        meta: Annotated[dict,  Flag('m', "meta")] = {},
        generate: Annotated[bool,  Flag('g', "generate")] = False,
        length: Annotated[int,  Flag('l', "length")] = 32,
        force: Annotated[bool,  Flag('f', "force")] = False
    ):
    # validation
    if not XVaultStore.exists_db(dbname):
        error(f"Secrets db '{dbname}' not found.")
        return -1
    if value and generate:        
        error("Cannot specify both value and generate.")
        return -1
    # check interactive
    interactive = sys.stdin.isatty() and value is None
    # generate value if requested
    if value is None and generate:        
        value = secrets_module.token_urlsafe(length)
    # if value is not provided, read from stdin or ask interactively
    if value is None:
        if sys.stdin.isatty():
            value1 = read_password(f"Enter secret value:   ", mask="*")
            value2 = read_password(f"Confirm secret value: ", mask="*")
            if value1 != value2:
                error("Aborting update: values do not match.")
                return -1
            value = value1
        else:
            value = sys.stdin.read()            
        value = value.rstrip("\n")
        if value == "":
            error("Aborting update: empty value.")
            return -1
    # ask for password if interactive and not provided
    password = None
    if XVaultStore.is_locked_db(dbname):
        password = ask_password()
    # init store
    secrets = XVaultStore(dbname, password = password)
    # check if exists, will raise if not
    exists = secrets.exists(key)
    if exists and not force:
        if not interactive:
            error(f"Secret '{key}' already exists. Use --force to overwrite it.")
            return -1
        confirm = input(f"Secret '{key}' already exists. Do you want to overwrite it? [y/n] ")
        if confirm.strip().lower() not in ("y", "yes"):
            error("Aborting update.")
            return -1
    # set    
    secrets.set(key, 
                value, 
                type = type_name, 
                services = [s.strip() for s in services.split(",") if s.strip()] if services else [], 
                meta=meta,
                description = description)
    # log
    if exists:
        print(f"{key} updated")
    else:
        print(f"{key} created")


@command("Remove secret value from db", examples=[
    "xvault remove dev mysecret",
    "xvault remove dev mysecret --force"
])
def store_remove(
        dbname: Annotated[str,  Argument("NAME")],
        key: Annotated[str,  Argument("KEY")],  
        force: Annotated[bool,  Flag('f', "force")] = False
    ):
    if not XVaultStore.exists_db(dbname):
        error(f"Secrets db '{dbname}' not found.")
        return -1
    # ask for password if interactive and not provided
    password = None
    if XVaultStore.is_locked_db(dbname):
        password = ask_password()
    # create instance
    secrets = XVaultStore(dbname)
    # validate
    if not secrets.exists(key):
        error(f"Secret '{key}' not found.")
        return -1
    if not force:
        confirm = input(f"Are you sure you want to remove the secret '{key}'? [y/n] ")
        if confirm.strip().lower() not in ("y", "yes"):
            error("Aborting deletion.")
            return -1
    # action
    secrets.remove(key)
    # log
    print(f"{key} removed")


@command("Delete secrets db", examples=[
    "xvault delete dev",
    "xvault delete dev --force"
])
def store_delete(
        dbname: Annotated[str,  Argument("NAME")],
        force: Annotated[bool,  Flag('f', "force")] = False
    ):
    if not XVaultStore.exists_db(dbname):
        error(f"Secrets db '{dbname}' not found.")
        return -1
    # create instance 
    xvault = XVaultStore(dbname)
    # confirm
    if not force:
        confirm = input(f"Are you sure you want to delete the secrets db '{dbname}'? [y/n] ")
        if confirm.strip().lower() not in ("y", "yes"):
            error("Aborting deletion.")
            return -1
    # action
    xvault.delete()
    # log
    print(f"Secrets db '{dbname}' deleted.")


@command("Unlock secrets db", examples=[
    "xvault unlock dev"
])
def store_unlock(
        dbname: Annotated[str,  Argument("NAME")]
    ):
    # validation
    if not XVaultStore.exists_db(dbname):
        error(f"Secrets db '{dbname}' not found.")
        return -1
    if not XVaultStore.is_locked_db(dbname):
        error(f"Secrets db '{dbname}' is not locked.")
        return -1
    # ask for password if interactive and not provided
    password = ask_password()
    # create instance 
    xvault = XVaultStore(dbname, password = password)
    # action
    xvault.unlock()
    # log
    print(f"Secrets db '{dbname}' unlocked.")


@command("Lock secrets db", examples=[
    "xvault lock dev"
])
def store_lock(
        dbname: Annotated[str,  Argument("NAME")]
    ):
    # validation
    if not XVaultStore.exists_db(dbname):
        error(f"Secrets db '{dbname}' not found.")
        return -1
    if XVaultStore.is_locked_db(dbname):
        error(f"Secrets db '{dbname}' is already locked.")
        return -1    
    # create instance 
    xvault = XVaultStore(dbname)
    # action
    xvault.lock()
    # log
    print(f"Secrets db '{dbname}' locked.")


@command("Show secrets db info", examples=[
    "xvault info dev"
])
def store_info(
        dbname: Annotated[str,  Argument("NAME")]
    ):
    if not XVaultStore.exists_db(dbname):
        error(f"Secrets db '{dbname}' not found.")
        return -1
    # create instance 
    xvault = XVaultStore(dbname)
    # action
    info = xvault.info()
    # print
    width = max(len(k) for k in info.keys())
    print(f"Secrets db info:")
    print("-" * (width + 2))
    for k, v in info.items():
        print(f"{k:<{width}} : {v}")


@command("Export secrets", examples=[
    "xvault export dev",
    "xvault export dev --format env",
    "xvault export dev --format json",
    "xvault export dev --format xvault"
])
def store_export(
        dbname: Annotated[str,  Argument("NAME")],
        format: Annotated[str,  Flag(' ', "format")] = "env"
    ):
    if not XVaultStore.exists_db(dbname):
        error(f"Secrets db '{dbname}' not found.")
        return -1
    # ask for password if interactive and not provided
    password = None
    if XVaultStore.is_locked_db(dbname):
        password = ask_password()
    # create instance
    xvault = XVaultStore(dbname, password = password)
    # action
    if format == "json":
        # .json
        dictionary = {}
        for key in xvault.keys():
            dictionary[key] = xvault.getValue(key)
        print(json.dumps(dictionary, indent=2))
    elif format == "env":
        # .env
        for key in xvault.keys():
            value = xvault.getValue(key)
            if isinstance(value, dict) or isinstance(value, list):
                value = json.dumps(value)
            print(format_env_line(key, value))
    elif format == "xvault":
        # .xvault (internal format)
        print(xvault.to_json())
    else:
        error(f"Unsupported export format '{format}'. Supported formats are: json, env, xvault.")
        return -1


@command("Import secrets into db", alias=["store","import"], examples=[
    "xvault import dev ./secrets-key-value.json",
    "xvault import dev ./secrets-key-value.env --force"
])
def store_imports(
        dbname: Annotated[str,  Argument("NAME")],
        filename: Annotated[str,  Argument("FILE")],
        force: Annotated[bool, Flag('f', "force")] = False,
        format: Annotated[str,  Flag(' ', "format")] = "auto",
        verbose: Annotated[bool, Flag('v', "verbose")] = False,

    ):
    # validation
    if not XVaultStore.exists_db(dbname):
        error(f"Secrets db '{dbname}' not found.")
        return -1
    # ask for password if interactive and not provided
    password = None
    if XVaultStore.is_locked_db(dbname):
        password = ask_password()
    # create instance
    xvault = XVaultStore(dbname, password = password)
    # auto detect format based on file extension
    if format == "auto":
        if filename.endswith(".json"):
            format = "json"
        elif filename.endswith(".env"):
            format = "env"
        elif filename.endswith(".xvault"):
            format = "xvault"
        else:
            error(f"Cannot auto detect format from file extension. Please specify the format using --format flag.")
            return -1
    # action
    new_count = 0
    updated_count = 0
    skipped_count = 0
    untouched_count = 0
    if format == "json":
        # .json
        with open(filename, "r") as f:
            dict = json.load(f) 
            print(f"Importing {len(dict)} secrets into '{dbname}' ...")
            if verbose:
                print()
            for key, value in dict.items():
                if xvault.exists(key):
                    if not force:
                        if verbose:
                            print(f"! {key} (exists, skipping)")
                        skipped_count += 1
                        continue
                    current_value = xvault.getValue(key)
                    if current_value == value:
                        if verbose:
                            print(f"= {key}")
                        untouched_count += 1
                    else:
                        if verbose:
                            print(f"~ {key}")
                        xvault.set(key, value)
                        updated_count += 1
                else:
                    if verbose:
                        print(f"+ {key}.")
                    xvault.set(key, value)
                    new_count += 1
    elif format == "env":
        # .env
        dict = dotenv_values(filename)
        print(f"Importing {len(dict)} secrets into '{dbname}' ...")
        if verbose:
            print()
        for key, value in dict.items():
            if xvault.exists(key):
                if not force:
                    if verbose:
                        print(f"! {key} (exists, skipping)")
                    skipped_count += 1
                    continue
                current_value = xvault.getValue(key)
                if current_value == value:
                    if verbose:
                        print(f"= {key}")
                    untouched_count += 1
                else:
                    if verbose:
                        print(f"~ {key}")
                    xvault.set(key, value)
                    updated_count += 1
            else:
                if verbose:
                    print(f"+ {key}.")
                xvault.set(key, value)
                new_count += 1
    elif format == "xvault":
        # .xvault (internal format)
        with open(filename, "r") as f:
            text = f.read()
            tmp = XVaultStore.from_json(text)
            print(f"Importing {len(tmp.secrets.items())} secrets into '{dbname}' ...")
            if verbose:
                print()
            for key, entry in tmp.secrets.items():
                tmp_value = tmp.getValue(key)
                if xvault.exists(key):
                    if not force:
                        if verbose:
                            print(f"! {key} (exists, skipping)")
                        skipped_count += 1
                        continue
                    current_value = xvault.getValue(key)
                    if current_value == entry.value:
                        if verbose:
                            print(f"= {key}")
                        untouched_count += 1
                    else:
                        if verbose:
                            print(f"~ {key}")
                        xvault.set(key, tmp_value, type = entry.type, services = entry.services, meta = entry.meta, description = entry.description)
                        updated_count += 1
                else:
                    if verbose:
                        print(f"+ {key}.")
                    xvault.set(key, tmp_value, type = entry.type, services = entry.services, meta = entry.meta, description = entry.description)
                    new_count += 1
    if verbose:
        print()
    print(f"Done. {new_count} new, {updated_count} updated, {untouched_count} untouched, {skipped_count} skipped..")




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



