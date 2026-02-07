import sys

import typer
from loguru import logger
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.table import Table
from typing_extensions import Annotated

from .models.ioc import IOC
from .providers import get_all_providers

logger.remove()

PROVIDERS = get_all_providers()

console = Console()
Oh = typer.Typer()


@Oh.command("gui", help="Launch the GUI")
def start_gui(
    logging: bool = typer.Option(False, "--logging", "-l", help="Enable logging"),
    verbose: bool = typer.Option(False, "--verbose", "-v", help="Verbose output"),
):
    from .gui import start

    if logging:
        if verbose:
            __level = "TRACE"
        else:
            __level = "INFO"
        logger.configure(handlers=[{"sink": sys.stdout, "level": __level}])
        logger.debug("Logging enabled")

    start()


@Oh.command("search", help="Search OSINT providers for a single IOC")
def search_one(
    ioc_value: Annotated[str, typer.Argument(..., help="The IOC to search for")],
    logging: bool = typer.Option(False, "--logging", "-l", help="Enable logging"),
    verbose: bool = typer.Option(False, "--verbose", "-v", help="Verbose output"),
    pretty: bool = typer.Option(False, "--pretty", "-p", help="Pretty print output"),
):
    if logging:
        if verbose:
            __level = "TRACE"
        else:
            __level = "INFO"
        logger.configure(handlers=[{"sink": sys.stdout, "level": __level}])
        logger.debug("Logging enabled")

    results = []

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        transient=True,
    ) as progress:
        ioc = IOC(ioc_value)

        description = f"Searching for [italic]{ioc.__class__.__name__}[/]: "
        description += f"[bold red]{ioc.value}[/]"
        progress.add_task(description=description, total=None)

        for name, provider in PROVIDERS.items():
            results.append((name, ioc, ioc.typ))

    if pretty:
        table = Table("IOC", "Type", "Results")
        for name, ioc, typ in results:
            table.add_row(ioc.value, typ, "None")
        console.print(table)
    else:
        for name, ioc, typ in results:
            console.print(f"{ioc.value:<40}\t{typ:<10}\tNone")


"""
@Oh.command("one", help="Extract IOCs from a string")
def ioc_one(
    ioc_value: Annotated[str, typer.Argument(..., help="The IOC to search for")],
    logging: bool = typer.Option(False, "--logging", "-l", help="Enable logging"),
    verbose: bool = typer.Option(False, "--verbose", "-v", help="Verbose output"),
    force_inline: bool = typer.Option(
        False, "--force-inline", "-Fi", help="Force inline comment"
    ),
    force_bulleted: bool = typer.Option(
        False, "--force-bulleted", "-Fb", help="Force bulleted comment"
    ),
    do_functional: bool = typer.Option(
        False,
        "--functional/--object-oriented",
        "-func/-oo",
        help="Functional or object-oriented implementation",
    ),
    do_print: bool = typer.Option(True, "--print/--quiet", "-p/-q"),
    set_clipboard: bool = typer.Option(
        False, "--set-clipboard", "-c", help="Set clipboard"
    ),
) -> MarkdownTemplate:
    logger.debug(f"Bulleted: {force_inline}, Inline: {force_bulleted}")

    # if force_inline and force_bulleted:
    # logger.error("Cannot use both ---force-inline and --force-bulleted")
    # raise ValueError("Cannot use both --inline and --bulleted")

    if logging:
        if verbose:
            __level = "TRACE"
        else:
            __level = "INFO"
        logger.configure(handlers=[{"sink": sys.stdout, "level": __level}])
        logger.debug("Logging enabled")

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        transient=True,
    ) as progress:
        ioc = string_to_ioc(ioc_value)

        description = f"Searching for [italic]{ioc.type}[/]: "
        description += f"[bold red]{ioc.value}[/]"
        progress.add_task(description=description, total=None)

        if force_inline:
            format = "inline"
        elif force_bulleted:
            format = "bulleted"
        else:
            format = "auto"

        md = default_templates[ioc.type].console.print(**ioc.get_enriched(), format=format)

        if set_clipboard:
            try:
                import pyperclip

                pyperclip.copy(md)
                logger.success("Copied to clipboard")
            except Exception as e:
                logger.error(f"Error: {e}")
                raise e

        if do_print:
            console.print(Markdown(md))
            console.print("")
        else:
            return md
"""

"""
@Oh.command("list", help="Extract IOCs from a ZTAP array", hidden=True)
def ioc_list(
    ioc_list: Annotated[str, typer.Argument(..., help="List of IOCs to search for")],
    logging: bool = typer.Option(False, "--logging", "-l", help="Enable logging"),
    verbose: bool = typer.Option(False, "--verbose", "-v", help="Verbose output"),
    do_print: bool = typer.Option(True, "--print/--quiet", "-p/-q", help="Print"),
    set_clipboard: bool = typer.Option(
        False, "--set-clipboard", "-c", help="Set clipboard"
    ),
) -> str:
    if logging:
        if verbose:
            __level = "TRACE"
        else:
            __level = "INFO"
        logger.configure(handlers=[{"sink": sys.stdout, "level": __level}])
        logger.debug("Logging enabled")

    ioc_list_stripped: str = ioc_list.strip('[] "')
    ioc_list_split: list = ioc_list_stripped.split(",")

    all_comments = ""

    for ioc_str in ioc_list_split:
        ioc_str = ioc_str.strip('" ')
        ioc_comment = ioc_one(
            ioc_str, logging=False, verbose=False, set_clipboard=False
        )
        if ioc_comment is not None:
            all_comments += ioc_comment

    if set_clipboard:
        try:
            import pyperclip

            pyperclip.copy(all_comments)
            logger.success("Copied to clipboard")
        except Exception as e:
            logger.error(f"Error: {e}")
            raise e

    if do_print:
        console.print(Markdown(all_comments))
    else:
        return all_comments
"""

"""
@Oh.command("file", help="Extract IOCs from a file", hidden=True)
def ioc_file(
    file: Annotated[
        Path,
        typer.Argument(
            ...,
            exists=True,
            file_okay=True,
            dir_okay=False,
            readable=True,
            writable=True,
            resolve_path=True,
            help="Path to extract IOCs from",
        ),
    ],
    logging: bool = typer.Option(False, "--logging", "-l", help="Enable logging"),
    verbose: bool = typer.Option(False, "--verbose", "-v", help="Verbose output"),
    do_print: bool = typer.Option(True, "--print/--quiet", "-p/-q", help="Print"),
    set_clipboard: bool = typer.Option(
        False, "--set-clipboard", "-c", help="Set clipboard"
    ),
    # validate_matches: bool = typer.Option(False, "--validate", "-V", help="Validate"),
) -> dict:
    if logging:
        if verbose:
            __level = "TRACE"
        else:
            __level = "INFO"
        logger.configure(handlers=[{"sink": sys.stdout, "level": __level}])
        logger.debug("Logging enabled")

    if not file.exists():
        msg = f"File not found: {file.absolute()}"

        console.print(msg)
        logger.error(msg)
        raise (FileNotFoundError(msg))

    matches: dict = {
        "ip": [],
        "domain": [],
        "sha256": [],
        "sha1": [],
    }

    with open(file, "r") as f:
        logger.debug(f"Reading file: {file.absolute()}")

        content = f.read()

        for i in ["ip", "domain", "sha256", "sha1"]:
            logger.debug(f"Searching: {i}")
            try:
                r_matches = ioc_regex_search(i, content)
                for m in r_matches:
                    logger.trace(f"Found match: {m}")
                    matches[i].append(m)
                    logger.trace("Added match to list")
            except Exception as e:
                logger.error(f"Error: {e}")

    #    if validate_matches:
    #        for ip in matches["ip"]:
    #            try:
    #                assert get_ioc_type(ip) == "IPv4"
    #                assert __is_ipv4(ip)
    #            except Exception as e:
    #                logger.error(f"Error: {e}")
    #                raise e
    #
    #        for domain in matches["domain"]:
    #            try:
    #                assert get_ioc_type(domain) == "Domain"
    #                assert __is_domain(domain)
    #            except Exception as e:
    #                logger.error(f"Error: {e}")
    #                raise e
    #
    #        for hash in matches["sha256"]:
    #            try:
    #                assert get_ioc_type(hash) == "SHA256"
    #                assert __is_sha256(hash)
    #            except Exception as e:
    #                logger.error(f"Error: {e}")
    #                raise e
    #
    #        for hash in matches["sha1"]:
    #            try:
    #                assert get_ioc_type(hash) == "SHA1"
    #                assert __is_sha1(hash)
    #            except Exception as e:
    #                logger.error(f"Error: {e}")
    #                raise e

    if do_print:
        console.print(matches)
    else:
        return matches
"""
