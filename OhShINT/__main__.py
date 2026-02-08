# import sys
#
# import typer
# from loguru import logger
# from rich.console import Console
# from typing_extensions import Annotated
#
# from .cli import app as cli
# from .gui import app as gui
#
# logger.remove()
#
# console = Console()
#
#
# Oh = typer.Typer()
#
# Oh.add_typer(cli, help=f"Command-line interface for {__name__}")
# Oh.add_typer(gui, help=f"Basic GUI interface for {__name__}")
#
#
# @Oh.callback()
# def main(
#    verbose: Annotated[
# bool, typer.Option("--verbose", "-v", help="Enable verbose output")
#    ] = False,
#    quiet: Annotated[
#        bool,
# typer.Option("--quiet", "-q", help="Enable quiet mode (suppress all logging)"),
#    ] = False,
#    pretty: Annotated[
#        bool,
#        typer.Option(
# "--pretty", "-p", help="Enable pretty output (overridden by quiet mode)"
#        ),
#    ] = False,
# ):
# """Main callback for the CLI, sets up global state based on shared options."""
#    if verbose and quiet:
# console.print("Cannot use both verbose and quiet modes at the same time.")
#        raise typer.Exit(code=1)
#
#    if verbose:
#        state["verbose"] = True
#
#    if quiet:
#        state["quiet"] = True
#
#    state["pretty"] = pretty and not quiet
#
#    if not state.get("quiet"):
# level = "DEBUG" if state.get("verbose") else "INFO"
# logger.configure(handlers=[{"sink": sys.stdout, "level": level}])
#        logger.debug("Logging enabled")
