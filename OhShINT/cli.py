# import typer
# from rich.console import Console
# from rich.progress import Progress, SpinnerColumn, TextColumn
# from rich.table import Table
# from typing_extensions import Annotated
#
# from . import APP_STATE, PROVIDERS
# from .models.ioc import IOC
#
# CLI = typer.Typer()
# console = Console()
#
#
# @CLI.command("search", help="Search OSINT providers for a single IOC")
# def search(
#    ioc_value: Annotated[str, typer.Argument(..., help="The IOC to search for")],
# ):
#
# results = []
#
# with Progress(
# SpinnerColumn(),
#        TextColumn("[progress.description]{task.description}"),
# transient=True,
# ) as progress:
# ioc = IOC(ioc_value)
#
#        description = f"Searching for [italic]{ioc.__class__.__name__}[/]: "
# description += f"[bold red]{ioc.value}[/]"
#        progress.add_task(description=description, total=None)
#
# for provider in PROVIDERS.values():
#            results.append((provider.human_name, ioc.cn, ioc, "None"))
#
# if APP_STATE.get("pretty"):
# table = Table("IOC", "Type", "Results")
# for provider, ioc_typ, ioc, result in results:
#            table.add_row(provider, ioc.value, ioc_typ, result)
# console.print(table)
# else:
# for provider, ioc_typ, ioc, result in results:
#            console.print(f"{provider:<20}\t{ioc.value:<32}\t{ioc_typ:<10}\t{result}")
