from __future__ import annotations

import json

import typer
from rich.console import Console
from rich.table import Table
from typing_extensions import Annotated

from .Providers import iter_load_providers
from .gui import launch_gui
from .history import History
from .models.ioc import IOC

console = Console()
Oh = typer.Typer(help="Oh-ShINT command-line interface")


@Oh.command("gui", help="Launch the graphical interface")
def gui() -> None:
	launch_gui()


@Oh.command("search", help="Search all configured providers for one IOC")
def search(
	ioc_value: Annotated[str, typer.Argument(..., help="Indicator to search")],
) -> None:
	ioc = IOC(ioc_value)

	table = Table("Provider", "IOC", "Type", "Status", "Summary")
	for provider in iter_load_providers():
		try:
			result = provider.search(ioc, history=History(create=True))
			summary = (
				f"keys={','.join(list(result.keys())[:4])}"
				if isinstance(result, dict)
				else str(result)[:80]
			)
			table.add_row(provider.human_name, ioc.value, ioc.cn, "OK", summary)
		except Exception as exc:
			table.add_row(provider.human_name, ioc.value, ioc.cn, "ERROR", str(exc))

	console.print(table)


@Oh.command("search-json", help="Search all configured providers and print JSON")
def search_json(
	ioc_value: Annotated[str, typer.Argument(..., help="Indicator to search")],
) -> None:
	ioc = IOC(ioc_value)
	payload: dict[str, object] = {}

	for provider in iter_load_providers():
		try:
			payload[provider.human_name] = provider.search(ioc, history=History(create=True))
		except Exception as exc:
			payload[provider.human_name] = {"error": str(exc)}

	console.print_json(json.dumps(payload, default=str))
