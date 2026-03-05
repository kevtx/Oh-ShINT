from __future__ import annotations

import json
import queue
from dataclasses import dataclass
from pathlib import Path
from threading import Thread
from tkinter import BooleanVar, StringVar, Tk
from tkinter import messagebox
from tkinter import ttk
from tkinter.scrolledtext import ScrolledText
from typing import Any, Type

from dotenv import dotenv_values, set_key, unset_key

from .Providers import AbuseIPDB, AlienVault, VirusTotal
from .history import History
from .models.ioc import IOC

WINDOW_TITLE = "Oh-ShINT"
RESULTS_COLUMNS = ("provider", "status", "summary")
PROVIDER_CLASSES: list[Type[Any]] = [AbuseIPDB, AlienVault, VirusTotal]


@dataclass(slots=True)
class ProviderSettings:
	enabled: BooleanVar
	token: StringVar


class OhShintGUI(Tk):
	def __init__(self) -> None:
		super().__init__()
		self.title(WINDOW_TITLE)
		self.geometry("1100x700")
		self.minsize(900, 600)

		self.env_path = Path(__file__).resolve().parent.parent / ".env"
		self.result_payloads: dict[str, str] = {}
		self.search_queue: queue.Queue[tuple[str, str, str, str]] = queue.Queue()
		self.search_in_progress = False
		self.provider_settings: dict[str, ProviderSettings] = {}

		self._load_settings()
		self._build_ui()

	def _load_settings(self) -> None:
		env_values = dotenv_values(self.env_path) if self.env_path.exists() else {}
		for provider_cls in PROVIDER_CLASSES:
			provider_name = provider_cls.human_name
			base_name = provider_cls.__name__.upper()

			token = (
				env_values.get(f"{base_name}_API_KEY")
				or env_values.get(base_name)
				or ""
			)
			enabled_raw = env_values.get(f"ENABLE_{base_name}", "1")
			enabled = str(enabled_raw).strip().lower() not in {"0", "false", "no"}

			self.provider_settings[provider_name] = ProviderSettings(
				enabled=BooleanVar(value=enabled),
				token=StringVar(value=token),
			)

	def _build_ui(self) -> None:
		self.columnconfigure(0, weight=1)
		self.rowconfigure(0, weight=1)

		self.tabs = ttk.Notebook(self)
		self.tabs.grid(row=0, column=0, sticky="nsew", padx=12, pady=12)

		self.search_tab = ttk.Frame(self.tabs, padding=10)
		self.settings_tab = ttk.Frame(self.tabs, padding=10)
		self.tabs.add(self.search_tab, text="Search")
		self.tabs.add(self.settings_tab, text="Settings")

		self._build_search_tab()
		self._build_settings_tab()

	def _build_search_tab(self) -> None:
		self.search_tab.columnconfigure(0, weight=1)
		self.search_tab.rowconfigure(1, weight=1)
		self.search_tab.rowconfigure(2, weight=1)

		input_row = ttk.Frame(self.search_tab)
		input_row.grid(row=0, column=0, sticky="ew", pady=(0, 10))
		input_row.columnconfigure(1, weight=1)

		ttk.Label(input_row, text="Indicator").grid(row=0, column=0, sticky="w")
		self.search_var = StringVar()
		self.search_entry = ttk.Entry(input_row, textvariable=self.search_var)
		self.search_entry.grid(row=0, column=1, sticky="ew", padx=8)
		self.search_entry.bind("<Return>", lambda _: self.submit_search())

		self.search_button = ttk.Button(input_row, text="Search", command=self.submit_search)
		self.search_button.grid(row=0, column=2, sticky="e")

		self.results_table = ttk.Treeview(
			self.search_tab,
			columns=RESULTS_COLUMNS,
			show="headings",
			height=12,
		)
		self.results_table.heading("provider", text="Provider")
		self.results_table.heading("status", text="Status")
		self.results_table.heading("summary", text="Summary")
		self.results_table.column("provider", width=180, anchor="w")
		self.results_table.column("status", width=110, anchor="center")
		self.results_table.column("summary", width=700, anchor="w")
		self.results_table.grid(row=1, column=0, sticky="nsew")

		table_scroll = ttk.Scrollbar(
			self.search_tab,
			orient="vertical",
			command=self.results_table.yview,
		)
		table_scroll.grid(row=1, column=1, sticky="ns")
		self.results_table.configure(yscrollcommand=table_scroll.set)
		self.results_table.bind("<<TreeviewSelect>>", self._on_result_selected)

		details_frame = ttk.LabelFrame(self.search_tab, text="Result Details")
		details_frame.grid(row=2, column=0, columnspan=2, sticky="nsew", pady=(10, 0))
		details_frame.columnconfigure(0, weight=1)
		details_frame.rowconfigure(0, weight=1)

		self.details_text = ScrolledText(details_frame, wrap="word", height=16)
		self.details_text.grid(row=0, column=0, sticky="nsew")
		self.details_text.configure(state="disabled")

		self.status_var = StringVar(value="Ready")
		ttk.Label(self.search_tab, textvariable=self.status_var).grid(
			row=3, column=0, sticky="w", pady=(8, 0)
		)

	def _build_settings_tab(self) -> None:
		self.settings_tab.columnconfigure(0, weight=1)

		ttk.Label(
			self.settings_tab,
			text="Configure provider API keys and enable/disable providers for searches.",
		).grid(row=0, column=0, sticky="w", pady=(0, 10))

		self.show_keys_var = BooleanVar(value=False)
		ttk.Checkbutton(
			self.settings_tab,
			text="Show API keys",
			variable=self.show_keys_var,
			command=self._refresh_key_visibility,
		).grid(row=1, column=0, sticky="w", pady=(0, 10))

		self.settings_rows: dict[str, ttk.Entry] = {}
		settings_grid = ttk.Frame(self.settings_tab)
		settings_grid.grid(row=2, column=0, sticky="ew")
		settings_grid.columnconfigure(2, weight=1)

		ttk.Label(settings_grid, text="Provider", width=24).grid(row=0, column=0, sticky="w")
		ttk.Label(settings_grid, text="Enabled", width=12).grid(row=0, column=1, sticky="w")
		ttk.Label(settings_grid, text="API Key").grid(row=0, column=2, sticky="w")

		for row_index, provider_cls in enumerate(PROVIDER_CLASSES, start=1):
			provider_name = provider_cls.human_name
			provider_state = self.provider_settings[provider_name]

			ttk.Label(settings_grid, text=provider_name).grid(
				row=row_index,
				column=0,
				sticky="w",
				pady=4,
			)

			ttk.Checkbutton(settings_grid, variable=provider_state.enabled).grid(
				row=row_index,
				column=1,
				sticky="w",
				pady=4,
			)

			key_entry = ttk.Entry(
				settings_grid,
				textvariable=provider_state.token,
				show="*",
				width=80,
			)
			key_entry.grid(row=row_index, column=2, sticky="ew", pady=4)
			self.settings_rows[provider_name] = key_entry

		actions = ttk.Frame(self.settings_tab)
		actions.grid(row=3, column=0, sticky="ew", pady=(14, 0))
		actions.columnconfigure(0, weight=1)

		ttk.Button(actions, text="Save Settings", command=self.save_settings).grid(
			row=0,
			column=1,
			sticky="e",
		)

	def _refresh_key_visibility(self) -> None:
		show_keys = self.show_keys_var.get()
		for entry in self.settings_rows.values():
			entry.configure(show="" if show_keys else "*")

	def save_settings(self) -> None:
		self.env_path.touch(exist_ok=True)
		for provider_cls in PROVIDER_CLASSES:
			provider_name = provider_cls.human_name
			provider_state = self.provider_settings[provider_name]
			base_name = provider_cls.__name__.upper()

			token_key = f"{base_name}_API_KEY"
			token = provider_state.token.get().strip()
			if token:
				set_key(str(self.env_path), token_key, token)
			else:
				unset_key(str(self.env_path), token_key)
				unset_key(str(self.env_path), base_name)

			enabled_key = f"ENABLE_{base_name}"
			set_key(
				str(self.env_path),
				enabled_key,
				"1" if provider_state.enabled.get() else "0",
			)

		self.status_var.set("Settings saved")
		messagebox.showinfo("Saved", f"Settings saved to {self.env_path}")

	def submit_search(self) -> None:
		if self.search_in_progress:
			return

		ioc_value = self.search_var.get().strip()
		if not ioc_value:
			messagebox.showwarning("Input required", "Please enter an indicator to search")
			return

		try:
			ioc = IOC(ioc_value)
		except ValueError as exc:
			messagebox.showerror("Invalid indicator", str(exc))
			return

		enabled_providers = [
			(
				provider_cls,
				self.provider_settings[provider_cls.human_name].token.get().strip() or None,
			)
			for provider_cls in PROVIDER_CLASSES
			if self.provider_settings[provider_cls.human_name].enabled.get()
		]
		if not enabled_providers:
			messagebox.showwarning("No providers enabled", "Enable at least one provider in Settings")
			self.tabs.select(self.settings_tab)
			return

		self._clear_results()
		self.status_var.set(
			f"Searching {len(enabled_providers)} provider(s) for {ioc.cn}: {ioc.value}"
		)
		self.search_button.configure(state="disabled")
		self.search_in_progress = True

		worker = Thread(
			target=self._run_search,
			args=(ioc.value, enabled_providers),
			daemon=True,
		)
		worker.start()
		self.after(100, self._poll_search_queue)

	def _run_search(self, ioc_value: str, provider_configs: list[tuple[Type[Any], str | None]]) -> None:
		for provider_cls, token in provider_configs:
			provider_name = provider_cls.human_name
			provider = None

			try:
				provider = provider_cls(token=token)
				result = provider.search(ioc_value, history=History(create=True))
				payload = json.dumps(result, indent=2, default=str)
				summary = self._summarize(result)
				self.search_queue.put((provider_name, "success", summary, payload))
			except Exception as exc:
				error_payload = json.dumps({"error": str(exc)}, indent=2)
				self.search_queue.put((provider_name, "error", str(exc), error_payload))
			finally:
				try:
					provider.close()
				except Exception:
					pass

		self.search_queue.put(("__done__", "done", "", ""))

	def _poll_search_queue(self) -> None:
		while not self.search_queue.empty():
			provider_name, status, summary, payload = self.search_queue.get_nowait()
			if provider_name == "__done__":
				self.search_in_progress = False
				self.search_button.configure(state="normal")
				self.status_var.set("Search complete")
				return

			row_id = self.results_table.insert(
				"",
				"end",
				values=(provider_name, status.upper(), summary),
			)
			self.result_payloads[row_id] = payload

		if self.search_in_progress:
			self.after(120, self._poll_search_queue)

	def _on_result_selected(self, _event: object) -> None:
		selected = self.results_table.selection()
		if not selected:
			return
		payload = self.result_payloads.get(selected[0], "")
		self.details_text.configure(state="normal")
		self.details_text.delete("1.0", "end")
		self.details_text.insert("1.0", payload)
		self.details_text.configure(state="disabled")

	def _clear_results(self) -> None:
		for row in self.results_table.get_children():
			self.results_table.delete(row)
		self.result_payloads.clear()
		self.details_text.configure(state="normal")
		self.details_text.delete("1.0", "end")
		self.details_text.configure(state="disabled")

	@staticmethod
	def _summarize(result: Any) -> str:
		if isinstance(result, dict):
			if "data" in result and isinstance(result["data"], dict):
				data = result["data"]
				confidence = data.get("abuseConfidenceScore")
				country = data.get("countryCode")
				total_reports = data.get("totalReports")
				details = []
				if confidence is not None:
					details.append(f"confidence={confidence}")
				if country:
					details.append(f"country={country}")
				if total_reports is not None:
					details.append(f"reports={total_reports}")
				if details:
					return ", ".join(details)
			keys = list(result.keys())
			return f"dict with keys: {', '.join(keys[:6])}"

		if isinstance(result, list):
			return f"list with {len(result)} item(s)"

		return str(result)[:120]


def launch_gui() -> None:
	app = OhShintGUI()
	app.mainloop()
