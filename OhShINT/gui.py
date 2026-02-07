from tkinter import Tk, ttk

from loguru import logger

from .providers import get_all_providers

WINDOW_TITLE = "Oh-ShINT"
PROVIDERS = get_all_providers()


class GUI(Tk):
    search_frame: ttk.Frame
    search_label: ttk.Label
    search_entry: ttk.Entry
    search_submit: ttk.Button
    result_table: ttk.Treeview

    def __init__(self):
        super().__init__()

        self.title(WINDOW_TITLE)
        self.resizable(False, False)

        self.search_frame = ttk.Frame(self)
        self.search_frame.grid_columnconfigure((0, 2), weight=0)
        self.search_frame.grid_columnconfigure(1, weight=1)

        self.search_label = ttk.Label(self.search_frame, text="Indicator:")
        self.search_label.grid(row=0, column=0, sticky="w")

        self.search_entry = ttk.Entry(self.search_frame)
        self.search_entry.grid(row=0, column=1, sticky="ew")

        self.search_submit = ttk.Button(
            self.search_frame, text="Go", width=5, command=self.submit_search
        )
        self.search_submit.grid(row=0, column=2, sticky="e")

        self.search_frame.grid(row=0, column=0, sticky="ne", padx=10, pady=10)

        self.result_table = ttk.Treeview(
            self, columns=("provider", "results"), show="headings"
        )
        self.result_table.heading("provider", text="Provider")
        self.result_table.heading("results", text="Results")

        self.result_table.grid(
            row=1, column=0, sticky="nsew", columnspan=2, padx=10, pady=10
        )

    def submit_search(self) -> None:
        ioc = self.search_entry.get()
        if not ioc:
            logger.warning("No IOC provided")
            return
        logger.debug(f"Searching for {ioc}")
        self.clear_results()
        for provider in PROVIDERS.values():
            try:
                provider.search(ioc)
                self.result_table.insert(
                    "",
                    "end",
                    # values=(provider.human_name, osint.indicators),
                )
            except Exception as e:
                logger.error(f"{provider.human_name}: Error: {e}")

    def clear_results(self) -> None:
        for i in self.result_table.get_children():
            self.result_table.delete(i)

    def start(self):
        self.mainloop()


def start():
    gui = GUI()
    gui.start()


if __name__ == "__main__":
    start()
