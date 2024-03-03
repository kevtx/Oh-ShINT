import customtkinter
from loguru import logger

# from OhShINT.CLI import md_one


class InputFrame(customtkinter.CTkFrame):
    def __init__(self, master, **kwargs):
        super().__init__(master, **kwargs)

        # IOC Entry
        self.IOC_Entry = customtkinter.CTkEntry(
            self, placeholder_text="Enter your IOC here..."
        )
        self.IOC_Entry.grid(row=1, column=1, padx=20, pady=20, sticky="nsew")

        # Set from clipboard button
        self.btn_setFromClipboard = customtkinter.CTkButton(
            self, text="Paste from clipboard", command=self.setFromClipboard_button
        )
        self.btn_setFromClipboard.grid(row=2, column=1, padx=20, pady=0, sticky="nsew")

    def setInputBoxContent(self, content: str) -> None:
        if self.IOC_Entry.get() != "":
            self.IOC_Entry.delete(0, "end")
        self.IOC_Entry.insert(0, content)

    def setFromClipboard_button(self) -> str:
        clipboard = self.clipboard_get()
        clipboard.strip(r"\n, ")

        self.setInputBoxContent(clipboard)


class CheckboxFrame(customtkinter.CTkFrame):
    global osint_toggles
    osint_toggles = []

    def __init__(self, master, **kwargs):
        super().__init__(master, **kwargs)

        self.label = customtkinter.CTkLabel(self, text="OSINT")
        self.label.grid(row=1, column=1, padx=20, pady=0, sticky="nw")

        # Toggles --
        #   VirusTotal
        self.toggle_VirusTotal = customtkinter.CTkCheckBox(self, text="VirusTotal")
        self.toggle_VirusTotal.grid(
            row=2, column=1, padx=20, pady=(0, 20), sticky="new"
        )
        osint_toggles.append(self.toggle_VirusTotal)

        #   AlienVaultOTX
        self.toggle_AlienVault = customtkinter.CTkCheckBox(self, text="AlienVaultOTX")
        self.toggle_AlienVault.grid(
            row=3, column=1, padx=20, pady=(0, 20), sticky="new"
        )
        osint_toggles.append(self.toggle_AlienVault)

        #   AbuseIPDB
        self.toggle_AbuseIPDB = customtkinter.CTkCheckBox(self, text="AbuseIPDB")
        self.toggle_AbuseIPDB.grid(row=4, column=1, padx=20, pady=(0, 20), sticky="new")
        osint_toggles.append(self.toggle_AbuseIPDB)


class OutputFrame(customtkinter.CTkFrame):
    def __init__(self, master, **kwargs):
        super().__init__(master, **kwargs)

        self.label = customtkinter.CTkLabel(self, text="Markdown")
        self.label.grid(row=1, column=1, padx=20, pady=0, sticky="w")

        self.textbox = customtkinter.CTkTextbox(
            master=self, width=400, corner_radius=0, state="disabled"
        )
        self.textbox.grid(row=1, column=1, padx=20, pady=20, sticky="nsew")

        # Copy to clipboard button
        self.button_copyToClipboard = customtkinter.CTkButton(
            self, text="Copy to clipboard", command=self.setClipboard_button
        )
        self.button_copyToClipboard.grid(row=2, column=1, padx=20, pady=20, sticky="sw")

        self.btn_Submit = customtkinter.CTkButton(
            self, text="Submit", command=self.search_and_update
        )
        self.btn_Submit.grid(row=2, column=1, padx=20, pady=20, sticky="se")

    def update_text(self, text: str) -> None:
        self.textbox.delete("0.0", "end")
        self.textbox.insert("0.0", f"{text}\n")

    def search_and_update(self) -> None:
        if (
            not self.master.chkFrame.toggle_VirusTotal.get()
            and not self.master.chkFrame.toggle_AlienVault.get()
            and not self.master.chkFrame.toggle_AbuseIPDB.get()
        ):
            msg = "No toggles are on!"
            logger.error(msg)
            return None

        for toggle in osint_toggles:
            if toggle.get():
                logger.debug(f"{toggle.cget('text')} toggle is on")

        # r = md_one(self.master.inputFrame.IOC_Entry.get(), set_clipboard=False)
        r = "Test! Dummy text."
        self.update_text(r)

    def setClipboard_button(self) -> None:
        try:
            clipboard_content = self.master.inputFrame.IOC_Entry.get()
            if clipboard_content == "":
                logger.error("Clipboard is empty!")
                return None
            clipboard_content.strip(r", ")
            self.clipboard_clear()
            self.clipboard_append(clipboard_content)
            self.update()
            logger.info("Copied to clipboard!")
        except Exception as e:
            logger.error(e)
            raise e


class AssistantGUI(customtkinter.CTk):
    def __init__(self):
        super().__init__()

        self.title("OSINT Assistant")
        self.geometry("725x360")
        self.grid_rowconfigure((1, 2), weight=1)
        self.grid_columnconfigure((1, 2), weight=1)

        self.inputFrame = InputFrame(master=self, border_width=1, border_color="gray")
        self.inputFrame.grid(row=1, column=1, padx=20, pady=20, sticky="nsew")

        self.chkFrame = CheckboxFrame(master=self, border_width=1, border_color="gray")
        self.chkFrame.grid(row=2, column=1, padx=20, pady=20, sticky="nsew")

        self.outFrame = OutputFrame(master=self, border_width=1, border_color="gray")
        self.outFrame.grid(row=1, column=2, padx=20, pady=20, sticky="nsew", rowspan=2)


def start():
    gui = AssistantGUI()
    gui.mainloop()
