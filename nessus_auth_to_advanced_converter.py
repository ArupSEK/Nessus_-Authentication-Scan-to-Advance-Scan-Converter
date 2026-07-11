#!/usr/bin/env python3
"""Fixed entry point for creating Advanced Scan copies.

This wrapper corrects the two confusing defaults in the original GUI:
1. Preview mode no longer silently prevents scan creation.
2. Advanced Scan is selected by default instead of Basic Network Scan.

The original authentication scan remains unchanged. The tool copies it first
and converts only the copied scan.
"""

from __future__ import annotations

import tkinter as tk
from tkinter import messagebox
from typing import List

import nessus_auth_to_va_converter as base


class AdvancedConverterApp(base.ConverterApp):
    def __init__(self) -> None:
        super().__init__()
        self.title("Nessus Authentication Scan to Advanced Scan Converter v1.1")

        # Actual creation mode is the default. Single-test mode still limits
        # the first run to one scan for safety.
        self.preview_var.set(False)
        self.single_test_var.set(True)
        self.delete_failed_var.set(False)
        self.suffix_var.set("_ADVANCED_VA")

        self.selected_btn.configure(text="CREATE Advanced Scan from Selected")
        self.all_btn.configure(text="CREATE Advanced Scans from All")
        self.status_var.set(
            "CREATE mode enabled. Single-test mode will process one scan first."
        )

    def _connect_complete(
        self,
        client: base.NessusClient,
        folders: List[base.Folder],
        templates: List[base.Template],
    ) -> None:
        super()._connect_complete(client, folders, templates)

        advanced_display = next(
            (
                display
                for display, template in self.template_map.items()
                if template.title.strip().lower() == "advanced scan"
            ),
            "",
        )
        if advanced_display:
            self.template_var.set(advanced_display)
            self.status_var.set(
                "Connected. Advanced Scan selected. Load the source scans."
            )
        else:
            messagebox.showwarning(
                base.APP_TITLE,
                "Advanced Scan template was not returned by Nessus. "
                "Check the API-key permissions and available templates.",
            )

    def start_conversion(self, scans: List[base.Scan]) -> None:
        template = self.template_map.get(self.template_var.get())
        if template is None:
            messagebox.showwarning(base.APP_TITLE, "Select the Advanced Scan template.")
            return

        if template.title.strip().lower() != "advanced scan":
            proceed = messagebox.askyesno(
                base.APP_TITLE,
                f"The selected template is '{template.title}', not 'Advanced Scan'.\n\n"
                "Continue anyway?",
            )
            if not proceed:
                return

        if self.preview_var.get():
            create_now = messagebox.askyesno(
                base.APP_TITLE,
                "Preview mode is enabled, so NO scan will be created.\n\n"
                "Disable Preview mode and create the Advanced Scan now?",
            )
            if not create_now:
                return
            self.preview_var.set(False)

        super().start_conversion(scans)


def main() -> None:
    AdvancedConverterApp().mainloop()


if __name__ == "__main__":
    main()
