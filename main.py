"""
BurpLite — entry point.
Run:  python main.py
"""

import os
import sys
import traceback

# Add project root to path so `core` and `ui` resolve as packages
ROOT = os.path.dirname(os.path.abspath(__file__))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

if __name__ == "__main__":
    try:
        from ui.app import BurpLiteApp
        app = BurpLiteApp()
        app.run()
    except Exception:
        err = traceback.format_exc()
        # Try to show a tkinter error dialog; fall back to console
        try:
            import tkinter as tk
            from tkinter import messagebox
            root = tk.Tk()
            root.withdraw()
            messagebox.showerror("BurpLite Startup Error", err)
            root.destroy()
        except Exception:
            print(err)
        sys.exit(1)
