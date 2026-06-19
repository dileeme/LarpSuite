
import tkinter as tk 
from tkinter import ttk ,messagebox 

from core .ca import ca_cert_path ,install_ca_windows ,uninstall_ca_windows ,generate_root_ca 
from core .proxy import ProxyServer 
from ui .proxy_tab import ProxyTab 
from ui .repeater_tab import RepeaterTab 
from ui .intruder_tab import IntruderTab 
from ui .decoder_tab import DecoderTab 
from ui .scanner_tab import ScannerTab 
from ui .diagnostics_tab import DiagnosticsTab 
from ui .dashboard_tab import DashboardTab 
from ui .target_tab import TargetTab 
from ui .logger_tab import LoggerTab 
from ui .comparer_tab import ComparerTab 
from ui .sequencer_tab import SequencerTab 
from ui .organizer_tab import OrganizerTab 
from ui .settings_tab import SettingsTab 


DARK_BG ="#0D0E14"
DARK_FG ="#E8DCC8"
ACCENT ="#C8A951"


def _apply_dark_theme (root :tk .Tk ):
    style =ttk .Style (root )
    try :
        style .theme_use ("clam")
    except Exception :
        pass 

    style .configure (".",
    background =DARK_BG ,foreground =DARK_FG ,
    fieldbackground ="#1E1F2E",troughcolor ="#1E1F2E",
    bordercolor ="#2E2A1A",selectbackground ="#5A4A1E",
    )
    style .configure ("TNotebook",background =DARK_BG ,tabmargins =[2 ,2 ,0 ,0 ])
    style .configure ("TNotebook.Tab",background ="#1E1F2E",foreground =DARK_FG ,padding =[10 ,4 ])
    style .map ("TNotebook.Tab",
    background =[("selected",ACCENT )],
    foreground =[("selected","#ffffff")],
    )
    style .configure ("TFrame",background =DARK_BG )
    style .configure ("TLabelframe",background =DARK_BG ,foreground =DARK_FG )
    style .configure ("TLabelframe.Label",background =DARK_BG ,foreground =ACCENT )
    style .configure ("TButton",background ="#1E1F2E",foreground =DARK_FG )
    style .map ("TButton",background =[("active","#2E2A1A")])
    style .configure ("TEntry",fieldbackground ="#1E1F2E",foreground =DARK_FG )
    style .configure ("TCombobox",fieldbackground ="#1E1F2E",foreground =DARK_FG ,
    selectbackground ="#5A4A1E")
    style .configure ("TCheckbutton",background =DARK_BG ,foreground =DARK_FG )
    style .configure ("TLabel",background =DARK_BG ,foreground =DARK_FG )
    style .configure ("TScrollbar",background ="#1E1F2E",troughcolor ="#0D0E14")
    style .configure ("Treeview",
    background ="#0A0B10",foreground =DARK_FG ,
    fieldbackground ="#0A0B10",rowheight =20 ,
    )
    style .configure ("Treeview.Heading",background ="#1E1F2E",foreground =ACCENT )
    style .map ("Treeview",background =[("selected","#5A4A1E")])
    style .configure ("TSpinbox",fieldbackground ="#1E1F2E",foreground =DARK_FG )
    style .configure ("Horizontal.TProgressbar",troughcolor ="#1E1F2E",background =ACCENT )

    root .configure (bg =DARK_BG )
    root .option_add ("*Background",DARK_BG )
    root .option_add ("*Foreground",DARK_FG )
    root .option_add ("*Font","TkDefaultFont")


class LarpSuiteApp :
    def __init__ (self ):
        self .root =tk .Tk ()
        self .root .title ("Larp Suite — Web Penetration Testing Proxy")
        self .root .geometry ("1400x860")
        self .root .minsize (1000 ,650 )

        _apply_dark_theme (self .root )

        self ._proxy =ProxyServer (host ="127.0.0.1",port =8888 )
        self ._build ()
        self .root .protocol ("WM_DELETE_WINDOW",self ._on_close )

    def _build (self ):

        menubar =tk .Menu (self .root ,bg =DARK_BG ,fg =DARK_FG ,tearoff =0 )
        self .root .config (menu =menubar )

        proxy_menu =tk .Menu (menubar ,tearoff =0 ,bg =DARK_BG ,fg =DARK_FG )
        menubar .add_cascade (label ="Proxy",menu =proxy_menu )
        proxy_menu .add_command (label ="Start Proxy",command =self ._start_proxy )
        proxy_menu .add_command (label ="Stop Proxy",command =self ._stop_proxy )

        ca_menu =tk .Menu (menubar ,tearoff =0 ,bg =DARK_BG ,fg =DARK_FG )
        menubar .add_cascade (label ="CA Certificate",menu =ca_menu )
        ca_menu .add_command (label ="Install Root CA (Admin)",command =self ._install_ca )
        ca_menu .add_command (label ="Uninstall Root CA (Admin)",command =self ._uninstall_ca )
        ca_menu .add_command (label ="Show CA cert path",command =self ._show_ca_path )
        ca_menu .add_command (label ="Regenerate CA",command =self ._regen_ca )

        help_menu =tk .Menu (menubar ,tearoff =0 ,bg =DARK_BG ,fg =DARK_FG )
        menubar .add_cascade (label ="Help",menu =help_menu )
        help_menu .add_command (label ="Quick Start",command =self ._show_help )


        self ._statusbar =tk .Label (
        self .root ,
        text ="  Larp Suite ready  |  Set browser proxy to 127.0.0.1:8888",
        anchor ="w",bg ="#08090D",fg ="#7A6E52",font =("Consolas",8 ),
        )
        self ._statusbar .pack (side ="bottom",fill ="x")


        self ._nb =ttk .Notebook (self .root )
        self ._nb .pack (fill ="both",expand =True ,padx =4 ,pady =4 )


        self ._repeater_tab =RepeaterTab (self ._nb )
        self ._comparer_tab =ComparerTab (self ._nb )
        self ._organizer_tab =OrganizerTab (self ._nb )
        self ._sequencer_tab =SequencerTab (self ._nb )

        self ._proxy_tab =ProxyTab (
        self ._nb ,
        proxy_server =self ._proxy ,
        send_to_repeater_cb =self ._repeater_tab .load_entry ,
        )
        self ._target_tab =TargetTab (
        self ._nb ,
        send_to_repeater_cb =self ._repeater_tab .load_entry ,
        )
        self ._dashboard_tab =DashboardTab (
        self ._nb ,
        proxy_server =self ._proxy ,
        start_proxy_cb =self ._start_proxy ,
        stop_proxy_cb =self ._stop_proxy ,
        )
        self ._intruder_tab =IntruderTab (self ._nb )
        self ._decoder_tab =DecoderTab (self ._nb )
        self ._scanner_tab =ScannerTab (self ._nb )
        self ._logger_tab =LoggerTab (self ._nb )
        self ._diagnostics_tab =DiagnosticsTab (self ._nb )
        self ._settings_tab =SettingsTab (self ._nb ,proxy_server =self ._proxy )


        self ._nb .add (self ._dashboard_tab ,text ="  Dashboard  ")
        self ._nb .add (self ._target_tab ,text ="  Target  ")
        self ._nb .add (self ._proxy_tab ,text ="  Proxy  ")
        self ._nb .add (self ._intruder_tab ,text ="  Intruder  ")
        self ._nb .add (self ._repeater_tab ,text ="  Repeater  ")
        self ._nb .add (self ._sequencer_tab ,text ="  Sequencer  ")
        self ._nb .add (self ._decoder_tab ,text ="  Decoder  ")
        self ._nb .add (self ._comparer_tab ,text ="  Comparer  ")
        self ._nb .add (self ._logger_tab ,text ="  Logger  ")
        self ._nb .add (self ._organizer_tab ,text ="  Organizer  ")
        self ._nb .add (self ._scanner_tab ,text ="  Scanner  ")
        self ._nb .add (self ._diagnostics_tab ,text ="  Code Diagnostics  ")
        self ._nb .add (self ._settings_tab ,text ="  Settings  ")

    def _start_proxy (self ):
        if not self ._proxy .running :
            self ._proxy .start ()
            self ._statusbar .config (
            text =f"  Proxy running on 127.0.0.1:{self ._proxy .port }  |  Route browser traffic through this address"
            )

    def _stop_proxy (self ):
        if self ._proxy .running :
            self ._proxy .stop ()
            self ._statusbar .config (text ="  Proxy stopped")

    def _install_ca (self ):
        ok ,msg =install_ca_windows ()
        if ok :
            messagebox .showinfo ("CA Installed",msg +"\n\nRestart your browser to trust the CA.")
        else :
            messagebox .showerror ("Install Failed",msg +"\n\nRun Larp Suite as Administrator.")

    def _uninstall_ca (self ):
        ok ,msg =uninstall_ca_windows ()
        if ok :
            messagebox .showinfo ("CA Removed",msg )
        else :
            messagebox .showerror ("Uninstall Failed",msg )

    def _show_ca_path (self ):
        path =ca_cert_path ()
        messagebox .showinfo ("CA Certificate",
        f"CA cert path:\n{path }\n\nImport this into your browser's trusted CAs.")

    def _regen_ca (self ):
        if messagebox .askyesno ("Regenerate CA",
        "This will create a new root CA. Existing browser trust will break. Continue?"):
            generate_root_ca ()
            messagebox .showinfo ("Done","New root CA generated. Re-install it into your browser.")

    def _show_help (self ):
        msg =(
        "Larp Suite Quick Start\n"
        "======================\n\n"
        "1. CA Certificate: Menu -> Install Root CA (Admin)\n"
        "   Import the CA cert into your browser trust store.\n\n"
        "2. Set browser proxy to: 127.0.0.1 : 8888\n\n"
        "3. Dashboard -> Start Proxy\n\n"
        "4. Browse your target -- traffic appears in Proxy, Logger, and Target.\n\n"
        "5. Sequencer: analyse session token entropy.\n\n"
        "6. Comparer: side-by-side diff of any two texts.\n\n"
        "7. Organizer: track findings and notes.\n\n"
        "8. Code Diagnostics: static analysis of a local source directory.\n\n"
        "9. Settings: proxy port, timeouts, upstream proxy, logging."
        )
        messagebox .showinfo ("Quick Start",msg )

    def _on_close (self ):
        self ._stop_proxy ()
        self .root .destroy ()

    def run (self ):
        self .root .mainloop ()
