
import json 
import os 
import tkinter as tk 
from tkinter import ttk ,messagebox ,filedialog 

DARK_BG ="#0D0E14"
DARK_FG ="#E8DCC8"
ACCENT ="#C8A951"

SETTINGS_FILE =os .path .join (os .path .dirname (__file__ ),"..","settings.json")

DEFAULTS :dict ={
"proxy_host":"127.0.0.1",
"proxy_port":"8888",
"intercept_on":False ,
"upstream_proxy":"",
"upstream_port":"",
"user_agent":"LarpSuite/1.0",
"connect_timeout":"10",
"read_timeout":"30",
"max_history":"5000",
"scope_only":False ,
"log_to_file":False ,
"log_path":"",
"theme":"Dark",
"font_size":"9",
}


class SettingsTab (ttk .Frame ):
    def __init__ (self ,parent ,proxy_server =None ,**kw ):
        super ().__init__ (parent ,**kw )
        self ._proxy =proxy_server 
        self ._vars :dict [str ,tk .Variable ]={}
        self ._build ()
        self ._load ()

    def _build (self ):
        self .columnconfigure (0 ,weight =1 )
        self .rowconfigure (0 ,weight =1 )

        canvas =tk .Canvas (self ,bg =DARK_BG ,highlightthickness =0 )
        vsb =ttk .Scrollbar (self ,orient ="vertical",command =canvas .yview )
        canvas .configure (yscrollcommand =vsb .set )
        canvas .grid (row =0 ,column =0 ,sticky ="nsew")
        vsb .grid (row =0 ,column =1 ,sticky ="ns")

        inner =ttk .Frame (canvas )
        inner .columnconfigure (1 ,weight =1 )
        canvas .create_window ((0 ,0 ),window =inner ,anchor ="nw")
        inner .bind ("<Configure>",
        lambda e :canvas .configure (scrollregion =canvas .bbox ("all")))

        r =[0 ]

        def section (title ):
            tk .Label (inner ,text =title ,bg =DARK_BG ,fg =ACCENT ,
            font =("Consolas",10 ,"bold")).grid (
            row =r [0 ],column =0 ,columnspan =2 ,sticky ="w",padx =8 ,pady =(12 ,4 ))
            r [0 ]+=1 
            ttk .Separator (inner ,orient ="horizontal").grid (
            row =r [0 ],column =0 ,columnspan =2 ,sticky ="ew",padx =8 ,pady =(0 ,6 ))
            r [0 ]+=1 

        def field (label ,key ,widget_type ="entry",**kw_extra ):
            tk .Label (inner ,text =label ,bg =DARK_BG ,fg =DARK_FG ,
            font =("Consolas",9 ),width =28 ,anchor ="w").grid (
            row =r [0 ],column =0 ,sticky ="w",padx =(16 ,4 ),pady =3 )

            if widget_type =="check":
                var =tk .BooleanVar (value =DEFAULTS .get (key ,False ))
                w =ttk .Checkbutton (inner ,variable =var )
            elif widget_type =="combo":
                var =tk .StringVar (value =DEFAULTS .get (key ,""))
                w =ttk .Combobox (inner ,textvariable =var ,state ="readonly",
                width =20 ,**kw_extra )
            elif widget_type =="browse":
                var =tk .StringVar (value =DEFAULTS .get (key ,""))
                frm =ttk .Frame (inner )
                entry =ttk .Entry (frm ,textvariable =var ,width =30 )
                entry .pack (side ="left",fill ="x",expand =True )
                ttk .Button (frm ,text ="Browse...",
                command =lambda v =var :v .set (
                filedialog .askopenfilename ()or v .get ())
                ).pack (side ="left",padx =4 )
                frm .grid (row =r [0 ],column =1 ,sticky ="ew",padx =(0 ,8 ),pady =3 )
                self ._vars [key ]=var 
                r [0 ]+=1 
                return 
            else :
                var =tk .StringVar (value =DEFAULTS .get (key ,""))
                w =ttk .Entry (inner ,textvariable =var ,width =30 ,**kw_extra )

            w .grid (row =r [0 ],column =1 ,sticky ="w",padx =(0 ,8 ),pady =3 )
            self ._vars [key ]=var 
            r [0 ]+=1 


        section ("Proxy")
        field ("Listen host","proxy_host")
        field ("Listen port","proxy_port")
        field ("Intercept by default","intercept_on","check")
        field ("Scope only","scope_only","check")
        field ("Upstream proxy host","upstream_proxy")
        field ("Upstream proxy port","upstream_port")


        section ("HTTP")
        field ("Default User-Agent","user_agent")
        field ("Connect timeout (s)","connect_timeout")
        field ("Read timeout (s)","read_timeout")
        field ("Max history entries","max_history")


        section ("Logging")
        field ("Log traffic to file","log_to_file","check")
        field ("Log file path","log_path","browse")


        section ("Appearance")
        field ("Theme","theme","combo",values =["Dark","Light"])
        field ("Font size","font_size","combo",values =["8","9","10","11","12"])


        btn_frame =ttk .Frame (inner )
        btn_frame .grid (row =r [0 ],column =0 ,columnspan =2 ,pady =16 ,padx =8 ,sticky ="w")
        ttk .Button (btn_frame ,text ="Save Settings",command =self ._save ).pack (side ="left",padx =4 )
        ttk .Button (btn_frame ,text ="Reset Defaults",command =self ._reset ).pack (side ="left",padx =4 )
        ttk .Button (btn_frame ,text ="Apply to Proxy",command =self ._apply_proxy ).pack (side ="left",padx =4 )


    def _save (self ):
        data ={k :(v .get ()if hasattr (v ,"get")else v )
        for k ,v in self ._vars .items ()}
        try :
            with open (SETTINGS_FILE ,"w")as f :
                json .dump (data ,f ,indent =2 )
            messagebox .showinfo ("Settings","Settings saved.")
        except Exception as exc :
            messagebox .showerror ("Save Failed",str (exc ))

    def _load (self ):
        if not os .path .exists (SETTINGS_FILE ):
            return 
        try :
            with open (SETTINGS_FILE )as f :
                data =json .load (f )
            for k ,v in data .items ():
                if k in self ._vars :
                    self ._vars [k ].set (v )
        except Exception :
            pass 

    def _reset (self ):
        if messagebox .askyesno ("Reset","Reset all settings to defaults?"):
            for k ,v in DEFAULTS .items ():
                if k in self ._vars :
                    self ._vars [k ].set (v )

    def _apply_proxy (self ):
        if not self ._proxy :
            return 
        try :
            port =int (self ._vars ["proxy_port"].get ())
            self ._proxy .port =port 
            messagebox .showinfo ("Applied",f"Proxy port set to {port }.\nRestart proxy to take effect.")
        except ValueError :
            messagebox .showerror ("Invalid","Port must be a number.")

    def get (self ,key :str ):
        var =self ._vars .get (key )
        return var .get ()if var else DEFAULTS .get (key )
