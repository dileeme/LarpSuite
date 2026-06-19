
import time 
import tkinter as tk 
from tkinter import ttk 

from core .history import history ,HistoryEntry 
from ui .proxy_tab import launch_proxied_browser 

DARK_BG ="#0D0E14"
DARK_FG ="#E8DCC8"
ACCENT ="#C8A951"
CODE_FG ="#B8A882"


class DashboardTab (ttk .Frame ):
    def __init__ (self ,parent ,proxy_server =None ,start_proxy_cb =None ,
    stop_proxy_cb =None ,**kw ):
        super ().__init__ (parent ,**kw )
        self ._proxy =proxy_server 
        self ._start_cb =start_proxy_cb 
        self ._stop_cb =stop_proxy_cb 
        self ._req_count =0 
        self ._host_counts :dict [str ,int ]={}
        self ._recent :list [str ]=[]
        self ._build ()
        history .on_new_entry (self ._on_entry )
        self ._tick ()

    def _build (self ):
        self .columnconfigure (0 ,weight =1 )
        self .columnconfigure (1 ,weight =1 )
        self .rowconfigure (1 ,weight =1 )


        title =tk .Label (self ,text ="  Larp Suite  —  Dashboard",
        bg ="#08090D",fg =ACCENT ,
        font =("Consolas",14 ,"bold"),anchor ="w")
        title .grid (row =0 ,column =0 ,columnspan =2 ,sticky ="ew",pady =(0 ,6 ))


        left =ttk .Frame (self )
        left .grid (row =1 ,column =0 ,sticky ="nsew",padx =(6 ,3 ),pady =4 )
        left .columnconfigure (0 ,weight =1 )


        self ._status_frame =ttk .LabelFrame (left ,text ="Proxy Status")
        self ._status_frame .grid (row =0 ,column =0 ,sticky ="ew",pady =(0 ,6 ))
        self ._status_frame .columnconfigure (1 ,weight =1 )

        tk .Label (self ._status_frame ,text ="State:",bg =DARK_BG ,fg =DARK_FG ).grid (
        row =0 ,column =0 ,sticky ="w",padx =8 ,pady =4 )
        self ._state_var =tk .StringVar (value ="Stopped")
        tk .Label (self ._status_frame ,textvariable =self ._state_var ,
        bg =DARK_BG ,fg ="#ff4444",font =("Consolas",10 ,"bold")).grid (
        row =0 ,column =1 ,sticky ="w")

        tk .Label (self ._status_frame ,text ="Address:",bg =DARK_BG ,fg =DARK_FG ).grid (
        row =1 ,column =0 ,sticky ="w",padx =8 ,pady =2 )
        tk .Label (self ._status_frame ,text ="127.0.0.1 : 8888",
        bg =DARK_BG ,fg =CODE_FG ,font =("Consolas",9 )).grid (
        row =1 ,column =1 ,sticky ="w")

        tk .Label (self ._status_frame ,text ="Requests:",bg =DARK_BG ,fg =DARK_FG ).grid (
        row =2 ,column =0 ,sticky ="w",padx =8 ,pady =2 )
        self ._req_var =tk .StringVar (value ="0")
        tk .Label (self ._status_frame ,textvariable =self ._req_var ,
        bg =DARK_BG ,fg =CODE_FG ,font =("Consolas",9 )).grid (
        row =2 ,column =1 ,sticky ="w")

        tk .Label (self ._status_frame ,text ="Uptime:",bg =DARK_BG ,fg =DARK_FG ).grid (
        row =3 ,column =0 ,sticky ="w",padx =8 ,pady =(2 ,8 ))
        self ._uptime_var =tk .StringVar (value ="—")
        tk .Label (self ._status_frame ,textvariable =self ._uptime_var ,
        bg =DARK_BG ,fg =CODE_FG ,font =("Consolas",9 )).grid (
        row =3 ,column =1 ,sticky ="w")

        self ._start_time :float |None =None 


        btn_frame =ttk .Frame (self ._status_frame )
        btn_frame .grid (row =4 ,column =0 ,columnspan =2 ,pady =(0 ,8 ),padx =8 ,sticky ="w")
        ttk .Button (btn_frame ,text ="▶  Start Proxy",command =self ._start ).pack (side ="left",padx =(0 ,4 ))
        ttk .Button (btn_frame ,text ="■  Stop Proxy",command =self ._stop ).pack (side ="left",padx =(0 ,4 ))
        ttk .Button (btn_frame ,text ="Open Browser",command =self ._open_browser ).pack (side ="left")


        stats =ttk .LabelFrame (left ,text ="Traffic Statistics")
        stats .grid (row =1 ,column =0 ,sticky ="ew",pady =(0 ,6 ))
        stats .columnconfigure (1 ,weight =1 )

        labels =[("Hosts seen:","_hosts_var"),
        ("GET requests:","_get_var"),
        ("POST requests:","_post_var"),
        ("HTTPS:","_https_var"),
        ("Errors (5xx):","_err_var")]
        for i ,(lbl ,attr )in enumerate (labels ):
            tk .Label (stats ,text =lbl ,bg =DARK_BG ,fg =DARK_FG ).grid (
            row =i ,column =0 ,sticky ="w",padx =8 ,pady =2 )
            var =tk .StringVar (value ="0")
            setattr (self ,attr ,var )
            tk .Label (stats ,textvariable =var ,bg =DARK_BG ,fg =CODE_FG ,
            font =("Consolas",9 )).grid (row =i ,column =1 ,sticky ="w")

        tk .Label (stats ,text ="",bg =DARK_BG ).grid (row =len (labels ),column =0 )


        top_frame =ttk .LabelFrame (left ,text ="Top Hosts")
        top_frame .grid (row =2 ,column =0 ,sticky ="nsew",pady =(0 ,6 ))
        top_frame .rowconfigure (0 ,weight =1 )
        top_frame .columnconfigure (0 ,weight =1 )
        left .rowconfigure (2 ,weight =1 )

        self ._hosts_tree =ttk .Treeview (top_frame ,columns =("Host","Reqs"),
        show ="headings",height =8 )
        self ._hosts_tree .heading ("Host",text ="Host")
        self ._hosts_tree .heading ("Reqs",text ="Requests")
        self ._hosts_tree .column ("Host",width =220 )
        self ._hosts_tree .column ("Reqs",width =70 ,anchor ="e")
        hsb =ttk .Scrollbar (top_frame ,orient ="vertical",
        command =self ._hosts_tree .yview )
        self ._hosts_tree .configure (yscrollcommand =hsb .set )
        self ._hosts_tree .grid (row =0 ,column =0 ,sticky ="nsew",padx =4 ,pady =4 )
        hsb .grid (row =0 ,column =1 ,sticky ="ns")


        right =ttk .Frame (self )
        right .grid (row =1 ,column =1 ,sticky ="nsew",padx =(3 ,6 ),pady =4 )
        right .columnconfigure (0 ,weight =1 )
        right .rowconfigure (1 ,weight =1 )


        log_frame =ttk .LabelFrame (right ,text ="Event Log")
        log_frame .grid (row =0 ,column =0 ,sticky ="nsew",pady =(0 ,6 ))
        log_frame .columnconfigure (0 ,weight =1 )
        log_frame .rowconfigure (0 ,weight =1 )
        right .rowconfigure (0 ,weight =1 )

        self ._log =tk .Text (log_frame ,height =18 ,wrap ="none",
        bg ="#0A0B10",fg =DARK_FG ,
        font =("Consolas",8 ),state ="disabled")
        log_vsb =ttk .Scrollbar (log_frame ,orient ="vertical",command =self ._log .yview )
        self ._log .configure (yscrollcommand =log_vsb .set )
        self ._log .grid (row =0 ,column =0 ,sticky ="nsew",padx =4 ,pady =4 )
        log_vsb .grid (row =0 ,column =1 ,sticky ="ns")

        self ._log .tag_configure ("ts",foreground ="#7A6E52")
        self ._log .tag_configure ("ok",foreground ="#A8B840")
        self ._log .tag_configure ("err",foreground ="#ff4444")
        self ._log .tag_configure ("inf",foreground =CODE_FG )


        act_frame =ttk .LabelFrame (right ,text ="Recent Requests")
        act_frame .grid (row =1 ,column =0 ,sticky ="nsew")
        act_frame .columnconfigure (0 ,weight =1 )
        act_frame .rowconfigure (0 ,weight =1 )

        self ._recent_tree =ttk .Treeview (
        act_frame ,
        columns =("#","Method","Host","Path","Status"),
        show ="headings",height =10 ,
        )
        for col ,w in [("#",40 ),("Method",60 ),("Host",180 ),("Path",200 ),("Status",55 )]:
            self ._recent_tree .heading (col ,text =col )
            self ._recent_tree .column (col ,width =w ,anchor ="w")
        act_vsb =ttk .Scrollbar (act_frame ,orient ="vertical",
        command =self ._recent_tree .yview )
        self ._recent_tree .configure (yscrollcommand =act_vsb .set )
        self ._recent_tree .grid (row =0 ,column =0 ,sticky ="nsew",padx =4 ,pady =4 )
        act_vsb .grid (row =0 ,column =1 ,sticky ="ns")

        self ._log_event ("Larp Suite started","inf")


    def _on_entry (self ,entry :HistoryEntry ):
        self .after (0 ,self ._update_entry ,entry )

    def _update_entry (self ,entry :HistoryEntry ):
        self ._req_count +=1 
        host =entry .host 

        self ._host_counts [host ]=self ._host_counts .get (host ,0 )+1 
        self ._req_var .set (str (self ._req_count ))
        self ._hosts_var .set (str (len (self ._host_counts )))

        all_entries =history .get_all ()
        self ._get_var .set (str (sum (1 for e in all_entries if e .method =="GET")))
        self ._post_var .set (str (sum (1 for e in all_entries if e .method =="POST")))
        self ._https_var .set (str (sum (1 for e in all_entries if e .request .is_https )))
        self ._err_var .set (str (sum (1 for e in all_entries 
        if e .response and e .response .status_code >=500 )))


        for item in self ._hosts_tree .get_children ():
            self ._hosts_tree .delete (item )
        for h ,cnt in sorted (self ._host_counts .items (),key =lambda x :x [1 ],reverse =True )[:15 ]:
            self ._hosts_tree .insert ("","end",values =(h ,cnt ))


        status =entry .response .status_code if entry .response else "—"
        tag ="err"if isinstance (status ,int )and status >=400 else ""
        self ._recent_tree .insert ("",0 ,tags =(tag ,),
        values =(entry .id ,entry .method ,host ,
        entry .path [:60 ],status ))
        children =self ._recent_tree .get_children ()
        if len (children )>200 :
            self ._recent_tree .delete (children [-1 ])

        self ._log_event (f"{entry .method } {host }{entry .path [:50 ]}  →  {status }",
        "err"if isinstance (status ,int )and status >=400 else "ok")

    def _log_event (self ,msg :str ,tag :str ="inf"):
        ts =time .strftime ("%H:%M:%S")
        self ._log .config (state ="normal")
        self ._log .insert ("end",f"[{ts }] ","ts")
        self ._log .insert ("end",msg +"\n",tag )
        self ._log .see ("end")
        self ._log .config (state ="disabled")

    def _start (self ):
        if self ._start_cb :
            self ._start_cb ()
        self ._state_var .set ("Running")
        self ._start_time =time .time ()

        for w in self ._status_frame .winfo_children ():
            if isinstance (w ,tk .Label )and w .cget ("textvariable")==str (self ._state_var ):
                w .config (fg ="#A8B840")
        self ._log_event ("Proxy started on 127.0.0.1:8888","ok")

    def _stop (self ):
        if self ._stop_cb :
            self ._stop_cb ()
        self ._state_var .set ("Stopped")
        self ._start_time =None 
        self ._log_event ("Proxy stopped","err")

    def _open_browser (self ):
        if self ._proxy and not self ._proxy .running :
            self ._start ()
        port =self ._proxy .port if self ._proxy else 8888 
        launch_proxied_browser (port )
        self ._log_event (f"Browser launched via proxy 127.0.0.1:{port }","inf")

    def _tick (self ):
        if self ._start_time :
            elapsed =int (time .time ()-self ._start_time )
            h ,rem =divmod (elapsed ,3600 )
            m ,s =divmod (rem ,60 )
            self ._uptime_var .set (f"{h :02d}:{m :02d}:{s :02d}")
        self .after (1000 ,self ._tick )
