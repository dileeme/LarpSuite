
import re 
import tkinter as tk 
from tkinter import ttk ,simpledialog ,messagebox 

from core .history import history ,HistoryEntry 

DARK_BG ="#0D0E14"
DARK_FG ="#E8DCC8"
ACCENT ="#C8A951"


class TargetTab (ttk .Frame ):
    def __init__ (self ,parent ,send_to_repeater_cb =None ,**kw ):
        super ().__init__ (parent ,**kw )
        self ._send_to_repeater =send_to_repeater_cb 

        self ._site_map :dict [str ,set [str ]]={}
        self ._scope_patterns :list [re .Pattern ]=[]
        self ._scope_raw :list [str ]=[]
        self ._build ()
        history .on_new_entry (self ._on_entry )

    def _build (self ):
        self .columnconfigure (0 ,weight =1 )
        self .columnconfigure (1 ,weight =2 )
        self .rowconfigure (0 ,weight =1 )


        left =ttk .LabelFrame (self ,text ="Site Map")
        left .grid (row =0 ,column =0 ,sticky ="nsew",padx =(6 ,3 ),pady =6 )
        left .columnconfigure (0 ,weight =1 )
        left .rowconfigure (1 ,weight =1 )

        tb =ttk .Frame (left )
        tb .grid (row =0 ,column =0 ,columnspan =2 ,sticky ="ew",padx =4 ,pady =4 )
        ttk .Button (tb ,text ="Clear",command =self ._clear_map ).pack (side ="left",padx =2 )
        ttk .Button (tb ,text ="Add to Scope",command =self ._add_to_scope_selected ).pack (side ="left",padx =2 )
        ttk .Button (tb ,text ="Exclude Scope",command =self ._exclude_selected ).pack (side ="left",padx =2 )

        self ._tree =ttk .Treeview (left ,show ="tree headings",
        columns =("Requests","InScope"),
        selectmode ="browse")
        self ._tree .heading ("#0",text ="Host / Path")
        self ._tree .heading ("Requests",text ="Reqs")
        self ._tree .heading ("InScope",text ="In Scope")
        self ._tree .column ("#0",width =260 )
        self ._tree .column ("Requests",width =50 ,anchor ="e")
        self ._tree .column ("InScope",width =70 ,anchor ="center")

        self ._tree .tag_configure ("in_scope",foreground ="#A8B840")
        self ._tree .tag_configure ("out_scope",foreground ="#7A6E52")
        self ._tree .tag_configure ("host",foreground =ACCENT )

        vsb =ttk .Scrollbar (left ,orient ="vertical",command =self ._tree .yview )
        hsb =ttk .Scrollbar (left ,orient ="horizontal",command =self ._tree .xview )
        self ._tree .configure (yscrollcommand =vsb .set ,xscrollcommand =hsb .set )
        self ._tree .grid (row =1 ,column =0 ,sticky ="nsew",padx =(4 ,0 ),pady =(0 ,4 ))
        vsb .grid (row =1 ,column =1 ,sticky ="ns")
        hsb .grid (row =2 ,column =0 ,sticky ="ew",padx =4 )

        self ._tree .bind ("<<TreeviewSelect>>",self ._on_select )
        self ._tree .bind ("<Button-3>",self ._ctx_menu )


        right =ttk .Frame (self )
        right .grid (row =0 ,column =1 ,sticky ="nsew",padx =(3 ,6 ),pady =6 )
        right .columnconfigure (0 ,weight =1 )
        right .rowconfigure (1 ,weight =1 )


        scope_frame =ttk .LabelFrame (right ,text ="Scope")
        scope_frame .grid (row =0 ,column =0 ,sticky ="ew",pady =(0 ,6 ))
        scope_frame .columnconfigure (0 ,weight =1 )

        scope_tb =ttk .Frame (scope_frame )
        scope_tb .grid (row =0 ,column =0 ,sticky ="ew",padx =4 ,pady =4 )
        ttk .Button (scope_tb ,text ="Add Pattern…",command =self ._add_scope_pattern ).pack (side ="left",padx =2 )
        ttk .Button (scope_tb ,text ="Remove Selected",command =self ._remove_scope_pattern ).pack (side ="left",padx =2 )

        self ._scope_list =tk .Listbox (scope_frame ,bg ="#0A0B10",fg ="#A8B840",
        font =("Consolas",9 ),height =5 ,
        selectbackground ="#5A4A1E")
        self ._scope_list .grid (row =1 ,column =0 ,sticky ="ew",padx =4 ,pady =(0 ,4 ))


        detail_frame =ttk .LabelFrame (right ,text ="Selected Request")
        detail_frame .grid (row =1 ,column =0 ,sticky ="nsew")
        detail_frame .columnconfigure (0 ,weight =1 )
        detail_frame .rowconfigure (0 ,weight =1 )

        self ._detail =tk .Text (detail_frame ,wrap ="none",bg ="#0A0B10",fg =DARK_FG ,
        font =("Consolas",9 ),state ="disabled")
        dvsb =ttk .Scrollbar (detail_frame ,orient ="vertical",command =self ._detail .yview )
        dhsb =ttk .Scrollbar (detail_frame ,orient ="horizontal",command =self ._detail .xview )
        self ._detail .configure (yscrollcommand =dvsb .set ,xscrollcommand =dhsb .set )
        self ._detail .grid (row =0 ,column =0 ,sticky ="nsew",padx =(4 ,0 ),pady =4 )
        dvsb .grid (row =0 ,column =1 ,sticky ="ns")
        dhsb .grid (row =1 ,column =0 ,sticky ="ew",padx =4 )


        self ._ctx =tk .Menu (self ,tearoff =0 ,bg =DARK_BG ,fg =DARK_FG )
        self ._ctx .add_command (label ="Send to Repeater",command =self ._send_repeater )
        self ._ctx .add_command (label ="Add to Scope",command =self ._add_to_scope_selected )
        self ._ctx .add_command (label ="Exclude from Scope",command =self ._exclude_selected )


        self ._host_nodes :dict [str ,str ]={}
        self ._path_nodes :dict [str ,dict [str ,str ]]={}
        self ._path_entries :dict [str ,dict [str ,HistoryEntry ]]={}
        self ._selected_entry :HistoryEntry |None =None 


    def _on_entry (self ,entry :HistoryEntry ):
        self .after (0 ,self ._add_to_map ,entry )

    def _add_to_map (self ,entry :HistoryEntry ):
        host =entry .host 
        path =entry .path .split ("?")[0 ]or "/"

        if host not in self ._host_nodes :
            in_scope =self ._is_in_scope (host )
            tag ="in_scope"if in_scope else "out_scope"
            iid =self ._tree .insert ("","end",text =f"  {host }",
            values =(0 ,"✓"if in_scope else ""),
            tags =("host",tag ),open =False )
            self ._host_nodes [host ]=iid 
            self ._path_nodes [host ]={}
            self ._path_entries [host ]={}
            self ._site_map [host ]=set ()

        host_iid =self ._host_nodes [host ]

        if path not in self ._path_nodes [host ]:
            in_scope =self ._is_in_scope (host +path )
            tag ="in_scope"if in_scope else "out_scope"
            piid =self ._tree .insert (host_iid ,"end",text =f"  {path }",
            values =(1 ,"✓"if in_scope else ""),tags =(tag ,))
            self ._path_nodes [host ][path ]=piid 
            self ._path_entries [host ][path ]=entry 
            self ._site_map [host ].add (path )
        else :
            piid =self ._path_nodes [host ][path ]
            cur =int (self ._tree .item (piid ,"values")[0 ])
            self ._tree .item (piid ,values =(cur +1 ,self ._tree .item (piid ,"values")[1 ]))
            self ._path_entries [host ][path ]=entry 


        total =sum (int (self ._tree .item (p ,"values")[0 ])
        for p in self ._path_nodes [host ].values ())
        self ._tree .item (host_iid ,values =(total ,self ._tree .item (host_iid ,"values")[1 ]))

    def _on_select (self ,_ =None ):
        sel =self ._tree .selection ()
        if not sel :
            return 
        iid =sel [0 ]
        parent =self ._tree .parent (iid )
        if not parent :
            return 
        host_text =self ._tree .item (parent ,"text").strip ()
        path_text =self ._tree .item (iid ,"text").strip ()
        entry =self ._path_entries .get (host_text ,{}).get (path_text )
        self ._selected_entry =entry 
        if entry :
            self ._set_detail (entry .request .to_display ())

    def _set_detail (self ,text :str ):
        self ._detail .config (state ="normal")
        self ._detail .delete ("1.0","end")
        self ._detail .insert ("1.0",text )
        self ._detail .config (state ="disabled")

    def _clear_map (self ):
        for iid in self ._tree .get_children ():
            self ._tree .delete (iid )
        self ._host_nodes .clear ()
        self ._path_nodes .clear ()
        self ._path_entries .clear ()
        self ._site_map .clear ()

    def _ctx_menu (self ,event ):
        iid =self ._tree .identify_row (event .y )
        if iid :
            self ._tree .selection_set (iid )
            self ._on_select ()
            self ._ctx .post (event .x_root ,event .y_root )

    def _send_repeater (self ):
        if self ._selected_entry and self ._send_to_repeater :
            self ._send_to_repeater (self ._selected_entry )


    def _is_in_scope (self ,target :str )->bool :
        return any (p .search (target )for p in self ._scope_patterns )

    def _add_scope_pattern (self ):
        pat =simpledialog .askstring ("Add Scope Pattern",
        "Enter a regex or hostname pattern:\n(e.g.  example\\.com  or  .*\\.target\\.com)",
        parent =self )
        if pat :
            self ._scope_raw .append (pat )
            try :
                self ._scope_patterns .append (re .compile (pat ,re .I ))
                self ._scope_list .insert ("end",pat )
                self ._refresh_scope_tags ()
            except re .error as e :
                messagebox .showerror ("Invalid Pattern",str (e ))

    def _add_to_scope_selected (self ):
        sel =self ._tree .selection ()
        if not sel :
            return 
        iid =sel [0 ]
        parent =self ._tree .parent (iid )
        host =self ._tree .item (iid if not parent else parent ,"text").strip ()
        self ._scope_raw .append (re .escape (host ))
        self ._scope_patterns .append (re .compile (re .escape (host ),re .I ))
        self ._scope_list .insert ("end",re .escape (host ))
        self ._refresh_scope_tags ()

    def _exclude_selected (self ):
        sel =self ._tree .selection ()
        if not sel :
            return 
        iid =sel [0 ]
        parent =self ._tree .parent (iid )
        host =self ._tree .item (iid if not parent else parent ,"text").strip ()
        pat =f"(?!.*{re .escape (host )})"
        self ._scope_raw .append (pat )
        try :
            self ._scope_patterns .append (re .compile (pat ,re .I ))
            self ._scope_list .insert ("end",f"EXCLUDE: {host }")
        except re .error :
            pass 

    def _remove_scope_pattern (self ):
        sel =self ._scope_list .curselection ()
        if not sel :
            return 
        idx =sel [0 ]
        self ._scope_list .delete (idx )
        self ._scope_raw .pop (idx )
        self ._scope_patterns .pop (idx )
        self ._refresh_scope_tags ()

    def _refresh_scope_tags (self ):
        for host ,host_iid in self ._host_nodes .items ():
            in_scope =self ._is_in_scope (host )
            self ._tree .item (host_iid ,
            tags =("host","in_scope"if in_scope else "out_scope"),
            values =(self ._tree .item (host_iid ,"values")[0 ],
            "✓"if in_scope else ""))
            for path ,piid in self ._path_nodes [host ].items ():
                in_scope =self ._is_in_scope (host +path )
                self ._tree .item (piid ,
                tags =("in_scope"if in_scope else "out_scope",),
                values =(self ._tree .item (piid ,"values")[0 ],
                "✓"if in_scope else ""))
