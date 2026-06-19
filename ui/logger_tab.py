
import time 
import tkinter as tk 
from tkinter import ttk ,filedialog 

from core .history import history ,HistoryEntry 

DARK_BG ="#0D0E14"
DARK_FG ="#E8DCC8"
ACCENT ="#C8A951"

COLS =("#","Time","Method","Host","Path","Status","Length","MIME")


class LoggerTab (ttk .Frame ):
    def __init__ (self ,parent ,**kw ):
        super ().__init__ (parent ,**kw )
        self ._entries :list [HistoryEntry ]=[]
        self ._build ()
        history .on_new_entry (self ._on_entry )

    def _build (self ):
        self .columnconfigure (0 ,weight =1 )
        self .rowconfigure (1 ,weight =1 )


        tb =ttk .Frame (self )
        tb .grid (row =0 ,column =0 ,sticky ="ew",padx =6 ,pady =4 )

        ttk .Label (tb ,text ="Filter:").pack (side ="left")
        self ._filter_var =tk .StringVar ()
        self ._filter_var .trace_add ("write",lambda *_ :self ._apply_filter ())
        ttk .Entry (tb ,textvariable =self ._filter_var ,width =30 ).pack (side ="left",padx =4 )

        ttk .Label (tb ,text ="Method:").pack (side ="left",padx =(8 ,0 ))
        self ._method_var =tk .StringVar (value ="All")
        ttk .Combobox (tb ,textvariable =self ._method_var ,
        values =["All","GET","POST","PUT","DELETE","PATCH","OPTIONS"],
        width =8 ,state ="readonly").pack (side ="left",padx =4 )
        self ._method_var .trace_add ("write",lambda *_ :self ._apply_filter ())

        ttk .Label (tb ,text ="Status:").pack (side ="left",padx =(8 ,0 ))
        self ._status_var =tk .StringVar (value ="All")
        ttk .Combobox (tb ,textvariable =self ._status_var ,
        values =["All","2xx","3xx","4xx","5xx"],
        width =6 ,state ="readonly").pack (side ="left",padx =4 )
        self ._status_var .trace_add ("write",lambda *_ :self ._apply_filter ())

        ttk .Button (tb ,text ="Clear Log",command =self ._clear ).pack (side ="left",padx =8 )
        ttk .Button (tb ,text ="Export CSV",command =self ._export_csv ).pack (side ="left")

        self ._count_var =tk .StringVar (value ="0 entries")
        ttk .Label (tb ,textvariable =self ._count_var ,foreground ="gray").pack (side ="right",padx =6 )


        tbl =ttk .Frame (self )
        tbl .grid (row =1 ,column =0 ,sticky ="nsew",padx =6 ,pady =(0 ,4 ))
        tbl .columnconfigure (0 ,weight =1 )
        tbl .rowconfigure (0 ,weight =1 )

        self ._tree =ttk .Treeview (tbl ,columns =COLS ,show ="headings",
        selectmode ="browse")
        widths =[45 ,75 ,65 ,200 ,250 ,60 ,70 ,130 ]
        for col ,w in zip (COLS ,widths ):
            self ._tree .heading (col ,text =col ,
            command =lambda c =col :self ._sort (c ))
            self ._tree .column (col ,width =w ,anchor ="w")

        self ._tree .tag_configure ("2xx",foreground ="#A8B840")
        self ._tree .tag_configure ("3xx",foreground ="#8AB0C8")
        self ._tree .tag_configure ("4xx",foreground ="#ffcc00")
        self ._tree .tag_configure ("5xx",foreground ="#ff4444")

        vsb =ttk .Scrollbar (tbl ,orient ="vertical",command =self ._tree .yview )
        hsb =ttk .Scrollbar (tbl ,orient ="horizontal",command =self ._tree .xview )
        self ._tree .configure (yscrollcommand =vsb .set ,xscrollcommand =hsb .set )
        self ._tree .grid (row =0 ,column =0 ,sticky ="nsew")
        vsb .grid (row =0 ,column =1 ,sticky ="ns")
        hsb .grid (row =1 ,column =0 ,sticky ="ew")
        self ._tree .bind ("<<TreeviewSelect>>",self ._on_select )


        paned =ttk .PanedWindow (self ,orient ="horizontal")
        paned .grid (row =2 ,column =0 ,sticky ="ew",padx =6 ,pady =(0 ,6 ))

        req_frame =ttk .LabelFrame (paned ,text ="Request")
        paned .add (req_frame ,weight =1 )
        self ._req_text =tk .Text (req_frame ,height =8 ,wrap ="none",
        bg ="#0A0B10",fg =DARK_FG ,font =("Consolas",8 ),
        state ="disabled")
        self ._req_text .pack (fill ="both",expand =True ,padx =4 ,pady =4 )

        resp_frame =ttk .LabelFrame (paned ,text ="Response")
        paned .add (resp_frame ,weight =1 )
        self ._resp_text =tk .Text (resp_frame ,height =8 ,wrap ="none",
        bg ="#0A0B10",fg =DARK_FG ,font =("Consolas",8 ),
        state ="disabled")
        self ._resp_text .pack (fill ="both",expand =True ,padx =4 ,pady =4 )


    def _on_entry (self ,entry :HistoryEntry ):
        self .after (0 ,self ._insert ,entry )

    def _insert (self ,entry :HistoryEntry ):
        self ._entries .append (entry )
        self ._insert_row (entry )
        self ._count_var .set (f"{len (self ._entries )} entries")

    def _insert_row (self ,entry :HistoryEntry ):
        flt =self ._filter_var .get ().lower ()
        method =self ._method_var .get ()
        status =self ._status_var .get ()

        if flt and flt not in (entry .host +entry .path ).lower ():
            return 
        if method !="All"and entry .method !=method :
            return 
        if status !="All":
            code =entry .response .status_code if entry .response else 0 
            bucket =f"{code //100 }xx"
            if bucket !=status :
                return 

        code =entry .response .status_code if entry .response else 0 
        tag =f"{code //100 }xx"if code else ""
        ts =time .strftime ("%H:%M:%S",time .localtime (entry .timestamp ))
        mime =entry .content_type .split ("/")[-1 ][:20 ]if entry .content_type else ""

        self ._tree .insert ("","end",iid =str (entry .id ),tags =(tag ,),values =(
        entry .id ,ts ,entry .method ,entry .host ,
        entry .path [:80 ],entry .status ,entry .length ,mime ,
        ))

    def _apply_filter (self ):
        for iid in self ._tree .get_children ():
            self ._tree .delete (iid )
        for entry in self ._entries :
            self ._insert_row (entry )

    def _on_select (self ,_ =None ):
        sel =self ._tree .selection ()
        if not sel :
            return 
        try :
            entry_id =int (sel [0 ])
        except ValueError :
            return 
        entry =history .get_by_id (entry_id )
        if not entry :
            return 
        self ._set_text (self ._req_text ,entry .request .to_display ())
        self ._set_text (self ._resp_text ,entry .response .to_display ()if entry .response else "")

    def _set_text (self ,widget ,text :str ):
        widget .config (state ="normal")
        widget .delete ("1.0","end")
        widget .insert ("1.0",text )
        widget .config (state ="disabled")

    def _sort (self ,col :str ):
        items =[(self ._tree .set (i ,col ),i )for i in self ._tree .get_children ("")]
        items .sort (key =lambda x :(x [0 ].isdigit (),int (x [0 ])if x [0 ].isdigit ()else x [0 ].lower ()))
        for idx ,(_ ,iid )in enumerate (items ):
            self ._tree .move (iid ,"",idx )

    def _clear (self ):
        self ._entries .clear ()
        for iid in self ._tree .get_children ():
            self ._tree .delete (iid )
        self ._count_var .set ("0 entries")

    def _export_csv (self ):
        path =filedialog .asksaveasfilename (
        defaultextension =".csv",
        filetypes =[("CSV","*.csv"),("All","*.*")],
        title ="Export Logger CSV",
        )
        if not path :
            return 
        import csv 
        with open (path ,"w",newline ="",encoding ="utf-8")as f :
            w =csv .writer (f )
            w .writerow (COLS )
            for iid in self ._tree .get_children ():
                w .writerow (self ._tree .item (iid ,"values"))
