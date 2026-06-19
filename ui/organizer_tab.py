
import json 
import time 
import tkinter as tk 
from tkinter import ttk ,filedialog ,messagebox ,simpledialog 

DARK_BG ="#0D0E14"
DARK_FG ="#E8DCC8"
ACCENT ="#C8A951"

PRIORITIES =["Critical","High","Medium","Low","Info"]
STATUSES =["Open","In Progress","Done","Won't Fix"]
PRI_COLOUR ={
"Critical":"#ff4444",
"High":"#ff8800",
"Medium":"#ffcc00",
"Low":"#8AB0C8",
"Info":"#7A6E52",
}
STAT_COLOUR ={
"Open":"#ff8800",
"In Progress":"#ffcc00",
"Done":"#A8B840",
"Won't Fix":"#7A6E52",
}


class OrganizerTab (ttk .Frame ):
    def __init__ (self ,parent ,**kw ):
        super ().__init__ (parent ,**kw )
        self ._items :list [dict ]=[]
        self ._next_id =1 
        self ._build ()

    def _build (self ):
        self .columnconfigure (0 ,weight =1 )
        self .rowconfigure (1 ,weight =1 )


        tb =ttk .Frame (self )
        tb .grid (row =0 ,column =0 ,sticky ="ew",padx =6 ,pady =4 )

        ttk .Button (tb ,text ="+ Add Item",command =self ._add_item ).pack (side ="left",padx =2 )
        ttk .Button (tb ,text ="Delete",command =self ._delete_item ).pack (side ="left",padx =2 )
        ttk .Button (tb ,text ="Mark Done",command =self ._mark_done ).pack (side ="left",padx =2 )
        ttk .Button (tb ,text ="Export JSON",command =self ._export ).pack (side ="left",padx =2 )
        ttk .Button (tb ,text ="Import JSON",command =self ._import ).pack (side ="left",padx =2 )

        ttk .Label (tb ,text ="Filter:").pack (side ="left",padx =(12 ,4 ))
        self ._filter_var =tk .StringVar ()
        self ._filter_var .trace_add ("write",lambda *_ :self ._refresh ())
        ttk .Entry (tb ,textvariable =self ._filter_var ,width =20 ).pack (side ="left")

        ttk .Label (tb ,text ="Status:").pack (side ="left",padx =(8 ,4 ))
        self ._stat_filter =tk .StringVar (value ="All")
        ttk .Combobox (tb ,textvariable =self ._stat_filter ,
        values =["All"]+STATUSES ,width =12 ,
        state ="readonly").pack (side ="left")
        self ._stat_filter .trace_add ("write",lambda *_ :self ._refresh ())


        paned =ttk .PanedWindow (self ,orient ="horizontal")
        paned .grid (row =1 ,column =0 ,sticky ="nsew",padx =6 ,pady =(0 ,6 ))


        list_frame =ttk .LabelFrame (paned ,text ="Items")
        paned .add (list_frame ,weight =2 )
        list_frame .columnconfigure (0 ,weight =1 )
        list_frame .rowconfigure (0 ,weight =1 )

        cols =("#","Priority","Status","Title","Created")
        self ._tree =ttk .Treeview (list_frame ,columns =cols ,show ="headings",
        selectmode ="browse")
        widths =[40 ,80 ,100 ,300 ,130 ]
        for col ,w in zip (cols ,widths ):
            self ._tree .heading (col ,text =col )
            self ._tree .column (col ,width =w ,anchor ="w")

        for pri ,col in PRI_COLOUR .items ():
            self ._tree .tag_configure (f"pri_{pri }",foreground =col )

        vsb =ttk .Scrollbar (list_frame ,orient ="vertical",command =self ._tree .yview )
        self ._tree .configure (yscrollcommand =vsb .set )
        self ._tree .grid (row =0 ,column =0 ,sticky ="nsew",padx =(4 ,0 ),pady =4 )
        vsb .grid (row =0 ,column =1 ,sticky ="ns",pady =4 )
        self ._tree .bind ("<<TreeviewSelect>>",self ._on_select )
        self ._tree .bind ("<Double-1>",lambda _ :self ._edit_item ())


        detail =ttk .LabelFrame (paned ,text ="Detail")
        paned .add (detail ,weight =1 )
        detail .columnconfigure (1 ,weight =1 )

        fields =[
        ("Title:","_d_title"),
        ("Priority:","_d_priority"),
        ("Status:","_d_status"),
        ("Tags:","_d_tags"),
        ("URL:","_d_url"),
        ]
        for i ,(lbl ,attr )in enumerate (fields ):
            tk .Label (detail ,text =lbl ,bg =DARK_BG ,fg =DARK_FG ,
            font =("Consolas",9 )).grid (row =i ,column =0 ,sticky ="w",
            padx =(8 ,4 ),pady =3 )
            if attr =="_d_priority":
                var =tk .StringVar (value ="Medium")
                w =ttk .Combobox (detail ,textvariable =var ,values =PRIORITIES ,
                state ="readonly",width =14 )
                setattr (self ,attr +"_var",var )
            elif attr =="_d_status":
                var =tk .StringVar (value ="Open")
                w =ttk .Combobox (detail ,textvariable =var ,values =STATUSES ,
                state ="readonly",width =14 )
                setattr (self ,attr +"_var",var )
            else :
                var =tk .StringVar ()
                w =ttk .Entry (detail ,textvariable =var ,width =30 )
                setattr (self ,attr +"_var",var )
            w .grid (row =i ,column =1 ,sticky ="ew",padx =(0 ,8 ),pady =3 )

        tk .Label (detail ,text ="Notes:",bg =DARK_BG ,fg =DARK_FG ,
        font =("Consolas",9 )).grid (row =len (fields ),column =0 ,
        sticky ="nw",padx =(8 ,4 ),pady =3 )
        self ._notes_text =tk .Text (detail ,wrap ="word",bg ="#0A0B10",fg =DARK_FG ,
        font =("Consolas",9 ),height =10 )
        self ._notes_text .grid (row =len (fields ),column =0 ,columnspan =2 ,
        sticky ="nsew",padx =8 ,pady =(0 ,4 ))
        detail .rowconfigure (len (fields ),weight =1 )

        ttk .Button (detail ,text ="Save Changes",command =self ._save_edit ).grid (
        row =len (fields )+1 ,column =0 ,columnspan =2 ,pady =(0 ,8 ))

        self ._selected_id :int |None =None 


    def _add_item (self ):
        title =simpledialog .askstring ("New Item","Item title:",parent =self )
        if not title :
            return 
        item ={
        "id":self ._next_id ,
        "title":title ,
        "priority":"Medium",
        "status":"Open",
        "tags":"",
        "url":"",
        "notes":"",
        "created":time .strftime ("%Y-%m-%d %H:%M"),
        }
        self ._next_id +=1 
        self ._items .append (item )
        self ._refresh ()

    def _delete_item (self ):
        if self ._selected_id is None :
            return 
        if not messagebox .askyesno ("Delete","Delete this item?"):
            return 
        self ._items =[i for i in self ._items if i ["id"]!=self ._selected_id ]
        self ._selected_id =None 
        self ._refresh ()

    def _mark_done (self ):
        if self ._selected_id is None :
            return 
        for item in self ._items :
            if item ["id"]==self ._selected_id :
                item ["status"]="Done"
                break 
        self ._refresh ()

    def _save_edit (self ):
        if self ._selected_id is None :
            return 
        for item in self ._items :
            if item ["id"]==self ._selected_id :
                item ["title"]=self ._d_title_var .get ()
                item ["priority"]=self ._d_priority_var .get ()
                item ["status"]=self ._d_status_var .get ()
                item ["tags"]=self ._d_tags_var .get ()
                item ["url"]=self ._d_url_var .get ()
                item ["notes"]=self ._notes_text .get ("1.0","end-1c")
                break 
        self ._refresh ()

    def _edit_item (self ):
        pass 

    def _on_select (self ,_ =None ):
        sel =self ._tree .selection ()
        if not sel :
            return 
        try :
            item_id =int (self ._tree .item (sel [0 ],"values")[0 ])
        except (IndexError ,ValueError ):
            return 
        self ._selected_id =item_id 
        item =next ((i for i in self ._items if i ["id"]==item_id ),None )
        if not item :
            return 
        self ._d_title_var .set (item ["title"])
        self ._d_priority_var .set (item ["priority"])
        self ._d_status_var .set (item ["status"])
        self ._d_tags_var .set (item .get ("tags",""))
        self ._d_url_var .set (item .get ("url",""))
        self ._notes_text .delete ("1.0","end")
        self ._notes_text .insert ("1.0",item .get ("notes",""))


    def _refresh (self ):
        for iid in self ._tree .get_children ():
            self ._tree .delete (iid )

        flt =self ._filter_var .get ().lower ()
        sflt =self ._stat_filter .get ()

        for item in self ._items :
            if flt and flt not in (item ["title"]+item .get ("tags","")).lower ():
                continue 
            if sflt !="All"and item ["status"]!=sflt :
                continue 
            tag =f"pri_{item ['priority']}"
            self ._tree .insert ("","end",iid =str (item ["id"]),tags =(tag ,),values =(
            item ["id"],item ["priority"],item ["status"],
            item ["title"],item ["created"],
            ))


    def _export (self ):
        path =filedialog .asksaveasfilename (
        defaultextension =".json",
        filetypes =[("JSON","*.json"),("All","*.*")],
        title ="Export Organizer",
        )
        if not path :
            return 
        with open (path ,"w",encoding ="utf-8")as f :
            json .dump (self ._items ,f ,indent =2 )
        messagebox .showinfo ("Exported",f"Saved {len (self ._items )} items to {path }")

    def _import (self ):
        path =filedialog .askopenfilename (
        filetypes =[("JSON","*.json"),("All","*.*")],
        title ="Import Organizer",
        )
        if not path :
            return 
        try :
            with open (path ,"r",encoding ="utf-8")as f :
                items =json .load (f )
            for item in items :
                item ["id"]=self ._next_id 
                self ._next_id +=1 
                self ._items .append (item )
            self ._refresh ()
        except Exception as exc :
            messagebox .showerror ("Import Failed",str (exc ))


    def add_finding (self ,title :str ,url :str ="",priority :str ="Medium",
    notes :str =""):
        item ={
        "id":self ._next_id ,
        "title":title ,
        "priority":priority ,
        "status":"Open",
        "tags":"auto",
        "url":url ,
        "notes":notes ,
        "created":time .strftime ("%Y-%m-%d %H:%M"),
        }
        self ._next_id +=1 
        self ._items .append (item )
        self ._refresh ()
