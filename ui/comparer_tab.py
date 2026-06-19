
import difflib 
import tkinter as tk 
from tkinter import ttk ,filedialog 

DARK_BG ="#0D0E14"
DARK_FG ="#E8DCC8"
ACCENT ="#C8A951"


class ComparerTab (ttk .Frame ):
    def __init__ (self ,parent ,**kw ):
        super ().__init__ (parent ,**kw )
        self ._build ()

    def _build (self ):
        self .columnconfigure (0 ,weight =1 )
        self .rowconfigure (1 ,weight =1 )
        self .rowconfigure (2 ,weight =1 )


        tb =ttk .Frame (self )
        tb .grid (row =0 ,column =0 ,sticky ="ew",padx =6 ,pady =4 )

        ttk .Label (tb ,text ="Compare by:").pack (side ="left")
        self ._mode_var =tk .StringVar (value ="Line")
        ttk .Radiobutton (tb ,text ="Line",variable =self ._mode_var ,value ="Line").pack (side ="left",padx =4 )
        ttk .Radiobutton (tb ,text ="Word",variable =self ._mode_var ,value ="Word").pack (side ="left")

        ttk .Button (tb ,text ="◀▶  Compare",command =self ._compare ).pack (side ="left",padx =12 )
        ttk .Button (tb ,text ="Clear",command =self ._clear ).pack (side ="left")
        ttk .Button (tb ,text ="Swap",command =self ._swap ).pack (side ="left",padx =4 )

        self ._info_var =tk .StringVar (value ="")
        ttk .Label (tb ,textvariable =self ._info_var ,foreground ="gray").pack (side ="right",padx =6 )


        input_pane =ttk .PanedWindow (self ,orient ="horizontal")
        input_pane .grid (row =1 ,column =0 ,sticky ="nsew",padx =6 ,pady =(0 ,2 ))

        self ._left_text =self ._make_input_panel (input_pane ,"Item 1")
        self ._right_text =self ._make_input_panel (input_pane ,"Item 2")


        diff_pane =ttk .PanedWindow (self ,orient ="horizontal")
        diff_pane .grid (row =2 ,column =0 ,sticky ="nsew",padx =6 ,pady =(2 ,6 ))

        self ._left_diff =self ._make_diff_panel (diff_pane ,"Item 1 (diff)")
        self ._right_diff =self ._make_diff_panel (diff_pane ,"Item 2 (diff)")


        def _sync_y (*args ):
            self ._left_diff .yview (*args )
            self ._right_diff .yview (*args )

        self ._shared_vsb =ttk .Scrollbar (self ,orient ="vertical",command =_sync_y )
        self ._shared_vsb .grid (row =2 ,column =1 ,sticky ="ns",pady =(2 ,6 ))
        self ._left_diff .configure (yscrollcommand =self ._shared_vsb .set )
        self ._right_diff .configure (yscrollcommand =self ._shared_vsb .set )

    def _make_input_panel (self ,parent ,title :str )->tk .Text :
        frame =ttk .LabelFrame (parent ,text =title )
        parent .add (frame ,weight =1 )
        frame .columnconfigure (0 ,weight =1 )
        frame .rowconfigure (1 ,weight =1 )

        btn_bar =ttk .Frame (frame )
        btn_bar .grid (row =0 ,column =0 ,sticky ="ew",padx =4 ,pady =(4 ,0 ))
        text_widget =tk .Text .__new__ (tk .Text )

        def _load ():
            path =filedialog .askopenfilename (title =f"Load {title }")
            if path :
                try :
                    content =open (path ,"r",encoding ="utf-8",errors ="replace").read ()
                    text_widget .delete ("1.0","end")
                    text_widget .insert ("1.0",content )
                except Exception as e :
                    pass 

        ttk .Button (btn_bar ,text ="Load File…",command =_load ).pack (side ="left",padx =2 )
        ttk .Button (btn_bar ,text ="Clear",
        command =lambda :text_widget .delete ("1.0","end")).pack (side ="left")

        text_widget .__init__ (frame ,wrap ="none",bg ="#0A0B10",fg =DARK_FG ,
        font =("Consolas",9 ),undo =True )
        hsb =ttk .Scrollbar (frame ,orient ="horizontal",command =text_widget .xview )
        text_widget .configure (xscrollcommand =hsb .set )
        text_widget .grid (row =1 ,column =0 ,sticky ="nsew",padx =4 ,pady =4 )
        hsb .grid (row =2 ,column =0 ,sticky ="ew",padx =4 )
        return text_widget 

    def _make_diff_panel (self ,parent ,title :str )->tk .Text :
        frame =ttk .LabelFrame (parent ,text =title )
        parent .add (frame ,weight =1 )
        frame .columnconfigure (0 ,weight =1 )
        frame .rowconfigure (0 ,weight =1 )

        widget =tk .Text (frame ,wrap ="none",bg ="#0A0B10",fg =DARK_FG ,
        font =("Consolas",9 ),state ="disabled")
        hsb =ttk .Scrollbar (frame ,orient ="horizontal",command =widget .xview )
        widget .configure (xscrollcommand =hsb .set )
        widget .grid (row =0 ,column =0 ,sticky ="nsew",padx =(4 ,0 ),pady =4 )
        hsb .grid (row =1 ,column =0 ,sticky ="ew",padx =4 )

        widget .tag_configure ("add",background ="#151E0A",foreground ="#A8B840")
        widget .tag_configure ("remove",background ="#1E0808",foreground ="#ff6666")
        widget .tag_configure ("equal",foreground ="#7A6E52")
        widget .tag_configure ("header",foreground =ACCENT ,font =("Consolas",9 ,"bold"))
        return widget 


    def _compare (self ):
        a =self ._left_text .get ("1.0","end-1c")
        b =self ._right_text .get ("1.0","end-1c")

        if self ._mode_var .get ()=="Line":
            a_seq =a .splitlines (keepends =True )
            b_seq =b .splitlines (keepends =True )
        else :
            a_seq =a .split ()
            b_seq =b .split ()

        matcher =difflib .SequenceMatcher (None ,a_seq ,b_seq )
        opcodes =matcher .get_opcodes ()

        self ._clear_diff ()
        adds =removes =changes =0 

        for tag_op ,i1 ,i2 ,j1 ,j2 in opcodes :
            a_chunk ="".join (a_seq [i1 :i2 ])
            b_chunk ="".join (b_seq [j1 :j2 ])

            if tag_op =="equal":
                self ._append_diff (self ._left_diff ,a_chunk ,"equal")
                self ._append_diff (self ._right_diff ,b_chunk ,"equal")
            elif tag_op =="replace":
                self ._append_diff (self ._left_diff ,a_chunk ,"remove")
                self ._append_diff (self ._right_diff ,b_chunk ,"add")
                changes +=1 
            elif tag_op =="delete":
                self ._append_diff (self ._left_diff ,a_chunk ,"remove")
                self ._append_diff (self ._right_diff ,"","remove")
                removes +=1 
            elif tag_op =="insert":
                self ._append_diff (self ._left_diff ,"","add")
                self ._append_diff (self ._right_diff ,b_chunk ,"add")
                adds +=1 

        ratio =matcher .ratio ()
        self ._info_var .set (
        f"Similarity: {ratio *100 :.1f}%  |  "
        f"+{adds } inserts  -{removes } deletes  ~{changes } changes"
        )

    def _append_diff (self ,widget :tk .Text ,text :str ,tag :str ):
        widget .config (state ="normal")
        if text :
            widget .insert ("end",text ,tag )
        widget .config (state ="disabled")

    def _clear_diff (self ):
        for w in (self ._left_diff ,self ._right_diff ):
            w .config (state ="normal")
            w .delete ("1.0","end")
            w .config (state ="disabled")

    def _clear (self ):
        for w in (self ._left_text ,self ._right_text ):
            w .delete ("1.0","end")
        self ._clear_diff ()
        self ._info_var .set ("")

    def _swap (self ):
        a =self ._left_text .get ("1.0","end-1c")
        b =self ._right_text .get ("1.0","end-1c")
        self ._left_text .delete ("1.0","end")
        self ._left_text .insert ("1.0",b )
        self ._right_text .delete ("1.0","end")
        self ._right_text .insert ("1.0",a )


    def load_left (self ,text :str ):
        self ._left_text .delete ("1.0","end")
        self ._left_text .insert ("1.0",text )

    def load_right (self ,text :str ):
        self ._right_text .delete ("1.0","end")
        self ._right_text .insert ("1.0",text )
