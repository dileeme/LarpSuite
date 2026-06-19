
import math 
import re 
import statistics 
import tkinter as tk 
from tkinter import ttk ,filedialog 

DARK_BG ="#0D0E14"
DARK_FG ="#E8DCC8"
ACCENT ="#C8A951"


def _shannon_entropy (s :str )->float :
    if not s :
        return 0.0 
    freq ={}
    for c in s :
        freq [c ]=freq .get (c ,0 )+1 
    n =len (s )
    return -sum ((f /n )*math .log2 (f /n )for f in freq .values ())


def _effective_bits (tokens :list [str ])->dict :
    if not tokens :
        return {}

    lengths =[len (t )for t in tokens ]
    charset =set ("".join (tokens ))
    charset_size =len (charset )

    avg_len =statistics .mean (lengths )
    entropy_per_char =math .log2 (charset_size )if charset_size >1 else 0 
    effective_bits =avg_len *entropy_per_char 


    per_token =[_shannon_entropy (t )*len (t )for t in tokens ]
    avg_shannon =statistics .mean (per_token )if per_token else 0 


    max_len =max (lengths )
    pos_entropy =[]
    for i in range (max_len ):
        chars_at_pos =[t [i ]for t in tokens if i <len (t )]
        freq ={}
        for c in chars_at_pos :
            freq [c ]=freq .get (c ,0 )+1 
        n =len (chars_at_pos )
        e =-sum ((f /n )*math .log2 (f /n )for f in freq .values ())if n >1 else 0 
        pos_entropy .append (e )

    total_pos_entropy =sum (pos_entropy )


    unique =len (set (tokens ))
    duplicates =len (tokens )-unique 

    return {
    "count":len (tokens ),
    "unique":unique ,
    "duplicates":duplicates ,
    "avg_length":avg_len ,
    "charset_size":charset_size ,
    "charset":"".join (sorted (charset )),
    "effective_bits":effective_bits ,
    "avg_shannon_bits":avg_shannon ,
    "pos_entropy_total":total_pos_entropy ,
    "pos_entropy":pos_entropy ,
    "rating":_rate (effective_bits ),
    }


def _rate (bits :float )->tuple [str ,str ]:
    if bits >=128 :
        return ("STRONG","#A8B840")
    if bits >=64 :
        return ("ADEQUATE","#ffcc00")
    if bits >=32 :
        return ("WEAK","#ff8800")
    return ("VERY WEAK","#ff4444")


class SequencerTab (ttk .Frame ):
    def __init__ (self ,parent ,**kw ):
        super ().__init__ (parent ,**kw )
        self ._tokens :list [str ]=[]
        self ._build ()

    def _build (self ):
        self .columnconfigure (0 ,weight =1 )
        self .columnconfigure (1 ,weight =1 )
        self .rowconfigure (1 ,weight =1 )


        tb =ttk .Frame (self )
        tb .grid (row =0 ,column =0 ,columnspan =2 ,sticky ="ew",padx =6 ,pady =4 )

        ttk .Button (tb ,text ="▶  Analyse",command =self ._analyse ).pack (side ="left",padx =2 )
        ttk .Button (tb ,text ="Load from file",command =self ._load_file ).pack (side ="left",padx =2 )
        ttk .Button (tb ,text ="Clear",command =self ._clear ).pack (side ="left",padx =2 )

        ttk .Label (tb ,text ="Extract regex:").pack (side ="left",padx =(12 ,4 ))
        self ._regex_var =tk .StringVar (value =r"[A-Za-z0-9+/=_\-]{8,}")
        ttk .Entry (tb ,textvariable =self ._regex_var ,width =30 ).pack (side ="left")
        ttk .Button (tb ,text ="Extract",command =self ._extract_regex ).pack (side ="left",padx =4 )


        left =ttk .LabelFrame (self ,text ="Tokens  (one per line)")
        left .grid (row =1 ,column =0 ,sticky ="nsew",padx =(6 ,3 ),pady =(0 ,6 ))
        left .columnconfigure (0 ,weight =1 )
        left .rowconfigure (0 ,weight =1 )

        self ._token_text =tk .Text (left ,wrap ="none",bg ="#0A0B10",fg =DARK_FG ,
        font =("Consolas",9 ))
        tvsb =ttk .Scrollbar (left ,orient ="vertical",command =self ._token_text .yview )
        thsb =ttk .Scrollbar (left ,orient ="horizontal",command =self ._token_text .xview )
        self ._token_text .configure (yscrollcommand =tvsb .set ,xscrollcommand =thsb .set )
        self ._token_text .grid (row =0 ,column =0 ,sticky ="nsew",padx =(4 ,0 ),pady =4 )
        tvsb .grid (row =0 ,column =1 ,sticky ="ns")
        thsb .grid (row =1 ,column =0 ,sticky ="ew",padx =4 )


        right =ttk .Frame (self )
        right .grid (row =1 ,column =1 ,sticky ="nsew",padx =(3 ,6 ),pady =(0 ,6 ))
        right .columnconfigure (0 ,weight =1 )
        right .rowconfigure (1 ,weight =1 )


        summary =ttk .LabelFrame (right ,text ="Analysis Summary")
        summary .grid (row =0 ,column =0 ,sticky ="ew",pady =(0 ,6 ))
        summary .columnconfigure (1 ,weight =1 )

        self ._summary_labels :dict [str ,tk .StringVar ]={}
        rows =[
        ("Tokens analysed","count"),
        ("Unique tokens","unique"),
        ("Duplicates","duplicates"),
        ("Average length","avg_length"),
        ("Charset size","charset_size"),
        ("Effective entropy","effective_bits"),
        ("Shannon entropy","avg_shannon_bits"),
        ("Position entropy","pos_entropy_total"),
        ("Security rating","rating"),
        ]
        for i ,(label ,key )in enumerate (rows ):
            tk .Label (summary ,text =label +":",bg =DARK_BG ,fg =DARK_FG ,
            font =("Consolas",9 )).grid (row =i ,column =0 ,sticky ="w",padx =8 ,pady =2 )
            var =tk .StringVar (value ="—")
            self ._summary_labels [key ]=var 
            lbl =tk .Label (summary ,textvariable =var ,bg =DARK_BG ,
            fg ="#B8A882",font =("Consolas",9 ,"bold"))
            lbl .grid (row =i ,column =1 ,sticky ="w",padx =4 )
            if key =="rating":
                self ._rating_label =lbl 
        tk .Label (summary ,text ="",bg =DARK_BG ).grid (row =len (rows ),column =0 )


        charset_frame =ttk .LabelFrame (right ,text ="Observed Charset")
        charset_frame .grid (row =1 ,column =0 ,sticky ="nsew")
        charset_frame .columnconfigure (0 ,weight =1 )
        charset_frame .rowconfigure (0 ,weight =1 )

        self ._charset_text =tk .Text (charset_frame ,height =4 ,wrap ="word",
        bg ="#0A0B10",fg ="#A8B840",
        font =("Consolas",10 ),state ="disabled")
        self ._charset_text .grid (row =0 ,column =0 ,sticky ="nsew",padx =4 ,pady =4 )


        pos_frame =ttk .LabelFrame (right ,text ="Per-Position Entropy")
        pos_frame .grid (row =2 ,column =0 ,sticky ="ew",pady =(6 ,0 ))
        pos_frame .columnconfigure (0 ,weight =1 )

        self ._canvas =tk .Canvas (pos_frame ,height =60 ,bg ="#0A0B10",
        highlightthickness =0 )
        self ._canvas .grid (row =0 ,column =0 ,sticky ="ew",padx =4 ,pady =4 )


    def _analyse (self ):
        raw =self ._token_text .get ("1.0","end-1c")
        self ._tokens =[l .strip ()for l in raw .splitlines ()if l .strip ()]
        if not self ._tokens :
            return 
        result =_effective_bits (self ._tokens )
        self ._show_result (result )

    def _show_result (self ,r :dict ):
        rating_text ,rating_color =r ["rating"]

        self ._summary_labels ["count"].set (str (r ["count"]))
        self ._summary_labels ["unique"].set (str (r ["unique"]))
        self ._summary_labels ["duplicates"].set (str (r ["duplicates"]))
        self ._summary_labels ["avg_length"].set (f"{r ['avg_length']:.1f} chars")
        self ._summary_labels ["charset_size"].set (str (r ["charset_size"]))
        self ._summary_labels ["effective_bits"].set (f"{r ['effective_bits']:.1f} bits")
        self ._summary_labels ["avg_shannon_bits"].set (f"{r ['avg_shannon_bits']:.1f} bits")
        self ._summary_labels ["pos_entropy_total"].set (f"{r ['pos_entropy_total']:.1f} bits")
        self ._summary_labels ["rating"].set (rating_text )
        self ._rating_label .config (fg =rating_color )

        self ._charset_text .config (state ="normal")
        self ._charset_text .delete ("1.0","end")
        self ._charset_text .insert ("1.0",r ["charset"])
        self ._charset_text .config (state ="disabled")

        self ._draw_pos_entropy (r ["pos_entropy"])

    def _draw_pos_entropy (self ,entropies :list [float ]):
        self ._canvas .delete ("all")
        if not entropies :
            return 
        w =self ._canvas .winfo_width ()or 400 
        h =55 
        max_e =max (entropies )if entropies else 1 
        bar_w =max (1 ,w //len (entropies ))

        for i ,e in enumerate (entropies ):
            bar_h =int ((e /max_e )*(h -10 ))if max_e else 0 
            x0 =i *bar_w 
            x1 =x0 +bar_w -1 
            y0 =h -bar_h 

            ratio =e /max_e if max_e else 0 
            r =int (255 *(1 -ratio ))
            g =int (200 *ratio )
            colour =f"#{r :02x}{g :02x}30"
            self ._canvas .create_rectangle (x0 ,y0 ,x1 ,h ,fill =colour ,outline ="")

    def _load_file (self ):
        path =filedialog .askopenfilename (title ="Load token list")
        if path :
            content =open (path ,"r",encoding ="utf-8",errors ="replace").read ()
            self ._token_text .delete ("1.0","end")
            self ._token_text .insert ("1.0",content )

    def _extract_regex (self ):
        raw =self ._token_text .get ("1.0","end-1c")
        pat =self ._regex_var .get ()
        try :
            matches =re .findall (pat ,raw )
            self ._token_text .delete ("1.0","end")
            self ._token_text .insert ("1.0","\n".join (matches ))
        except re .error as e :
            tk .messagebox .showerror ("Regex Error",str (e ))

    def _clear (self ):
        self ._token_text .delete ("1.0","end")
        self ._tokens .clear ()
        for var in self ._summary_labels .values ():
            var .set ("—")
        self ._charset_text .config (state ="normal")
        self ._charset_text .delete ("1.0","end")
        self ._charset_text .config (state ="disabled")
        self ._canvas .delete ("all")


    def load_tokens (self ,tokens :list [str ]):
        self ._token_text .delete ("1.0","end")
        self ._token_text .insert ("1.0","\n".join (tokens ))
