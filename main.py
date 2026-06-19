
import os 
import sys 
import traceback 


ROOT =os .path .dirname (os .path .abspath (__file__ ))
if ROOT not in sys .path :
    sys .path .insert (0 ,ROOT )

if __name__ =="__main__":
    try :
        from ui .app import LarpSuiteApp 
        app =LarpSuiteApp ()
        app .run ()
    except Exception :
        err =traceback .format_exc ()

        try :
            import tkinter as tk 
            from tkinter import messagebox 
            root =tk .Tk ()
            root .withdraw ()
            messagebox .showerror ("Larp Suite Startup Error",err )
            root .destroy ()
        except Exception :
            print (err )
        sys .exit (1 )
