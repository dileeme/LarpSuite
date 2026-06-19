
import logging 
import select 
import socket 
import ssl 
import threading 
from typing import Callable 

logging .basicConfig (
filename ="proxy_debug.log",
level =logging .DEBUG ,
format ="%(asctime)s %(levelname)s %(message)s",
)
log =logging .getLogger ("proxy")

from core .ca import get_domain_cert 
from core .history import history 
from core .http_utils import HttpRequest ,HttpResponse ,parse_request ,parse_response 

BUFFER =65536 


class InterceptFlag :

    def __init__ (self ):
        self ._active =False 
        self ._lock =threading .Lock ()

        self ._queue :dict [int ,tuple [HttpRequest ,threading .Event ,list ]]={}
        self ._qlock =threading .Lock ()
        self ._on_queued :Callable |None =None 

    @property 
    def active (self )->bool :
        with self ._lock :
            return self ._active 

    @active .setter 
    def active (self ,value :bool ):
        with self ._lock :
            self ._active =value 

    def enqueue (self ,entry_id :int ,request :HttpRequest )->HttpRequest :
        event =threading .Event ()
        modified =[request ]
        with self ._qlock :
            self ._queue [entry_id ]=(request ,event ,modified )
        if self ._on_queued :
            self ._on_queued (entry_id ,request )
        event .wait (timeout =120 )
        with self ._qlock :
            self ._queue .pop (entry_id ,None )
        return modified [0 ]

    def forward (self ,entry_id :int ,modified_request :HttpRequest |None =None ):
        with self ._qlock :
            item =self ._queue .get (entry_id )
        if item :
            _ ,event ,holder =item 
            holder [0 ]=modified_request or holder [0 ]
            event .set ()

    def drop (self ,entry_id :int ):
        with self ._qlock :
            item =self ._queue .get (entry_id )
        if item :
            _ ,event ,holder =item 
            holder [0 ]=None 
            event .set ()

    def pending (self )->list [int ]:
        with self ._qlock :
            return list (self ._queue .keys ())

    def set_on_queued (self ,cb :Callable ):
        self ._on_queued =cb 


intercept =InterceptFlag ()


class ProxyHandler (threading .Thread ):

    def __init__ (self ,client_sock :socket .socket ,addr ):
        super ().__init__ (daemon =True )
        self .client =client_sock 
        self .addr =addr 

    def run (self ):
        try :
            self ._process ()
        except Exception as e :
            log .exception (f"Handler error: {e }")
        finally :
            try :
                self .client .close ()
            except Exception :
                pass 

    def _recv_all (self ,sock :socket .socket ,timeout :float =5.0 )->bytes :
        sock .settimeout (timeout )
        data =b""
        try :
            while True :
                chunk =sock .recv (BUFFER )
                if not chunk :
                    break 
                data +=chunk 

                if b"\r\n\r\n"in data :
                    header_end =data .index (b"\r\n\r\n")+4 
                    header_str =data [:header_end ].decode (errors ="replace")

                    cl =0 
                    for line in header_str .split ("\r\n"):
                        if line .lower ().startswith ("content-length:"):
                            try :
                                cl =int (line .split (":",1 )[1 ].strip ())
                            except ValueError :
                                pass 
                    body_so_far =data [header_end :]
                    if len (body_so_far )>=cl :
                        break 
        except socket .timeout :
            pass 
        return data 

    def _process (self ):
        raw =self ._recv_all (self .client )
        if not raw :
            return 

        first_line =raw .split (b"\r\n",1 )[0 ].decode (errors ="replace")

        if first_line .upper ().startswith ("CONNECT"):
            self ._handle_https (raw )
        else :
            self ._handle_http (raw )

    def _handle_http (self ,raw :bytes ):
        req =parse_request (raw )
        if not req :
            return 


        host =req .headers .get ("Host","")
        if ":"in host :
            req .host ,port_str =host .rsplit (":",1 )
            req .port =int (port_str )
        else :
            req .host =host 
            req .port =80 


        if req .path .startswith ("http://")or req .path .startswith ("https://"):
            from urllib .parse import urlparse 
            parsed =urlparse (req .path )
            req .path =parsed .path or "/"
            if parsed .query :
                req .path +="?"+parsed .query 

        entry =history .add (req )

        if intercept .active :
            req =intercept .enqueue (entry .id ,req )
            if req is None :
                _send_drop_response (self .client )
                return 

        raw_resp =self ._forward (req .host ,req .port ,req .to_bytes (),use_ssl =False )
        resp =parse_response (raw_resp )
        history .update_response (entry .id ,resp )
        self .client .sendall (raw_resp )

    def _handle_https (self ,raw :bytes ):
        first_line =raw .split (b"\r\n",1 )[0 ].decode (errors ="replace")
        parts =first_line .split ()
        if len (parts )<2 :
            log .warning ("HTTPS: bad CONNECT line")
            return 
        host_port =parts [1 ]
        host =host_port .split (":")[0 ]
        port =int (host_port .split (":")[1 ])if ":"in host_port else 443 
        log .debug (f"CONNECT {host }:{port }")


        self .client .sendall (b"HTTP/1.1 200 Connection Established\r\n\r\n")


        cert_path ,key_path =get_domain_cert (host )
        ctx =ssl .SSLContext (ssl .PROTOCOL_TLS_SERVER )
        try :
            ctx .load_cert_chain (cert_path ,key_path )
        except Exception as e :
            log .error (f"load_cert_chain failed for {host }: {e }")
            return 


        try :
            ctx .set_alpn_protocols (["http/1.1"])
        except Exception :
            pass 


        self .client .settimeout (15 )
        try :
            tls_client =ctx .wrap_socket (self .client ,server_side =True )
        except ssl .SSLError as e :
            log .error (f"SSL wrap failed for {host }: {e }")
            return 
        except Exception as e :
            log .error (f"wrap_socket error for {host }: {e }")
            return 

        log .debug (f"TLS handshake OK for {host }, ALPN={tls_client .selected_alpn_protocol ()}")

        raw_req =self ._recv_all (tls_client )
        if not raw_req :
            log .warning (f"Empty request after TLS for {host }")
            tls_client .close ()
            return 

        log .debug (f"Request first line: {raw_req .split (b'\r\n',1 )[0 ]}")

        req =parse_request (raw_req ,host =host ,port =port ,is_https =True )
        if not req :
            log .warning (f"parse_request failed for {host }, raw={raw_req [:200 ]}")
            tls_client .close ()
            return 

        entry =history .add (req )

        if intercept .active :
            req =intercept .enqueue (entry .id ,req )
            if req is None :
                _send_drop_response (tls_client )
                tls_client .close ()
                return 

        raw_resp =self ._forward (host ,port ,req .to_bytes (),use_ssl =True )
        log .debug (f"Forward response length: {len (raw_resp )} for {host }{req .path }")
        resp =parse_response (raw_resp )
        history .update_response (entry .id ,resp )
        try :
            tls_client .sendall (raw_resp )
        except Exception as e :
            log .error (f"sendall failed for {host }: {e }")
        tls_client .close ()

    @staticmethod 
    def _forward (host :str ,port :int ,raw :bytes ,use_ssl :bool )->bytes :
        try :
            sock =socket .create_connection ((host ,port ),timeout =15 )
            if use_ssl :
                ctx =ssl .create_default_context ()
                ctx .check_hostname =False 
                ctx .verify_mode =ssl .CERT_NONE 

                try :
                    ctx .set_alpn_protocols (["http/1.1"])
                except Exception :
                    pass 
                sock =ctx .wrap_socket (sock ,server_hostname =host )
            sock .sendall (raw )
            response =b""
            sock .settimeout (15 )
            try :
                while True :
                    chunk =sock .recv (BUFFER )
                    if not chunk :
                        break 
                    response +=chunk 
            except socket .timeout :
                pass 
            sock .close ()
            return response 
        except Exception as e :
            return _error_response (str (e ))


def _send_drop_response (sock ):
    try :
        sock .sendall (b"HTTP/1.1 403 Dropped by LarpSuite\r\nContent-Length: 0\r\n\r\n")
    except Exception :
        pass 


def _error_response (msg :str )->bytes :
    body =f"LarpSuite proxy error: {msg }".encode ()
    return (
    b"HTTP/1.1 502 Bad Gateway\r\n"
    b"Content-Type: text/plain\r\n"
    b"Content-Length: "+str (len (body )).encode ()+b"\r\n\r\n"+body 
    )


class ProxyServer (threading .Thread ):

    def __init__ (self ,host :str ="127.0.0.1",port :int =8888 ):
        super ().__init__ (daemon =True )
        self .host =host 
        self .port =port 
        self ._stop =threading .Event ()
        self ._server :socket .socket |None =None 
        self .running =False 
        self .error :str =""

    def run (self ):
        try :
            self ._server =socket .socket (socket .AF_INET ,socket .SOCK_STREAM )
            self ._server .setsockopt (socket .SOL_SOCKET ,socket .SO_REUSEADDR ,1 )
            self ._server .bind ((self .host ,self .port ))
            self ._server .listen (50 )
            self ._server .settimeout (1.0 )
        except OSError as e :
            self .error =str (e )
            self .running =False 
            return 

        self .running =True 
        while not self ._stop .is_set ():
            try :
                client ,addr =self ._server .accept ()
                ProxyHandler (client ,addr ).start ()
            except socket .timeout :
                continue 
            except Exception :
                break 
        self .running =False 

    def stop (self ):
        self ._stop .set ()
        if self ._server :
            try :
                self ._server .close ()
            except Exception :
                pass 
