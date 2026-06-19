
import datetime 
import ipaddress 
import os 
import subprocess 

from cryptography import x509 
from cryptography .hazmat .primitives import hashes ,serialization 
from cryptography .hazmat .primitives .asymmetric import rsa 
from cryptography .x509 .oid import NameOID 

CA_DIR =os .path .join (os .path .dirname (__file__ ),"..","ca")
CA_CERT =os .path .join (CA_DIR ,"larp_suite_ca.crt")
CA_KEY =os .path .join (CA_DIR ,"larp_suite_ca.key")

_cert_cache :dict ={}


def _ensure_ca_dir ():
    os .makedirs (CA_DIR ,exist_ok =True )


def generate_root_ca ():
    _ensure_ca_dir ()
    key =rsa .generate_private_key (public_exponent =65537 ,key_size =2048 )

    subject =issuer =x509 .Name ([
    x509 .NameAttribute (NameOID .COUNTRY_NAME ,"IN"),
    x509 .NameAttribute (NameOID .ORGANIZATION_NAME ,"LarpSuite MITM CA"),
    x509 .NameAttribute (NameOID .COMMON_NAME ,"LarpSuite Root CA"),
    ])
    now =datetime .datetime .utcnow ()
    cert =(
    x509 .CertificateBuilder ()
    .subject_name (subject )
    .issuer_name (issuer )
    .public_key (key .public_key ())
    .serial_number (x509 .random_serial_number ())
    .not_valid_before (now )
    .not_valid_after (now +datetime .timedelta (days =3650 ))
    .add_extension (x509 .BasicConstraints (ca =True ,path_length =None ),critical =True )
    .add_extension (x509 .KeyUsage (
    digital_signature =True ,key_cert_sign =True ,crl_sign =True ,
    content_commitment =False ,key_encipherment =False ,
    data_encipherment =False ,key_agreement =False ,
    encipher_only =False ,decipher_only =False ,
    ),critical =True )
    .sign (key ,hashes .SHA256 ())
    )

    with open (CA_KEY ,"wb")as f :
        f .write (key .private_bytes (
        serialization .Encoding .PEM ,
        serialization .PrivateFormat .TraditionalOpenSSL ,
        serialization .NoEncryption (),
        ))
    with open (CA_CERT ,"wb")as f :
        f .write (cert .public_bytes (serialization .Encoding .PEM ))

    return cert ,key 


def load_root_ca ():
    if not os .path .exists (CA_CERT )or not os .path .exists (CA_KEY ):
        return generate_root_ca ()

    with open (CA_KEY ,"rb")as f :
        key =serialization .load_pem_private_key (f .read (),password =None )
    with open (CA_CERT ,"rb")as f :
        cert =x509 .load_pem_x509_certificate (f .read ())
    return cert ,key 


def get_domain_cert (hostname :str )->tuple [str ,str ]:
    if hostname in _cert_cache :
        return _cert_cache [hostname ]

    _ensure_ca_dir ()
    ca_cert ,ca_key =load_root_ca ()

    leaf_key =rsa .generate_private_key (public_exponent =65537 ,key_size =2048 )
    now =datetime .datetime .utcnow ()


    try :
        san =x509 .SubjectAlternativeName ([x509 .IPAddress (ipaddress .ip_address (hostname ))])
    except ValueError :
        san =x509 .SubjectAlternativeName ([x509 .DNSName (hostname )])

    leaf_cert =(
    x509 .CertificateBuilder ()
    .subject_name (x509 .Name ([x509 .NameAttribute (NameOID .COMMON_NAME ,hostname )]))
    .issuer_name (ca_cert .subject )
    .public_key (leaf_key .public_key ())
    .serial_number (x509 .random_serial_number ())
    .not_valid_before (now )
    .not_valid_after (now +datetime .timedelta (days =365 ))
    .add_extension (san ,critical =False )
    .sign (ca_key ,hashes .SHA256 ())
    )

    safe_name =hostname .replace (":","_").replace ("*","wildcard")
    cert_path =os .path .join (CA_DIR ,f"{safe_name }.crt")
    key_path =os .path .join (CA_DIR ,f"{safe_name }.key")

    with open (cert_path ,"wb")as f :
        f .write (leaf_cert .public_bytes (serialization .Encoding .PEM ))
    with open (key_path ,"wb")as f :
        f .write (leaf_key .private_bytes (
        serialization .Encoding .PEM ,
        serialization .PrivateFormat .TraditionalOpenSSL ,
        serialization .NoEncryption (),
        ))

    _cert_cache [hostname ]=(cert_path ,key_path )
    return cert_path ,key_path 


def install_ca_windows ()->tuple [bool ,str ]:
    if not os .path .exists (CA_CERT ):
        generate_root_ca ()
    try :
        result =subprocess .run (
        ["certutil","-addstore","Root",CA_CERT ],
        capture_output =True ,text =True ,
        )
        if result .returncode ==0 :
            return True ,"Root CA installed successfully."
        return False ,result .stderr .strip ()or result .stdout .strip ()
    except FileNotFoundError :
        return False ,"certutil not found — are you on Windows?"


def uninstall_ca_windows ()->tuple [bool ,str ]:
    try :
        result =subprocess .run (
        ["certutil","-delstore","Root","LarpSuite Root CA"],
        capture_output =True ,text =True ,
        )
        if result .returncode ==0 :
            return True ,"Root CA removed."
        return False ,result .stderr .strip ()
    except FileNotFoundError :
        return False ,"certutil not found."


def ca_cert_path ()->str :
    if not os .path .exists (CA_CERT ):
        generate_root_ca ()
    return CA_CERT 
