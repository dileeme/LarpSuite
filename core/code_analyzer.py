
import ast 
import os 
import re 
import json 
from dataclasses import dataclass ,field 
from pathlib import Path 


LANG_MAP :dict [str ,str ]={
".py":"Python",".js":"JavaScript",".ts":"TypeScript",
".tsx":"TSX",".jsx":"JSX",".java":"Java",
".cs":"C#",".cpp":"C++",".cc":"C++",
".c":"C",".h":"C/C++ Header",".hpp":"C++ Header",
".go":"Go",".rs":"Rust",".php":"PHP",
".rb":"Ruby",".kt":"Kotlin",".swift":"Swift",
".html":"HTML",".css":"CSS",".sql":"SQL",
".sh":"Shell",".bat":"Batch",".ps1":"PowerShell",
".yaml":"YAML",".yml":"YAML",".json":"JSON",
".xml":"XML",".md":"Markdown",".env":"Env file",
".toml":"TOML",".ini":"INI",".cfg":"Config",
".conf":"Config",".config":"Config",
}

SKIP_DIRS ={
".git","__pycache__","node_modules",".venv","venv",
"dist","build",".idea",".vscode","coverage",".pytest_cache",
}

BINARY_EXTS ={
".png",".jpg",".jpeg",".gif",".ico",".svg",
".woff",".woff2",".ttf",".eot",".otf",
".zip",".tar",".gz",".bz2",".7z",".rar",
".exe",".dll",".so",".dylib",".bin",".obj",".o",
".pdf",".doc",".docx",".xls",".xlsx",
".pyc",".pyo",".class",
}


@dataclass 
class Finding :
    severity :str 
    confidence :str 
    category :str 
    file :str 
    line :int 
    snippet :str 
    detail :str 
    cwe :str =""


@dataclass 
class AnalysisResult :
    root :str 
    total_files :int =0 
    total_dirs :int =0 
    total_lines :int =0 
    blank_lines :int =0 
    comment_lines :int =0 
    lines_by_lang :dict =field (default_factory =dict )
    files_by_lang :dict =field (default_factory =dict )
    findings :list =field (default_factory =list )
    errors :list =field (default_factory =list )


@dataclass 
class Rule :
    severity :str 
    confidence :str 
    category :str 
    pattern :re .Pattern 
    detail :str 
    cwe :str =""

    suppress_if :list =field (default_factory =list )
    context_lines :int =3 


_RULES :list [Rule ]=[]


def _rule (severity ,confidence ,category ,pattern ,detail ,cwe ="",
suppress_if =None ,flags =re .I ,context =3 ):
    _RULES .append (Rule (
    severity =severity ,
    confidence =confidence ,
    category =category ,
    pattern =re .compile (pattern ,flags ),
    detail =detail ,
    cwe =cwe ,
    suppress_if =[re .compile (s ,re .I )for s in (suppress_if or [])],
    context_lines =context ,
    ))


_rule ("CRITICAL","HIGH","Hardcoded Secret",
r"-----BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY-----",
"Private key embedded in source — remove immediately",
cwe ="CWE-321")

_rule ("CRITICAL","HIGH","Hardcoded Secret",
r"\bAKIA[0-9A-Z]{16}\b",
"AWS Access Key ID in source",
cwe ="CWE-798")

_rule ("HIGH","HIGH","Hardcoded Secret",
r"\bghp_[A-Za-z0-9]{36}\b",
"GitHub personal access token",
cwe ="CWE-798")

_rule ("HIGH","HIGH","Hardcoded Secret",
r"\b(xox[baprs]-[0-9A-Za-z\-]{10,})\b",
"Slack token in source",
cwe ="CWE-798")

_rule ("HIGH","MEDIUM","Hardcoded Secret",
r"""(password|passwd|pwd|secret|auth[_\-]?token|api[_\-]?key|apikey)\s*=\s*["'][^"']{6,}["']""",
"Hardcoded credential — move to environment variable or secrets manager",
cwe ="CWE-798",

suppress_if =[
r"os\.environ|getenv|dotenv|example|placeholder|changeme|your[_\-]?key|<.*>|test.*=.*test",
])

_rule ("HIGH","MEDIUM","Hardcoded Secret",
r"(stripe_|stripe[_\-]?secret|sk_live_)[A-Za-z0-9]{20,}",
"Stripe secret key in source",
cwe ="CWE-798")


_rule ("MEDIUM","HIGH","API Placeholder",
r"\b(TODO|FIXME|HACK|XXX)\b.*?(key|token|secret|password|auth|api)",
"Security-sensitive TODO/FIXME — resolve before deployment",
cwe ="CWE-546")

_rule ("LOW","HIGH","API Placeholder",
r"https?://(localhost|127\.0\.0\.1|0\.0\.0\.0)(:\d+)?[/\w\-]*",
"Hardcoded localhost URL",
suppress_if =[r"#.*localhost",r"//.*localhost",r"test|spec|example"])

_rule ("LOW","MEDIUM","API Placeholder",
r"https?://[a-z0-9\-]+\.(example|test|staging|dev)\.[a-z]{2,}",
"Dev/staging URL hardcoded in source")


_rule ("HIGH","MEDIUM","SQL Injection",
r'(execute|query|raw|cursor\.execute)\s*\(\s*[f"\'].*?(SELECT|INSERT|UPDATE|DELETE|DROP|UNION)',
"SQL query with string formatting — use parameterised queries",
cwe ="CWE-89",
suppress_if =[r"#.*nosec",r"#.*noqa"])

_rule ("HIGH","MEDIUM","SQL Injection",
r'["\']\s*\+\s*(user|input|param|request\.|query\[|data\[|args\[)',
"String concatenation into query — potential SQL injection sink",
cwe ="CWE-89")

_rule ("MEDIUM","LOW","SQL Injection",
r'(SELECT|INSERT|UPDATE|DELETE).*\.format\s*\(',
".format() used in SQL string — parameterise the query",
cwe ="CWE-89",
suppress_if =[r"#.*nosec"])


_rule ("HIGH","MEDIUM","XSS",
r'innerHTML\s*[+]?=\s*(?!["\']\s*["\'])',
"innerHTML assignment with non-literal value — XSS risk",
cwe ="CWE-79",
suppress_if =[r"DOMPurify|sanitize|escapeHTML|encodeHTML"])

_rule ("HIGH","MEDIUM","XSS",
r'document\.write\s*\(',
"document.write() — XSS risk if argument contains user data",
cwe ="CWE-79",
suppress_if =[r"document\.write\s*\(\s*[\"']"])

_rule ("MEDIUM","LOW","XSS",
r'dangerouslySetInnerHTML',
"React dangerouslySetInnerHTML — ensure value is sanitised",
cwe ="CWE-79",
suppress_if =[r"DOMPurify|sanitize"])


_rule ("CRITICAL","HIGH","Command Injection",
r'(os\.system|subprocess\.(call|run|Popen|check_output))\s*\(\s*[f"\']',
"Shell command built with f-string — command injection risk",
cwe ="CWE-78",
suppress_if =[r"#.*nosec"])

_rule ("HIGH","HIGH","Command Injection",
r'\bshell\s*=\s*True',
"subprocess with shell=True — avoid or strictly sanitise all inputs",
cwe ="CWE-78",
suppress_if =[r"shlex\.quote|shlex\.split"])

_rule ("HIGH","MEDIUM","Command Injection",
r'\b(eval|exec)\s*\(',
"Dynamic code execution — dangerous if any input is user-controlled",
cwe ="CWE-95",
suppress_if =[r"ast\.literal_eval",r"#.*nosec"])

_rule ("HIGH","MEDIUM","Command Injection",
r'Runtime\.getRuntime\(\)\.exec\s*\(',
"Java Runtime.exec() — potential command injection",
cwe ="CWE-78")


_rule ("HIGH","MEDIUM","Path Traversal",
r'\.\./|\.\.[/\\\\]',
"Path traversal sequence — validate and canonicalise file paths",
cwe ="CWE-22",
suppress_if =[r"os\.path\.abspath|realpath|normpath|safe_join"])

_rule ("MEDIUM","MEDIUM","Path Traversal",
r'open\s*\([^)]*(?:request\.|param|user_input|args\[|data\[)',
"File open with potentially user-controlled path",
cwe ="CWE-22",
suppress_if =[r"os\.path\.abspath|realpath|safe_join|allowlist|whitelist"])


_rule ("HIGH","HIGH","Buffer Overflow",
r'\bgets\s*\(',
"gets() is unsafe — always use fgets()",
cwe ="CWE-120")

_rule ("HIGH","HIGH","Buffer Overflow",
r'\bsprintf\s*\(',
"sprintf() without length limit — use snprintf()",
cwe ="CWE-120",
suppress_if =[r"\bsnprintf\b"])

_rule ("HIGH","HIGH","Buffer Overflow",
r'\bstrcpy\s*\(',
"strcpy() without bounds check — use strncpy() / strlcpy()",
cwe ="CWE-120")

_rule ("MEDIUM","HIGH","Buffer Overflow",
r'\bstrcat\s*\(',
"strcat() without bounds check — use strncat()",
cwe ="CWE-120")

_rule ("MEDIUM","MEDIUM","Integer Overflow",
r'\(int\)\s*(strlen|sizeof)\s*\(',
"Casting size_t to int — may overflow on large inputs",
cwe ="CWE-190")


_rule ("MEDIUM","LOW","Memory Leak",
r'\bmalloc\s*\(|\bcalloc\s*\(|\brealloc\s*\(',
"Manual heap allocation — verify corresponding free() on all paths",
cwe ="CWE-401",
suppress_if =[r"\bfree\s*\("])

_rule ("MEDIUM","LOW","Memory Leak",
r'\b(getInputStream|getOutputStream|openConnection)\s*\(',
"Java I/O stream opened — ensure closed in finally block",
cwe ="CWE-404",
suppress_if =[r"try.with.resources|\.close\(\)|AutoCloseable"])

_rule ("LOW","LOW","Memory Leak",
r'\b(createConnection|pool\.connect|getConnection)\s*\(',
"DB connection acquired — verify release on all code paths",
cwe ="CWE-404",
suppress_if =[r"\.release\(\)|\.close\(\)|\.end\(\)|pool\.query"])


_rule ("HIGH","HIGH","Insecure Crypto",
r'\b(MD5|SHA1|SHA-1)\s*[\(\.]',
"Weak hash algorithm — use SHA-256 or stronger",
cwe ="CWE-327",
suppress_if =[r"non.?cryptographic|checksum|etag|cache"])

_rule ("HIGH","HIGH","Insecure Crypto",
r'\b(DES|3DES|Triple.?DES|RC4|RC2|Blowfish)\b',
"Deprecated cipher — use AES-256-GCM",
cwe ="CWE-327")

_rule ("MEDIUM","MEDIUM","Insecure Crypto",
r'random\.(random|randint|choice|uniform)\s*\(',
"Non-CSPRNG used — use `secrets` module for security-sensitive values",
cwe ="CWE-338",
suppress_if =[r"import secrets|os\.urandom|SystemRandom"])

_rule ("HIGH","HIGH","Insecure Crypto",
r'ssl\._create_unverified_context|verify\s*=\s*False',
"TLS certificate verification disabled",
cwe ="CWE-295")

_rule ("MEDIUM","MEDIUM","Insecure Crypto",
r'ECB\b|\.MODE_ECB',
"AES-ECB mode is deterministic and reveals patterns — use GCM or CBC with IV",
cwe ="CWE-327")


_rule ("MEDIUM","MEDIUM","Sensitive Data Exposure",
r'(print|console\.log|System\.out\.print|logger\.(debug|info|warn|error))\s*\(.*\b(password|token|secret|key|credential)\b',
"Sensitive value may appear in logs",
cwe ="CWE-532",
suppress_if =[r"redact|mask|\*+|len\(|hash\("])

_rule ("HIGH","MEDIUM","Sensitive Data Exposure",
r'(response\.(json|send|write)|res\.json|render)\s*\(.*\b(password|passwd|pwd|secret)\b',
"Credential field returned in API response",
cwe ="CWE-200")


_rule ("HIGH","MEDIUM","SSRF",
r'(requests\.(get|post|put)|urllib\.(request|urlopen)|fetch|axios)\s*\(\s*(?:f["\']|["\']?\s*\+)',
"HTTP request to dynamic URL — validate against an allowlist (SSRF risk)",
cwe ="CWE-918",
suppress_if =[r"allowlist|whitelist|urlparse|urlsplit|validate_url"])


_rule ("HIGH","MEDIUM","XXE",
r'(etree\.parse|minidom\.parse|SAXParser|XMLReader|DocumentBuilder)\s*\(',
"XML parser — ensure external entity processing is disabled",
cwe ="CWE-611",
suppress_if =[r"resolve_entities\s*=\s*False|XMLParser.*resolve_entities|defusedxml"])


_rule ("HIGH","MEDIUM","Insecure Deserialization",
r'\bpickle\.(loads?|Unpickler)\s*\(',
"pickle.load() with untrusted data — use JSON or sign the payload",
cwe ="CWE-502",
suppress_if =[r"#.*trusted|#.*internal"])

_rule ("HIGH","MEDIUM","Insecure Deserialization",
r'\byaml\.load\s*\(',
"yaml.load() without Loader=yaml.SafeLoader — arbitrary code execution",
cwe ="CWE-502",
suppress_if =[r"SafeLoader|safe_load"])

_rule ("MEDIUM","MEDIUM","Insecure Deserialization",
r'ObjectInputStream|readObject\s*\(',
"Java deserialization — validate class whitelist",
cwe ="CWE-502")


_rule ("MEDIUM","LOW","Open Redirect",
r'(redirect|location\.href|window\.location)\s*[=\(]\s*(?:request\.|param|args\[|query\[)',
"Redirect target derived from user input — validate against allowlist",
cwe ="CWE-601")


_rule ("MEDIUM","LOW","Authentication",
r'(DEBUG\s*=\s*True|debug\s*=\s*true)',
"Debug mode enabled — disable in production",
cwe ="CWE-94")

_rule ("HIGH","MEDIUM","Authentication",
r'(SECRET_KEY|JWT_SECRET|SESSION_SECRET)\s*=\s*["\'][^"\']{0,20}["\']',
"Short or hardcoded secret key for JWT/session — use a long random value",
cwe ="CWE-798")


_rule ("INFO","HIGH","Security Suppression",
r'#\s*(nosec|noqa)\b',
"Security/lint suppression — verify this suppression is intentional",
cwe ="")


_TAINT_SOURCES ={

"request.args","request.form","request.json","request.data",
"request.values","request.cookies","request.headers",
"request.get_json","request.files",

"request.GET","request.POST","request.body",
"request.META","request.FILES",

"Body","Query","Path","Header","Cookie",
"input","sys.argv","os.environ.get",
}


_TAINT_SINKS ={
"os.system":("CRITICAL","Command Injection","CWE-78"),
"subprocess.call":("CRITICAL","Command Injection","CWE-78"),
"subprocess.run":("CRITICAL","Command Injection","CWE-78"),
"subprocess.Popen":("CRITICAL","Command Injection","CWE-78"),
"eval":("HIGH","Command Injection","CWE-95"),
"exec":("HIGH","Command Injection","CWE-95"),
"open":("MEDIUM","Path Traversal","CWE-22"),
"cursor.execute":("HIGH","SQL Injection","CWE-89"),
"engine.execute":("HIGH","SQL Injection","CWE-89"),
"connection.execute":("HIGH","SQL Injection","CWE-89"),
"render_template_string":("HIGH","SSTI","CWE-94"),
"pickle.loads":("HIGH","Insecure Deserialization","CWE-502"),
"yaml.load":("HIGH","Insecure Deserialization","CWE-502"),
}


_AUTH_DECORATORS ={
"login_required","jwt_required","requires_auth",
"auth_required","token_required","permission_required",
"admin_required","staff_member_required","verify_token",
"authenticated","authorize","check_permissions",
}


class _PythonASTVisitor (ast .NodeVisitor ):

    def __init__ (self ,source_lines :list [str ],rel_path :str ):
        self ._lines =source_lines 
        self ._path =rel_path 
        self ._tainted :set [str ]=set ()
        self .findings :list [Finding ]=[]

    def _snippet (self ,node )->str :
        try :
            return self ._lines [node .lineno -1 ].strip ()[:200 ]
        except IndexError :
            return ""

    def _add (self ,node ,severity ,confidence ,category ,detail ,cwe =""):
        self .findings .append (Finding (
        severity =severity ,confidence =confidence ,category =category ,
        file =self ._path ,line =node .lineno ,
        snippet =self ._snippet (node ),detail =detail ,cwe =cwe ,
        ))


    def visit_Assign (self ,node :ast .Assign ):
        if _is_tainted_expr (node .value ,self ._tainted ):
            for target in node .targets :
                if isinstance (target ,ast .Name ):
                    self ._tainted .add (target .id )
        self .generic_visit (node )

    def visit_AnnAssign (self ,node :ast .AnnAssign ):
        if node .value and _is_tainted_expr (node .value ,self ._tainted ):
            if isinstance (node .target ,ast .Name ):
                self ._tainted .add (node .target .id )
        self .generic_visit (node )


    def visit_Call (self ,node :ast .Call ):
        sink_name =_call_name (node )
        if sink_name in _TAINT_SINKS :

            all_args =list (node .args )+[kw .value for kw in node .keywords ]
            if any (_is_tainted_expr (a ,self ._tainted )for a in all_args ):
                sev ,cat ,cwe =_TAINT_SINKS [sink_name ]
                self ._add (node ,sev ,"HIGH",cat ,
                f"Tainted user-input reaches {sink_name }() — high-confidence injection risk",
                cwe =cwe )

        self .generic_visit (node )


    def visit_FunctionDef (self ,node :ast .FunctionDef ):
        self ._check_route_auth (node )
        self .generic_visit (node )

    visit_AsyncFunctionDef =visit_FunctionDef 

    def _check_route_auth (self ,node ):
        decorator_names :set [str ]=set ()
        has_route =False 

        for dec in node .decorator_list :
            name =_decorator_name (dec )
            decorator_names .add (name )

            if re .search (r'\.(route|get|post|put|delete|patch)\s*\(',name )or name in ("app.route","router.get","router.post",
            "blueprint.route","bp.route"):
                has_route =True 
            if re .search (r'(route|get|post|put|delete|patch)$',name ):
                has_route =True 

        if not has_route :
            return 


        has_auth =any (
        any (auth in dname for auth in _AUTH_DECORATORS )
        for dname in decorator_names 
        )

        if not has_auth :

            public_hints ={"login","logout","register","health","ping",
            "static","favicon","index","home","public"}
            fn_name =node .name .lower ()
            if any (hint in fn_name for hint in public_hints ):
                return 

            self ._add (node ,"MEDIUM","MEDIUM","Authentication",
            f"Route '{node .name }' has no authentication decorator — verify access control is enforced",
            cwe ="CWE-306")


def _call_name (node :ast .Call )->str :
    if isinstance (node .func ,ast .Name ):
        return node .func .id 
    if isinstance (node .func ,ast .Attribute ):
        return f"{_expr_name (node .func .value )}.{node .func .attr }"
    return ""


def _expr_name (node )->str :
    if isinstance (node ,ast .Name ):
        return node .id 
    if isinstance (node ,ast .Attribute ):
        return f"{_expr_name (node .value )}.{node .attr }"
    return ""


def _decorator_name (dec )->str :
    if isinstance (dec ,ast .Name ):
        return dec .id 
    if isinstance (dec ,ast .Attribute ):
        return f"{_expr_name (dec .value )}.{dec .attr }"
    if isinstance (dec ,ast .Call ):
        return _decorator_name (dec .func )
    return ""


def _is_tainted_expr (node ,tainted :set [str ])->bool :
    if isinstance (node ,ast .Name ):
        return node .id in tainted 
    if isinstance (node ,ast .Attribute ):
        full =_expr_name (node )
        return (full in _TAINT_SOURCES or 
        any (full .startswith (src )for src in _TAINT_SOURCES )or 
        _expr_name (node .value )in tainted )
    if isinstance (node ,(ast .BinOp ,ast .BoolOp )):
        children =[]
        if isinstance (node ,ast .BinOp ):
            children =[node .left ,node .right ]
        else :
            children =node .values 
        return any (_is_tainted_expr (c ,tainted )for c in children )
    if isinstance (node ,ast .Call ):
        name =_call_name (node )
        if name in _TAINT_SOURCES or any (name .startswith (s )for s in _TAINT_SOURCES ):
            return True 
        return any (_is_tainted_expr (a ,tainted )for a in node .args )
    if isinstance (node ,ast .JoinedStr ):
        return any (_is_tainted_expr (v ,tainted )
        for v in node .values if isinstance (v ,ast .FormattedValue ))
    if isinstance (node ,ast .FormattedValue ):
        return _is_tainted_expr (node .value ,tainted )
    if isinstance (node ,(ast .List ,ast .Tuple ,ast .Set )):
        return any (_is_tainted_expr (e ,tainted )for e in node .elts )
    return False 


def _analyse_python_ast (text :str ,rel_path :str ,
source_lines :list [str ])->list [Finding ]:
    try :
        tree =ast .parse (text )
    except SyntaxError :
        return []
    visitor =_PythonASTVisitor (source_lines ,rel_path )
    visitor .visit (tree )
    return visitor .findings 


_CONFIG_RULES :list [tuple [str ,str ,re .Pattern ,str ,str ]]=[]


def _crule (severity ,category ,pattern ,detail ,cwe ="",flags =re .I ):
    _CONFIG_RULES .append ((severity ,category ,re .compile (pattern ,flags ),detail ,cwe ))


_crule ("HIGH","Hardcoded Secret",
r"^(SECRET_KEY|JWT_SECRET|DATABASE_URL|DB_PASSWORD|REDIS_URL)\s*=\s*.{6,}",
"Sensitive value in .env file — never commit .env to version control","CWE-312")

_crule ("MEDIUM","Configuration",
r"^DEBUG\s*=\s*(true|1|yes|on)\b",
"Debug mode enabled in config — disable for production","CWE-94")

_crule ("HIGH","Configuration",
r"^ALLOWED_HOSTS\s*=\s*\[\s*[\"']\*[\"']",
"Django ALLOWED_HOSTS = ['*'] — restricts to known hostnames in production","CWE-183")


_crule ("HIGH","Hardcoded Secret",
r"(MYSQL_ROOT_PASSWORD|POSTGRES_PASSWORD|MONGO_INITDB_ROOT_PASSWORD)\s*[:=]\s*\S+",
"Database root password hardcoded in docker-compose","CWE-798")

_crule ("HIGH","Configuration",
r"privileged\s*:\s*true",
"Docker container running as privileged — reduces isolation","CWE-269")

_crule ("MEDIUM","Configuration",
r"network_mode\s*:\s*host",
"Docker container using host network mode — bypasses network isolation")


_crule ("HIGH","Configuration",
r'<customErrors\s+mode\s*=\s*"Off"',
"ASP.NET custom errors off — detailed errors exposed to users","CWE-209")

_crule ("HIGH","Configuration",
r'<compilation\s[^>]*debug\s*=\s*"true"',
"ASP.NET compilation debug=true — disable for production","CWE-94")

_crule ("HIGH","Hardcoded Secret",
r'connectionString\s*=\s*"[^"]{10,}"',
"Connection string in config — use encrypted config or secrets manager","CWE-312")


_crule ("HIGH","Configuration",
r"tls\s*:\s*false|ssl\s*:\s*false|insecure\s*:\s*true",
"TLS/SSL disabled in configuration","CWE-295")

_crule ("MEDIUM","Configuration",
r"cors.*origins.*['\"]?\*['\"]?|allow_origins.*['\"]?\*['\"]?",
"CORS wildcard origin in config — restrict to known domains","CWE-942")


CONFIG_FILENAMES ={
".env","docker-compose.yml","docker-compose.yaml",
"web.config","app.config","appsettings.json",
"application.yml","application.yaml",
"settings.py","local_settings.py","config.py",
"config.yml","config.yaml","config.json",
}


def _analyse_config (text :str ,rel_path :str ,
source_lines :list [str ])->list [Finding ]:
    findings =[]
    for lineno ,line in enumerate (source_lines ,start =1 ):
        for severity ,category ,pattern ,detail ,cwe in _CONFIG_RULES :
            if pattern .search (line ):
                findings .append (Finding (
                severity =severity ,confidence ="HIGH",category =category ,
                file =rel_path ,line =lineno ,
                snippet =line .strip ()[:200 ],detail =detail ,cwe =cwe ,
                ))
                break 
    return findings 


_KNOWN_VULNS :list [tuple [str ,re .Pattern ,str ,str ,str ]]=[
("django",re .compile (r"^[123]\."),
"Django <4.x has known CVEs — upgrade to 4.2+ LTS","HIGH",""),
("flask",re .compile (r"^0\.|^1\.[01]\."),
"Flask <1.1 has known security issues — upgrade","MEDIUM",""),
("requests",re .compile (r"^2\.[01]\d\."),
"Old requests version — may lack TLS verification fixes","LOW",""),
("pyyaml",re .compile (r"^[0-4]\."),
"PyYAML <5.1 allows arbitrary code via yaml.load() — upgrade","HIGH","CWE-502"),
("pillow",re .compile (r"^[0-8]\."),
"Old Pillow version — multiple image parsing CVEs","MEDIUM",""),
("cryptography",re .compile (r"^[0-2]\d\."),
"Old cryptography package — upgrade to latest for security patches","MEDIUM",""),
("urllib3",re .compile (r"^1\.[12]\d\."),
"urllib3 <1.26 has CRLF injection and redirect issues","MEDIUM",""),
("lodash",re .compile (r"^[0-3]\.|^4\.[01]\d\."),
"Lodash <4.17.21 has prototype pollution CVE","HIGH","CWE-1321"),
("express",re .compile (r"^[0-3]\."),
"Express <4.x is EOL — upgrade","HIGH",""),
("axios",re .compile (r"^0\.[01]\d\."),
"Old axios — CSRF and SSRF vulnerabilities in <0.21.1","MEDIUM",""),
("jquery",re .compile (r"^[123]\.[0-2]\."),
"jQuery <3.5 has XSS vulnerabilities","HIGH","CWE-79"),
("log4j",re .compile (r"^2\.[0-9]\.(?!1[5-9]|[2-9]\d)"),
"Log4j <2.15 — Log4Shell RCE (CVE-2021-44228)","CRITICAL","CWE-917"),
]


def _analyse_requirements (text :str ,rel_path :str )->list [Finding ]:
    findings =[]
    for lineno ,raw in enumerate (text .splitlines (),start =1 ):
        line =raw .strip ()
        if not line or line .startswith ("#"):
            continue 

        m =re .match (r"^([A-Za-z0-9_\-\.]+)\s*[=><!^~]+\s*([0-9][^\s,;#]*)",line )
        if not m :
            continue 
        pkg ,ver =m .group (1 ).lower (),m .group (2 )
        for vuln_pkg ,ver_re ,detail ,severity ,cwe in _KNOWN_VULNS :
            if pkg ==vuln_pkg and ver_re .match (ver ):
                findings .append (Finding (
                severity =severity ,confidence ="MEDIUM",
                category ="Vulnerable Dependency",
                file =rel_path ,line =lineno ,
                snippet =line [:200 ],detail =detail ,cwe =cwe ,
                ))
    return findings 


def _analyse_package_json (text :str ,rel_path :str )->list [Finding ]:
    findings =[]
    try :
        data =json .loads (text )
    except json .JSONDecodeError :
        return findings 

    all_deps :dict [str ,str ]={}
    all_deps .update (data .get ("dependencies",{}))
    all_deps .update (data .get ("devDependencies",{}))

    for pkg ,ver_spec in all_deps .items ():
        ver =ver_spec .lstrip ("^~>=<v").split (" ")[0 ]
        for vuln_pkg ,ver_re ,detail ,severity ,cwe in _KNOWN_VULNS :
            if pkg .lower ()==vuln_pkg and ver and ver [0 ].isdigit ()and ver_re .match (ver ):
                findings .append (Finding (
                severity =severity ,confidence ="MEDIUM",
                category ="Vulnerable Dependency",
                file =rel_path ,line =1 ,
                snippet =f'"{pkg }": "{ver_spec }"',detail =detail ,cwe =cwe ,
                ))
    return findings 


def _run_regex_rules (lines :list [str ],rel_path :str )->list [Finding ]:
    findings =[]
    n =len (lines )
    for lineno ,line in enumerate (lines ,start =1 ):
        for rule in _RULES :
            if not rule .pattern .search (line ):
                continue 


            lo =max (0 ,lineno -1 -rule .context_lines )
            hi =min (n ,lineno -1 +rule .context_lines +1 )
            ctx ="\n".join (lines [lo :hi ])


            if any (sp .search (ctx )for sp in rule .suppress_if ):
                continue 

            findings .append (Finding (
            severity =rule .severity ,
            confidence =rule .confidence ,
            category =rule .category ,
            file =rel_path ,
            line =lineno ,
            snippet =line .strip ()[:200 ],
            detail =rule .detail ,
            cwe =rule .cwe ,
            ))
            break 

    return findings 


def analyse_directory (root :str ,progress_cb =None )->AnalysisResult :
    result =AnalysisResult (root =root )
    root_path =Path (root )

    all_files :list [Path ]=[]
    for dirpath ,dirnames ,filenames in os .walk (root ):
        dirnames [:]=[d for d in dirnames if d not in SKIP_DIRS ]
        result .total_dirs +=len (dirnames )
        for fname in filenames :
            all_files .append (Path (dirpath )/fname )

    result .total_files =len (all_files )

    for idx ,fpath in enumerate (all_files ):
        if progress_cb :
            progress_cb (str (fpath ),idx +1 ,result .total_files )

        ext =fpath .suffix .lower ()
        name =fpath .name .lower ()
        lang =LANG_MAP .get (ext ,"Other")

        result .files_by_lang [lang ]=result .files_by_lang .get (lang ,0 )+1 

        if ext in BINARY_EXTS :
            continue 

        try :
            text =fpath .read_text (encoding ="utf-8",errors ="replace")
        except Exception as exc :
            result .errors .append ((str (fpath ),str (exc )))
            continue 

        lines =text .splitlines ()
        lc =len (lines )
        result .total_lines +=lc 
        result .lines_by_lang [lang ]=result .lines_by_lang .get (lang ,0 )+lc 
        result .blank_lines +=sum (1 for l in lines if l .strip ()=="")
        result .comment_lines +=sum (
        1 for l in lines if re .match (r"^\s*(#|//|/\*|\*|<!--|--|;)",l )
        )

        rel =str (fpath .relative_to (root_path ))


        if name in CONFIG_FILENAMES or ext in (".env",".config",".conf",".cfg"):
            result .findings .extend (_analyse_config (text ,rel ,lines ))


        elif name =="requirements.txt"or name .startswith ("requirements"):
            result .findings .extend (_analyse_requirements (text ,rel ))

        elif name =="package.json":
            result .findings .extend (_analyse_package_json (text ,rel ))

        else :

            result .findings .extend (_run_regex_rules (lines ,rel ))


            if ext ==".py":
                result .findings .extend (_analyse_python_ast (text ,rel ,lines ))


    seen :set [tuple ]=set ()
    unique :list [Finding ]=[]
    for f in result .findings :
        key =(f .file ,f .line ,f .category )
        if key not in seen :
            seen .add (key )
            unique .append (f )
    result .findings =unique 

    return result 
