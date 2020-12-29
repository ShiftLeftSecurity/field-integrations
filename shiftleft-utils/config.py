import os

SHIFTLEFT_ORG_ID = os.getenv("SHIFTLEFT_ORG_ID")
SHIFTLEFT_ACCESS_TOKEN = os.getenv("SHIFTLEFT_ACCESS_TOKEN")
SHIFTLEFT_APP = os.getenv("SHIFTLEFT_APP")

# Indentation for json. Set to None to disable indendation
json_indent = 2

ngsast_logo = """
███╗   ██╗ ██████╗     ███████╗ █████╗ ███████╗████████╗
████╗  ██║██╔════╝     ██╔════╝██╔══██╗██╔════╝╚══██╔══╝
██╔██╗ ██║██║  ███╗    ███████╗███████║███████╗   ██║
██║╚██╗██║██║   ██║    ╚════██║██╔══██║╚════██║   ██║
██║ ╚████║╚██████╔╝    ███████║██║  ██║███████║   ██║
╚═╝  ╚═══╝ ╚═════╝     ╚══════╝╚═╝  ╚═╝╚══════╝   ╚═╝
"""

# This is WIP
sl_owasp_category = {
    "SQL Injection": "sqli",
    "LDAP Injection": "ldapi",
    "XPath Injection": "xpathi",
    "Weak Random": "weakrand",
    "Session Injection": "trustbound",
    "Cookie Injection": "securecookie",
    "Weak Hash": "hash",
    "hash": "hash",
    "Open Redirect": "pathtraver",
    "XSS": "xss",
    "Remote Code Execution": "cmdi",
    "Insecure Cookie": "securecookie",
    "Directory Traversal": "pathtraver",
    "Broken Authentication": "crypto",
    "Weak symmetric encryption algorithm": "crypto"
}
