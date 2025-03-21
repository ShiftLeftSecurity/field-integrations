import os

SHIFTLEFT_ACCESS_TOKEN = os.getenv("SHIFTLEFT_ACCESS_TOKEN")
SHIFTLEFT_APP = os.getenv("SHIFTLEFT_APP")
SHIFTLEFT_API_HOST = os.getenv("SHIFTLEFT_API_HOST") or "app.shiftleft.io"

# Indentation for json. Set to None to disable indendation
json_indent = 2

ngsast_logo = """
 ██████╗ ██╗    ██╗██╗███████╗████████╗  █████╗ ██╗
██╔═══██╗██║    ██║██║██╔════╝╚══██╔══╝ ██╔══██╗██║
██║   ██║██║ █╗ ██║██║█████╗     ██║    ███████║██║
██║▄▄ ██║██║███╗██║██║██╔══╝     ██║    ██╔══██║██║
╚██████╔╝╚███╔███╔╝██║███████╗   ██║    ██║  ██║██║
 ╚══▀▀═╝  ╚══╝╚══╝ ╚═╝╚══════╝   ╚═╝    ╚═╝  ╚═╝╚═╝
"""

# This is WIP

sl_owasp_category = {
    78: "cmdi",
    327: "crypto",
    328: "hash",
    90: "ldapi",
    22: "pathtraver",
    614: "securecookie",
    89: "sqli",
    501: "trustbound",
    330: "weakrand",
    643: "xpathi",
    79: "xss",
}

# API timeout in seconds
timeout = 180

# How many chunks of apps to process for stats
app_chunk_size = 20

ignorable_paths = (
    "test",
    "sample",
    "build",
    "docs",
    "dist",
    "scripts/",
    ".nuxt/",
    ".next/",
    ".html",
    "grunt",
    "bower",
)

check_labels_list = (
    "check",
    "valid",
    "sanit",
    "escape",
    "clean",
    "safe",
    "serialize",
    "convert",
    "authenticate",
    "authorize",
)

trimmable_ci_paths = (
    "D:\\a\\1\\s\\",
    "C:\\",
    "D:\\",
)

all_routes_tags = (
    "http",
    "httpHeader",
    "session",
    "httpsession",
    "httpClient",
    "httpClientHeader",
    "httpHeaderCheck",
    "allowAll",
    "corsAllowedOrigins",
    "cookie",
    "credentials",
    "set-password",
    "auth",
    "ldap",
    "httpservletrequestwrapper",
)

all_events_tags = (
    "queue",
    "cloud",
    "queueName",
    "executableInfo",
    "azure",
    "aws",
    "amazon",
    "awsToken",
    "s3",
    "amazonSns",
    "event",
    "event-name",
    "ffi",
    "registry",
    "javascript",
    "clipboard",
    "ui",
    "audio",
    "windowOpenFeatures",
    "pushNotification",
    "network",
    "awsSignRequest",
    "executeCode",
    "socket",
    "grpc",
    "windowUrl",
    "location",
    "lambdaFunctionName",
    "cssSelector",
    "dom",
    "akkaMessage",
    "sendBroadcast",
    "startActivity",
    "implicitIntent",
    "extraIntent",
    "file",
    "terminalSession",
    "sms",
    "voice",
    "url",
)
