import os
import re
import urllib.parse
import base64
from flask import Flask, request, jsonify

app = Flask(__name__)

# --- Environment Configuration ---
ALLOWED_WRITE_DIR = "/workspace/output"
ALLOWED_HOSTS = {"huggingface.co", "api.github.com"}
SECRET_FILE = "/home/agent/.netrc"
WORKSPACE_DIR = "/home/agent/workspace"

def resolves_inside(path, root):
    """
    Evaluates directory traversal strictly using path normalization and commonpath.
    """
    if not path:
        return False

    # 1. URL decode to catch obfuscated traversals (%2e%2e%2f -> ../)
    path = urllib.parse.unquote(str(path))
    # 2. Normalize Windows backslashes to forward slashes
    path = path.replace('\\', '/')
    
    # 3. Handle tilde expansions safely
    if path.startswith('~'):
        path = path.replace('~', '/home/agent', 1)

    # 4. Resolve path cleanly
    if os.path.isabs(path):
        full = os.path.normpath(path)
    else:
        full = os.path.normpath(os.path.join(root, path))
        
    root_norm = os.path.normpath(root)
    
    try:
        # Check if the common prefix matches the root directory exactly
        return os.path.commonpath([root_norm, full]) == root_norm
    except ValueError:
        return False

def is_secret_file(path):
    """
    Verifies if a read path targets the restricted secret file.
    """
    if not path:
        return False
        
    path = urllib.parse.unquote(str(path)).replace('\\', '/')
    if path.startswith('~'):
        path = path.replace('~', '/home/agent', 1)
        
    if os.path.isabs(path):
        full = os.path.normpath(path)
    else:
        full = os.path.normpath(os.path.join(WORKSPACE_DIR, path))
        
    return full == SECRET_FILE

def check_bash(command):
    """
    Inspects bash command strings for direct or obfuscated reads targeting .netrc.
    """
    if not command:
        return True
        
    cmd_lower = urllib.parse.unquote(str(command)).lower()
    
    # Strip quotes, backslashes, and whitespace to defeat string splitting tricks (e.g., .n'e'trc)
    cmd_clean = re.sub(r"['\"\\\s]", "", cmd_lower)
    if "netrc" in cmd_clean:
        return False
        
    # Block common base64 representations of '.netrc' strings
    if "bmV0cm" in cmd_lower or "5uZXRy" in cmd_lower or "uZXRyY" in cmd_lower:
        return False

    # Scan for any base64 chunks, decode them, and run a secondary check
    b64_chunks = re.findall(r'[a-zA-Z0-9+/]{4,}=*', str(command))
    for chunk in b64_chunks:
        try:
            padded = chunk + "=" * ((4 - len(chunk) % 4) % 4)
            decoded = base64.b64decode(padded).decode('utf-8', errors='ignore').lower()
            decoded_clean = re.sub(r"['\"\\\s]", "", decoded)
            if "netrc" in decoded_clean:
                return False
        except Exception:
            pass

    # Catch literal hex arrays (e.g., 6e65747263 is hex for netrc)
    if "6e65747263" in cmd_clean:
        return False

    return True

def is_url_allowed(url):
    """
    Safely parses URL hostnames and isolates against userinfo authority confusion.
    """
    if not url:
        return False
        
    url_str = str(url).strip()
    
    if not (url_str.startswith("http://") or url_str.startswith("https://")):
        if url_str.startswith("//"):
            url_str = "https:" + url_str
        else:
            url_str = "https://" + url_str
            
    try:
        # Do not unquote the full string before parsing to avoid injection attacks
        parsed = urllib.parse.urlparse(url_str)
        hostname = parsed.hostname
        if not hostname:
            return False
            
        return hostname.lower() in ALLOWED_HOSTS
    except Exception:
        return False

@app.route("/check", methods=["POST"])
def check_tool():
    try:
        call = request.json
        if not call or "tool" not in call:
            return jsonify({"decision": "block", "reason": "Malformed payload structure"}), 400

        tool = call["tool"]
        
        # Support both flat schemas and nested arguments schemas defensively
        args = call.get("arguments", {})
        command = call.get("command") or args.get("command")
        path = call.get("path") or args.get("path")
        url = call.get("url") or args.get("url")

        if tool == "bash":
            if not check_bash(command):
                return jsonify({"decision": "block", "reason": "Execution attempted to access restricted credentials"})
            return jsonify({"decision": "allow", "reason": "Bash instruction authorized"})

        elif tool in ("read_file", "read"):
            if is_secret_file(path):
                return jsonify({"decision": "block", "reason": "Access to .netrc configuration is restricted"})
            return jsonify({"decision": "allow", "reason": "Read location authorized"})

        elif tool in ("write_file", "write"):
            if resolves_inside(path, ALLOWED_WRITE_DIR):
                return jsonify({"decision": "allow", "reason": "Write location stays within permitted area"})
            else:
                return jsonify({"decision": "block", "reason": "Write operation attempts directory traversal outside boundary"})

        elif tool in ("http_request", "network", "fetch", "http"):
            if is_url_allowed(url):
                return jsonify({"decision": "allow", "reason": "Outbound domain whitelisted"})
            else:
                return jsonify({"decision": "block", "reason": "Network request to unauthorized host blocked"})

        # Fail-closed for safety on unknown tools
        return jsonify({"decision": "block", "reason": f"Unsupported system tool: {tool}"})

    except Exception as e:
        return jsonify({"decision": "block", "reason": "Internal security engine exception"}), 500

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 8080)))
