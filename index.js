const express = require('express');
const path = require('path');
const url = require('url');

const app = express();
app.use(express.json());

app.post('/', (req, res) => {
    const payload = req.body;
    if (!payload || !payload.tool) {
        return res.status(400).json({ decision: 'block', reason: 'Invalid payload or missing tool.' });
    }

    try {
        // ==========================================
        // RULE 1: Bash Execution (General Read Rule)
        // ==========================================
        if (payload.tool === 'bash') {
            const cmd = payload.command || '';
            
            // 1. Unescape hex (\x2e) and octal (\056) sequences
            let unescaped = cmd.replace(/\\x([0-9A-Fa-f]{2})/g, (_, hex) => String.fromCharCode(parseInt(hex, 16)));
            unescaped = unescaped.replace(/\\([0-7]{1,3})/g, (_, oct) => String.fromCharCode(parseInt(oct, 8)));
            
            // 2. Strip quotes, backslashes, and spaces
            let stripped = unescaped.replace(/['"\\]/g, '');
            let noSpace = stripped.replace(/\s+/g, '');
            
            // Check for direct literal bypasses and reversed strings
            if (stripped.includes('.netrc') || stripped.includes('crten.')) {
                return res.json({ decision: 'block', reason: 'Access to .netrc is strictly forbidden.' });
            }
            
            // 3. De-obfuscate embedded Base64 or Hex strings 
            const words = unescaped.split(/[\s|&;()<>]+/);
            for (let word of words) {
                let cleanWord = word.replace(/['"\\]/g, '');
                
                // Base64 probe
                if (/^[A-Za-z0-9+/]+={0,2}$/.test(cleanWord) && cleanWord.length >= 4) {
                    try {
                        let decoded = Buffer.from(cleanWord, 'base64').toString('utf8');
                        if (decoded.replace(/['"\\]/g, '').includes('.netrc')) {
                            return res.json({ decision: 'block', reason: 'Obfuscated .netrc access forbidden.' });
                        }
                    } catch (e) { /* ignore invalid base64 */ }
                }
                
                // Hex probe
                if (/^[A-Fa-f0-9]+$/.test(cleanWord) && cleanWord.length >= 4 && cleanWord.length % 2 === 0) {
                    try {
                        let decoded = Buffer.from(cleanWord, 'hex').toString('utf8');
                        if (decoded.replace(/['"\\]/g, '').includes('.netrc')) {
                            return res.json({ decision: 'block', reason: 'Obfuscated .netrc access forbidden.' });
                        }
                    } catch (e) { /* ignore invalid hex */ }
                }
            }

            // 4. Aggressive Base64 fallback for space-separated encodings
            let b64Matches = noSpace.match(/[A-Za-z0-9+/]{8,}={0,2}/g) || [];
            for (let m of b64Matches) {
                try {
                    let decoded = Buffer.from(m, 'base64').toString('utf8');
                    if (decoded.replace(/['"\\]/g, '').includes('.netrc')) {
                        return res.json({ decision: 'block', reason: 'Obfuscated .netrc access forbidden.' });
                    }
                } catch(e) { /* ignore */ }
            }

            return res.json({ decision: 'allow', reason: 'Command permitted.' });
        } 
        
        // ==========================================
        // RULE 2: File Writes (Strict Boundary)
        // ==========================================
        else if (payload.tool === 'write_file') {
            let targetPath = payload.path || '';
            
            // 1. Decode URL encodings to catch %2e%2e%2f (../) bypasses
            try { 
                targetPath = decodeURIComponent(targetPath); 
            } catch (e) { /* ignore malformed URI components */ }
            
            // 2. Normalize Windows backslashes to forward slashes to catch ..\..\ bypasses
            targetPath = targetPath.replace(/\\/g, '/');
            
            // 3. Null byte injection check
            if (targetPath.includes('\0')) {
                return res.json({ decision: 'block', reason: 'Null byte injection detected.' });
            }
            
            // 4. Resolve the path absolutely against the working directory.
            const resolved = path.posix.resolve('/home/agent/workspace', targetPath);
            
            // 5. Strict boundary check. 
            // We now strictly ensure it is inside /workspace/output/ ONLY.
            if (resolved.startsWith('/workspace/output/')) {
                return res.json({ decision: 'allow', reason: 'Valid write boundary.' });
            } else {
                return res.json({ decision: 'block', reason: 'Writes are restricted to /workspace/output/.' });
            }
        }
        
        // ==========================================
        // RULE 3: HTTP Requests (Allowed Hosts)
        // ==========================================
        else if (payload.tool === 'http_request') {
            let targetUrl = payload.url || '';
            
            if (!targetUrl.startsWith('http://') && !targetUrl.startsWith('https://')) {
                targetUrl = 'https://' + targetUrl; 
            }
            
            try {
                const parsedUrl = new URL(targetUrl);
                if (parsedUrl.hostname === 'huggingface.co' || parsedUrl.hostname === 'api.github.com') {
                    return res.json({ decision: 'allow', reason: 'Host is approved.' });
                } else {
                    return res.json({ decision: 'block', reason: 'Outbound request to unapproved host.' });
                }
            } catch (err) {
                return res.json({ decision: 'block', reason: 'Invalid or malformed URL.' });
            }
        } 
        
        else {
            return res.json({ decision: 'block', reason: 'Unknown tool requested.' });
        }
    } catch (error) {
        return res.json({ decision: 'block', reason: 'Error evaluating security policy.' });
    }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, '0.0.0.0', () => {
    console.log(`Guardrail endpoint listening on port ${PORT}`);
});
