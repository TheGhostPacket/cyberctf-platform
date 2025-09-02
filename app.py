# Enhanced app.py with more challenges and explanations
from flask import Flask, render_template, request, jsonify, session, redirect, url_for
from werkzeug.security import generate_password_hash, check_password_hash
import sqlite3
import hashlib
import base64
import os
from datetime import datetime
import secrets

app = Flask(__name__)
app.secret_key = secrets.token_hex(16)

# Database initialization with enhanced challenges
def init_db():
    conn = sqlite3.connect('ctf.db')
    cursor = conn.cursor()
    
    # Users table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            email TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            total_score INTEGER DEFAULT 0,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    
    # Challenges table with explanation field
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS challenges (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            title TEXT NOT NULL,
            description TEXT NOT NULL,
            category TEXT NOT NULL,
            points INTEGER NOT NULL,
            flag TEXT NOT NULL,
            hint TEXT,
            explanation TEXT,
            challenge_data TEXT,
            difficulty TEXT DEFAULT 'Easy'
        )
    ''')
    
    # Submissions table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS submissions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            challenge_id INTEGER,
            submitted_flag TEXT,
            is_correct BOOLEAN,
            submitted_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users (id),
            FOREIGN KEY (challenge_id) REFERENCES challenges (id)
        )
    ''')
    
    # Enhanced challenges with better educational content
    challenges = [
        # WEB SECURITY CHALLENGES (6 challenges)
        {
            'title': 'HTML Detective',
            'description': '''Welcome to your first cybersecurity challenge! 🕵️‍♂️<br><br>
            <strong>Your Mission:</strong> Find the secret flag hidden in HTML comments.<br><br>
            <strong>Instructions:</strong><br>
            1. Right-click anywhere on this page<br>
            2. Select "View Page Source" or "Inspect Element"<br>
            3. Look for HTML comments (they look like &lt;!-- comment --&gt;)<br>
            4. Find the flag that starts with FLAG{<br><br>
            <!-- FLAG{html_source_master} -->
            <strong>💡 Learning Goal:</strong> Understanding how to inspect web page source code for hidden information.''',
            'category': 'Web Security',
            'points': 50,
            'flag': 'FLAG{html_source_master}',
            'hint': 'HTML comments are not visible on the page, but they are in the source code. Right-click → View Page Source and look for <!-- -->',
            'explanation': '''<strong>🎓 What you learned:</strong><br><br>
            <strong>HTML Source Code Analysis</strong> is a fundamental web security skill where you examine the underlying HTML code of a webpage to find hidden information.<br><br>
            <strong>Why this matters:</strong><br>
            • Developers sometimes leave sensitive information in comments<br>
            • Hidden fields may contain important data<br>
            • Source code can reveal application structure<br><br>
            <strong>Real-world applications:</strong><br>
            • Bug bounty hunting<br>
            • Web application penetration testing<br>
            • Digital forensics investigations<br><br>
            <strong>🛡️ Security Tip:</strong> Never put sensitive information in HTML comments in production applications!''',
            'challenge_data': '<!-- FLAG{html_source_master} -->',
            'difficulty': 'Beginner'
        },
        {
            'title': 'Cookie Inspector',
            'description': '''🍪 Time to learn about browser cookies!<br><br>
            <strong>Your Mission:</strong> Find the flag stored in your browser cookies.<br><br>
            <strong>Instructions:</strong><br>
            1. Press F12 to open Developer Tools<br>
            2. Go to the "Application" tab (Chrome) or "Storage" tab (Firefox)<br>
            3. Look under "Cookies" in the left sidebar<br>
            4. Find the cookie named "secret_flag"<br><br>
            <strong>💡 Learning Goal:</strong> Understanding how cookies work and how to inspect them.''',
            'category': 'Web Security',
            'points': 75,
            'flag': 'FLAG{cookie_monster_detective}',
            'hint': 'Open Developer Tools (F12), go to Application tab, expand Cookies, and look for a cookie named "secret_flag"',
            'explanation': '''<strong>🎓 What you learned:</strong><br><br>
            <strong>Browser Cookies</strong> are small pieces of data stored by websites in your browser.<br><br>
            <strong>Cookie Security Concerns:</strong><br>
            • Sensitive data in cookies can be accessed via JavaScript<br>
            • Cookies are sent with every request to the domain<br>
            • Unencrypted cookies can be intercepted<br><br>
            <strong>Security Best Practices:</strong><br>
            • Use HttpOnly flag to prevent JavaScript access<br>
            • Use Secure flag for HTTPS-only cookies<br>
            • Never store passwords or sensitive data in cookies<br><br>
            <strong>🔍 Professional Use:</strong> Web security auditors regularly inspect cookies for sensitive information leaks.''',
            'challenge_data': 'secret_flag=FLAG{cookie_monster_detective}',
            'difficulty': 'Beginner'
        },
        {
            'title': 'Simple SQL Injection',
            'description': '''💉 Learn about SQL Injection - one of the most common web vulnerabilities!<br><br>
            <strong>Scenario:</strong> You found a login form that's vulnerable to SQL injection.<br><br>
            <strong>The vulnerable query looks like:</strong><br>
            <code>SELECT * FROM users WHERE username='admin' AND password='[YOUR_INPUT]'</code><br><br>
            <strong>Your Mission:</strong> Bypass the login by making the query always return true.<br><br>
            <strong>💡 Hint:</strong> What if you could make the password check always evaluate to true?''',
            'category': 'Web Security',
            'points': 150,
            'flag': 'FLAG{sql_injection_master}',
            'hint': '''Try entering this in the password field: <code>' OR '1'='1' --</code><br><br>
            This makes the query: <code>SELECT * FROM users WHERE username='admin' AND password='' OR '1'='1' --'</code><br><br>
            Since '1'='1' is always true, the login succeeds!''',
            'explanation': '''<strong>🎓 What you learned:</strong><br><br>
            <strong>SQL Injection</strong> is a vulnerability where malicious SQL code is inserted into application queries.<br><br>
            <strong>How it works:</strong><br>
            • User input is directly inserted into SQL queries<br>
            • Attackers can manipulate the query logic<br>
            • The '--' comment syntax ignores the rest of the query<br><br>
            <strong>Prevention methods:</strong><br>
            • Use parameterized queries (prepared statements)<br>
            • Input validation and sanitization<br>
            • Principle of least privilege for database users<br><br>
            <strong>🚨 Real Impact:</strong> SQL injection can lead to data breaches, data theft, and complete system compromise. It's #3 on the OWASP Top 10!''',
            'challenge_data': 'SELECT * FROM users WHERE username=\'admin\' AND password=\'[YOUR_INPUT]\'',
            'difficulty': 'Easy'
        },
        {
            'title': 'URL Parameter Manipulation',
            'description': '''🔗 Let's explore URL parameters!<br><br>
            <strong>Scenario:</strong> You notice this URL shows user profiles:<br>
            <code>https://example.com/profile?user=guest&role=user</code><br><br>
            <strong>Your Mission:</strong> What happens if you change the role parameter?<br><br>
            <strong>Try this:</strong> Change <code>role=user</code> to <code>role=admin</code><br><br>
            <strong>The flag format is:</strong> FLAG{parameter_[ROLE_YOU_FOUND]}''',
            'category': 'Web Security',
            'points': 100,
            'flag': 'FLAG{parameter_admin}',
            'hint': 'URL parameters can sometimes be manipulated to access different privileges. Try changing role=user to role=admin in the URL.',
            'explanation': '''<strong>🎓 What you learned:</strong><br><br>
            <strong>URL Parameter Manipulation</strong> is a technique where attackers modify URL parameters to access unauthorized content.<br><br>
            <strong>Common targets:</strong><br>
            • User IDs (user=123 → user=124)<br>
            • Role parameters (role=user → role=admin)<br>
            • Access levels (level=1 → level=5)<br><br>
            <strong>Security implications:</strong><br>
            • Horizontal privilege escalation<br>
            • Unauthorized data access<br>
            • Information disclosure<br><br>
            <strong>🛡️ Defense:</strong> Always validate parameters server-side and implement proper authorization checks!''',
            'challenge_data': 'profile?user=guest&role=user',
            'difficulty': 'Easy'
        },
        {
            'title': 'JavaScript Console Secrets',
            'description': '''🖥️ Time to explore the browser console!<br><br>
            <strong>Your Mission:</strong> Find the secret function hidden in the JavaScript console.<br><br>
            <strong>Instructions:</strong><br>
            1. Press F12 to open Developer Tools<br>
            2. Go to the "Console" tab<br>
            3. Type: <code>secretFlag()</code> and press Enter<br>
            4. The function will reveal the flag!<br><br>
            <strong>💡 Learning Goal:</strong> Understanding how JavaScript functions can be called from the console.''',
            'category': 'Web Security',
            'points': 80,
            'flag': 'FLAG{console_ninja}',
            'hint': 'Open the browser console (F12 → Console tab) and type: secretFlag() then press Enter',
            'explanation': '''<strong>🎓 What you learned:</strong><br><br>
            <strong>Browser Console</strong> is a powerful debugging tool that can also be used for security testing.<br><br>
            <strong>What you can do in the console:</strong><br>
            • Execute JavaScript functions<br>
            • Inspect variables and objects<br>
            • Modify page content dynamically<br>
            • Test for client-side vulnerabilities<br><br>
            <strong>Security considerations:</strong><br>
            • Sensitive functions shouldn't be exposed globally<br>
            • Client-side security is not real security<br>
            • Always validate on the server-side<br><br>
            <strong>🔍 Pro Tip:</strong> Security researchers often explore console APIs to find hidden functionality!''',
            'challenge_data': 'function secretFlag() { return "FLAG{console_ninja}"; }',
            'difficulty': 'Easy'
        },
        {
            'title': 'HTTP Headers Investigation',
            'description': '''📡 Let's investigate HTTP headers!<br><br>
            <strong>Your Mission:</strong> Find the flag hidden in HTTP response headers.<br><br>
            <strong>Instructions:</strong><br>
            1. Press F12 to open Developer Tools<br>
            2. Go to the "Network" tab<br>
            3. Refresh the page (F5)<br>
            4. Click on the first request (usually the HTML page)<br>
            5. Look in the "Response Headers" section<br>
            6. Find the header named "X-Secret-Flag"<br><br>
            <strong>💡 Learning Goal:</strong> Understanding HTTP headers and how they can contain information.''',
            'category': 'Web Security',
            'points': 120,
            'flag': 'FLAG{header_detective}',
            'hint': 'Open Developer Tools → Network tab → Refresh page → Click first request → Look for "X-Secret-Flag" in Response Headers',
            'explanation': '''<strong>🎓 What you learned:</strong><br><br>
            <strong>HTTP Headers</strong> carry metadata about HTTP requests and responses.<br><br>
            <strong>Common security-relevant headers:</strong><br>
            • X-Powered-By: Reveals server technology<br>
            • Server: Shows web server information<br>
            • X-Debug-Info: May contain sensitive debug data<br><br>
            <strong>Security implications:</strong><br>
            • Information disclosure about server setup<br>
            • Potential attack vectors identification<br>
            • Sensitive data leakage<br><br>
            <strong>🛡️ Best Practice:</strong> Remove or modify headers that reveal unnecessary information about your server stack!''',
            'challenge_data': 'X-Secret-Flag: FLAG{header_detective}',
            'difficulty': 'Easy'
        },

        # CRYPTOGRAPHY CHALLENGES (5 challenges)
        {
            'title': 'Caesar Cipher Beginner',
            'description': '''🏛️ Meet Julius Caesar's secret code!<br><br>
            <strong>The Challenge:</strong><br>
            Caesar cipher shifts each letter by a fixed number of positions in the alphabet.<br><br>
            <strong>Encrypted message:</strong> <code>SYNT{pnrfne_vf_rnfl}</code><br><br>
            <strong>Hint:</strong> This uses a shift of 13 (also called ROT13)<br>
            A→N, B→O, C→P, etc.<br><br>
            <strong>💡 Learning Goal:</strong> Understanding basic substitution ciphers.''',
            'category': 'Cryptography',
            'points': 75,
            'flag': 'FLAG{caesar_is_easy}',
            'hint': 'ROT13 means rotate each letter 13 positions: A→N, B→O, C→P... or use an online ROT13 decoder!',
            'explanation': '''<strong>🎓 What you learned:</strong><br><br>
            <strong>Caesar Cipher</strong> is one of the oldest known encryption techniques, named after Julius Caesar.<br><br>
            <strong>How it works:</strong><br>
            • Each letter is shifted by a fixed number of positions<br>
            • ROT13 is a special case with 13-position shift<br>
            • Very easy to break with frequency analysis<br><br>
            <strong>Modern relevance:</strong><br>
            • Understanding historical cryptography<br>
            • Basis for more complex ciphers<br>
            • Still used for simple obfuscation<br><br>
            <strong>🔓 Breaking it:</strong> Try all 25 possible shifts (brute force) or use frequency analysis!''',
            'challenge_data': 'SYNT{pnrfne_vf_rnfl}',
            'difficulty': 'Beginner'
        },
        {
            'title': 'Base64 Encoding',
            'description': '''📝 Base64 is everywhere in computing!<br><br>
            <strong>What is Base64?</strong><br>
            Base64 encoding converts binary data into text using 64 ASCII characters.<br><br>
            <strong>Encoded message:</strong><br>
            <code>RkxBR3tiYXNlNjRfZXhwZXJ0fQ==</code><br><br>
            <strong>Your Mission:</strong> Decode this Base64 string to reveal the flag.<br><br>
            <strong>💡 Learning Goal:</strong> Understanding Base64 encoding/decoding.''',
            'category': 'Cryptography',
            'points': 50,
            'flag': 'FLAG{base64_expert}',
            'hint': 'Use an online Base64 decoder, or in Python: import base64; base64.b64decode("string").decode()',
            'explanation': '''<strong>🎓 What you learned:</strong><br><br>
            <strong>Base64 Encoding</strong> is a method to encode binary data into ASCII text.<br><br>
            <strong>Why Base64 exists:</strong><br>
            • Safely transmit binary data over text-only channels<br>
            • Embed images in HTML/CSS<br>
            • Store binary data in databases<br><br>
            <strong>Characteristics:</strong><br>
            • Uses characters A-Z, a-z, 0-9, +, /<br>
            • Often ends with = or == for padding<br>
            • Increases data size by ~33%<br><br>
            <strong>🔍 Security Note:</strong> Base64 is encoding, NOT encryption! It provides no security, only format conversion.''',
            'challenge_data': 'RkxBR3tiYXNlNjRfZXhwZXJ0fQ==',
            'difficulty': 'Beginner'
        },
        {
            'title': 'MD5 Hash Detective',
            'description': '''🔍 Time to crack a hash!<br><br>
            <strong>What is MD5?</strong><br>
            MD5 is a cryptographic hash function that creates a 32-character hexadecimal string.<br><br>
            <strong>Hash to crack:</strong><br>
            <code>5d41402abc4b2a76b9719d911017c592</code><br><br>
            <strong>Hint:</strong> This is the MD5 hash of a very common English word!<br>
            Try words like: password, admin, test, hello, world<br><br>
            <strong>💡 Learning Goal:</strong> Understanding hash functions and rainbow table attacks.''',
            'category': 'Cryptography',
            'points': 100,
            'flag': 'FLAG{hello}',
            'hint': 'The hash is MD5 of "hello". Try hashing common words like hello, world, password, admin, test',
            'explanation': '''<strong>🎓 What you learned:</strong><br><br>
            <strong>MD5 Hashing</strong> creates a fixed-length "fingerprint" of input data.<br><br>
            <strong>Hash properties:</strong><br>
            • One-way function (hard to reverse)<br>
            • Same input always gives same hash<br>
            • Small input change = completely different hash<br><br>
            <strong>Why MD5 is weak:</strong><br>
            • Vulnerable to collision attacks<br>
            • Fast computation enables brute force<br>
            • Rainbow tables exist for common passwords<br><br>
            <strong>🛡️ Modern alternatives:</strong> SHA-256, SHA-3, bcrypt, scrypt, Argon2 for password hashing.''',
            'challenge_data': '5d41402abc4b2a76b9719d911017c592',
            'difficulty': 'Easy'
        },
        {
            'title': 'Hexadecimal Decoder',
            'description': '''🔢 Welcome to the world of hexadecimal!<br><br>
            <strong>What is Hexadecimal?</strong><br>
            Hex is a base-16 number system using digits 0-9 and letters A-F.<br><br>
            <strong>Encoded message:</strong><br>
            <code>464c41477b6865785f6d61737465727d</code><br><br>
            <strong>Your Mission:</strong> Convert this hex to ASCII text to find the flag.<br><br>
            <strong>💡 Learning Goal:</strong> Understanding hexadecimal encoding and ASCII conversion.''',
            'category': 'Cryptography',
            'points': 80,
            'flag': 'FLAG{hex_master}',
            'hint': 'Convert hex to ASCII. Each pair of hex digits represents one ASCII character. Use an online hex to ASCII converter.',
            'explanation': '''<strong>🎓 What you learned:</strong><br><br>
            <strong>Hexadecimal</strong> is a base-16 number system commonly used in computing.<br><br>
            <strong>Why hex is important:</strong><br>
            • Compact representation of binary data<br>
            • Easy conversion to/from binary<br>
            • Used in memory addresses, colors, encodings<br><br>
            <strong>Common uses in security:</strong><br>
            • Network packet analysis<br>
            • Memory dump analysis<br>
            • Hash representations<br>
            • Shellcode representation<br><br>
            <strong>💡 Conversion tip:</strong> Each ASCII character = 2 hex digits (e.g., 'A' = 41 in hex)''',
            'challenge_data': '464c41477b6865785f6d61737465727d',
            'difficulty': 'Easy'
        },
        {
            'title': 'Binary Message',
            'description': '''💻 Time to speak in binary - the language of computers!<br><br>
            <strong>What is Binary?</strong><br>
            Binary uses only 0s and 1s. Each group of 8 bits represents one ASCII character.<br><br>
            <strong>Binary message:</strong><br>
            <code>01000110 01001100 01000001 01000111 01111011 01100010 01101001 01101110 01100001 01110010 01111001 01111101</code><br><br>
            <strong>Your Mission:</strong> Convert each 8-bit group to its ASCII character.<br><br>
            <strong>💡 Learning Goal:</strong> Understanding binary-to-ASCII conversion.''',
            'category': 'Cryptography',
            'points': 120,
            'flag': 'FLAG{binary}',
            'hint': 'Convert each 8-bit binary number to decimal, then to ASCII. For example: 01000110 = 70 in decimal = "F" in ASCII',
            'explanation': '''<strong>🎓 What you learned:</strong><br><br>
            <strong>Binary System</strong> is the fundamental language of all digital computers.<br><br>
            <strong>Key concepts:</strong><br>
            • Base-2 number system (only 0 and 1)<br>
            • 8 bits = 1 byte = 1 ASCII character<br>
            • All computer data is ultimately binary<br><br>
            <strong>Security applications:</strong><br>
            • Reverse engineering<br>
            • Malware analysis<br>
            • Low-level exploit development<br>
            • Digital forensics<br><br>
            <strong>🎯 Pro Tip:</strong> Understanding binary is crucial for low-level security work and reverse engineering!''',
            'challenge_data': '01000110 01001100 01000001 01000111 01111011 01100010 01101001 01101110 01100001 01110010 01111001 01111101',
            'difficulty': 'Easy'
        },

        # NETWORK SECURITY CHALLENGES (3 challenges)
        {
            'title': 'Port Knowledge Quiz',
            'description': '''🌐 Test your network port knowledge!<br><br>
            <strong>Question:</strong> What is the default port number for HTTPS (secure web traffic)?<br><br>
            <strong>Choices:</strong><br>
            • 80 (HTTP)<br>
            • 443 (HTTPS)<br>
            • 22 (SSH)<br>
            • 25 (SMTP)<br><br>
            <strong>Flag format:</strong> FLAG{PORT_NUMBER}<br><br>
            <strong>💡 Learning Goal:</strong> Understanding common network ports and protocols.''',
            'category': 'Network Security',
            'points': 60,
            'flag': 'FLAG{443}',
            'hint': 'HTTPS uses port 443 by default. HTTP uses port 80, but HTTPS (secure) uses port 443.',
            'explanation': '''<strong>🎓 What you learned:</strong><br><br>
            <strong>Network Ports</strong> are communication endpoints that identify specific services.<br><br>
            <strong>Common ports to remember:</strong><br>
            • 21: FTP (File Transfer Protocol)<br>
            • 22: SSH (Secure Shell)<br>
            • 23: Telnet<br>
            • 25: SMTP (Email sending)<br>
            • 53: DNS (Domain Name System)<br>
            • 80: HTTP (Web traffic)<br>
            • 443: HTTPS (Secure web traffic)<br><br>
            <strong>🔒 Security importance:</strong> Open ports are potential attack vectors. Port scanning is often the first step in network reconnaissance!''',
            'challenge_data': 'HTTPS default port',
            'difficulty': 'Beginner'
        },
        {
            'title': 'DNS Lookup Challenge',
            'description': '''🔍 Let's explore DNS (Domain Name System)!<br><br>
            <strong>Your Mission:</strong> Find the flag hidden in a DNS TXT record.<br><br>
            <strong>Domain to investigate:</strong> <code>challenge.example.com</code><br><br>
            <strong>What to do:</strong><br>
            1. Use an online DNS lookup tool<br>
            2. Look up TXT records for the domain<br>
            3. Find the record containing a flag<br><br>
            <strong>Simulated TXT Record:</strong> "FLAG{dns_detective}"<br><br>
            <strong>💡 Learning Goal:</strong> Understanding DNS records and information gathering.''',
            'category': 'Network Security',
            'points': 100,
            'flag': 'FLAG{dns_detective}',
            'hint': 'DNS TXT records can contain arbitrary text data. Look for TXT records on challenge.example.com (simulated here as FLAG{dns_detective})',
            'explanation': '''<strong>🎓 What you learned:</strong><br><br>
            <strong>DNS (Domain Name System)</strong> translates human-readable domain names to IP addresses.<br><br>
            <strong>Common DNS record types:</strong><br>
            • A: Maps domain to IPv4 address<br>
            • AAAA: Maps domain to IPv6 address<br>
            • CNAME: Canonical name (alias)<br>
            • MX: Mail exchange servers<br>
            • TXT: Arbitrary text data<br><br>
            <strong>Security relevance:</strong><br>
            • DNS reconnaissance for subdomains<br>
            • TXT records may contain sensitive info<br>
            • DNS cache poisoning attacks<br><br>
            <strong>🕵️ OSINT Tip:</strong> DNS records are a goldmine for reconnaissance and information gathering!''',
            'challenge_data': 'challenge.example.com TXT "FLAG{dns_detective}"',
            'difficulty': 'Easy'
        },
        {
            'title': 'Network Protocol Identification',
            'description': '''📡 Time to identify network protocols!<br><br>
            <strong>Scenario:</strong> You intercepted network traffic and found these characteristics:<br><br>
            <strong>Traffic Analysis:</strong><br>
            • Uses port 22<br>
            • Encrypted connection<br>
            • Used for remote command line access<br>
            • Replaces insecure Telnet protocol<br><br>
            <strong>Question:</strong> What protocol is this?<br><br>
            <strong>Flag format:</strong> FLAG{PROTOCOL_NAME}<br><br>
            <strong>💡 Learning Goal:</strong> Understanding network protocols and their characteristics.''',
            'category': 'Network Security',
            'points': 80,
            'flag': 'FLAG{SSH}',
            'hint': 'This protocol uses port 22, provides encrypted remote access, and is the secure replacement for Telnet. It\'s SSH!',
            'explanation': '''<strong>🎓 What you learned:</strong><br><br>
            <strong>SSH (Secure Shell)</strong> is a secure protocol for remote access to computers.<br><br>
            <strong>SSH characteristics:</strong><br>
            • Default port: 22<br>
            • Encrypted communication<br>
            • Authentication via passwords or keys<br>
            • Secure replacement for Telnet<br><br>
            <strong>Security features:</strong><br>
            • Strong encryption<br>
            • Host key verification<br>
            • Port forwarding capabilities<br>
            • File transfer (SCP/SFTP)<br><br>
            <strong>🛡️ Security note:</strong> SSH is generally secure, but weak passwords, default credentials, and outdated versions can be vulnerable!''',
            'challenge_data': 'Port 22, encrypted, remote access, replaces Telnet',
            'difficulty': 'Easy'
        },

        # PASSWORD CRACKING CHALLENGES (3 challenges)
        {
            'title': 'Weak Password Analysis',
            'description': '''🔐 Let's analyze password security!<br><br>
            <strong>Scenario:</strong> You found this MD5 hash in a database breach:<br>
            <code>e99a18c428cb38d5f260853678922e03</code><br><br>
            <strong>Your Mission:</strong> This hash represents a very common password. Try these:<br>
            • password<br>
            • 123456<br>
            • admin<br>
            • qwerty<br><br>
            <strong>Hint:</strong> It's a 6-digit number that people often use as a password.<br><br>
            <strong>💡 Learning Goal:</strong> Understanding why common passwords are dangerous.''',
            'category': 'Password Cracking',
            'points': 90,
            'flag': 'FLAG{123456}',
            'hint': 'The hash is MD5 of "123456" - one of the most common passwords in the world!',
            'explanation': '''<strong>🎓 What you learned:</strong><br><br>
            <strong>Password Security</strong> is critical for protecting accounts and systems.<br><br>
            <strong>Common weak passwords:</strong><br>
            • 123456, password, admin, qwerty<br>
            • Personal information (birthdays, names)<br>
            • Dictionary words<br><br>
            <strong>Why weak passwords are dangerous:</strong><br>
            • Dictionary attacks succeed quickly<br>
            • Brute force attacks are feasible<br>
            • Rainbow tables exist for common passwords<br><br>
            <strong>🛡️ Strong password tips:</strong><br>
            • Use long, random passwords<br>
            • Include numbers, symbols, mixed case<br>
            • Use password managers<br>
            • Enable two-factor authentication!''',
            'challenge_data': 'e99a18c428cb38d5f260853678922e03',
            'difficulty': 'Easy'
        },
        {
            'title': 'Password Strength Quiz',
            'description': '''💪 Test your password strength knowledge!<br><br>
            <strong>Question:</strong> Which password is the STRONGEST?<br><br>
            <strong>Options:</strong><br>
            A) password123<br>
            B) P@ssw0rd!<br>
            C) Tr0ub4dor&3<br>
            D) correcthorsebatterystaple<br><br>
            <strong>Think about:</strong><br>
            • Length vs complexity<br>
            • Predictable patterns<br>
            • Dictionary words<br><br>
            <strong>Flag format:</strong> FLAG{OPTION_LETTER}<br><br>
            <strong>💡 Learning Goal:</strong> Understanding what makes passwords truly strong.''',
            'category': 'Password Cracking',
            'points': 70,
            'flag': 'FLAG{D}',
            'hint': 'Length matters more than complexity! "correcthorsebatterystaple" is long and hard to crack even though it uses simple words.',
            'explanation': '''<strong>🎓 What you learned:</strong><br><br>
            <strong>Password Strength</strong> is often misunderstood!<br><br>
            <strong>Why option D is strongest:</strong><br>
            • Length provides exponential security increase<br>
            • Random word combinations are hard to predict<br>
            • No predictable character substitutions<br><br>
            <strong>Password strength factors:</strong><br>
            • Length (most important!)<br>
            • Unpredictability<br>
            • No personal information<br>
            • No common patterns<br><br>
            <strong>🎯 Modern approach:</strong> Passphrases (multiple random words) are often stronger and more memorable than complex short passwords!<br><br>
            <strong>Reference:</strong> This is based on the famous XKCD comic about password strength!''',
            'challenge_data': 'Password strength comparison',
            'difficulty': 'Easy'
        },
        {
            'title': 'Hash Type Identification',
            'description': '''🔍 Can you identify this hash type?<br><br>
            <strong>Mystery Hash:</strong><br>
            <code>aab03e786183b1fd6bb36ce668e1ad1e</code><br><br>
            <strong>Clues:</strong><br>
            • 32 characters long<br>
            • Uses hexadecimal characters (0-9, a-f)<br>
            • Commonly used but now considered weak<br>
            • Often seen in older systems<br><br>
            <strong>Your Mission:</strong> Identify the hash type!<br><br>
            <strong>Flag format:</strong> FLAG{HASH_TYPE}<br><br>
            <strong>💡 Learning Goal:</strong> Recognizing different hash formats.''',
            'category': 'Password Cracking',
            'points': 60,
            'flag': 'FLAG{MD5}',
            'hint': 'This is a 32-character hexadecimal hash. MD5 produces 128-bit hashes, which equals 32 hex characters.',
            'explanation': '''<strong>🎓 What you learned:</strong><br><br>
            <strong>Hash Identification</strong> is crucial for password cracking and forensics.<br><br>
            <strong>Common hash lengths:</strong><br>
            • MD5: 32 hex characters (128 bits)<br>
            • SHA-1: 40 hex characters (160 bits)<br>
            • SHA-256: 64 hex characters (256 bits)<br>
            • NTLM: 32 hex characters (128 bits)<br><br>
            <strong>Why identification matters:</strong><br>
            • Different tools for different hash types<br>
            • Different attack strategies<br>
            • Understanding system security levels<br><br>
            <strong>🔍 Professional tip:</strong> Tools like hashcat and john the ripper can auto-detect many hash formats!''',
            'challenge_data': 'aab03e786183b1fd6bb36ce668e1ad1e',
            'difficulty': 'Easy'
        },

        # REVERSE ENGINEERING CHALLENGES (3 challenges)
        {
            'title': 'ASCII Art Detective',
            'description': '''🎨 Time for some ASCII art investigation!<br><br>
            <strong>Your Mission:</strong> Decode this ASCII art to find the hidden flag.<br><br>
            <pre>
 70  76  65  71 123  97 115  99 105 105  95 102 117 110 125
            </pre><br>
            <strong>Hint:</strong> These are ASCII decimal values. Convert each number to its ASCII character.<br><br>
            <strong>Example:</strong> 70 = "F", 76 = "L", 65 = "A"<br><br>
            <strong>💡 Learning Goal:</strong> Understanding ASCII encoding and decimal-to-character conversion.''',
            'category': 'Reverse Engineering',
            'points': 100,
            'flag': 'FLAG{ascii_fun}',
            'hint': 'Convert each decimal number to its ASCII character: 70="F", 76="L", 65="A", 71="G", 123="{", etc.',
            'explanation': '''<strong>🎓 What you learned:</strong><br><br>
            <strong>ASCII (American Standard Code for Information Interchange)</strong> assigns numeric values to characters.<br><br>
            <strong>Key ASCII ranges:</strong><br>
            • 48-57: Digits (0-9)<br>
            • 65-90: Uppercase letters (A-Z)<br>
            • 97-122: Lowercase letters (a-z)<br>
            • 32: Space character<br><br>
            <strong>Reverse engineering applications:</strong><br>
            • Analyzing binary data<br>
            • Decoding obfuscated strings<br>
            • Understanding file formats<br>
            • Malware analysis<br><br>
            <strong>🔧 Tools:</strong> HxD, 010 Editor, or simple programming scripts can help with ASCII conversion!''',
            'challenge_data': '70 76 65 71 123 97 115 99 105 105 95 102 117 110 125',
            'difficulty': 'Easy'
        },
        {
            'title': 'Simple XOR Cipher',
            'description': '''⚡ Meet the XOR cipher - simple but powerful!<br><br>
            <strong>What is XOR?</strong><br>
            XOR (exclusive or) returns true only when inputs differ.<br><br>
            <strong>Encrypted message:</strong><br>
            <code>5 30 8 25 28 24 29 9 20 8 21 11 5 1</code><br><br>
            <strong>Key:</strong> The number 42<br><br>
            <strong>Your Mission:</strong> XOR each number with 42 to get ASCII values, then convert to characters.<br><br>
            <strong>Example:</strong> 5 XOR 42 = 47, and ASCII 47 = "/"<br><br>
            <strong>💡 Learning Goal:</strong> Understanding XOR operations and their cryptographic use.''',
            'category': 'Reverse Engineering',
            'points': 150,
            'flag': 'FLAG{xor_rocks}',
            'hint': 'XOR each number with 42, then convert the result to ASCII. For example: 5 XOR 42 = 47, ASCII 47 = "/"',
            'explanation': '''<strong>🎓 What you learned:</strong><br><br>
            <strong>XOR (Exclusive OR)</strong> is a fundamental operation in cryptography and computing.<br><br>
            <strong>XOR properties:</strong><br>
            • A XOR B XOR B = A (self-inverse)<br>
            • XOR with 0 leaves value unchanged<br>
            • XOR with itself gives 0<br><br>
            <strong>Cryptographic uses:</strong><br>
            • Stream ciphers (like RC4)<br>
            • One-time pads<br>
            • Block cipher components<br><br>
            <strong>🛡️ Security note:</strong> Simple XOR with repeated keys is weak. Modern systems use complex XOR-based algorithms with proper key management!''',
            'challenge_data': '5 30 8 25 28 24 29 9 20 8 21 11 5 1',
            'difficulty': 'Medium'
        },
        {
            'title': 'File Signature Analysis',
            'description': '''📁 Let's analyze file signatures (magic numbers)!<br><br>
            <strong>What are file signatures?</strong><br>
            The first few bytes of a file that identify its type.<br><br>
            <strong>Mystery file header (in hex):</strong><br>
            <code>89 50 4E 47 0D 0A 1A 0A</code><br><br>
            <strong>Your Mission:</strong> Identify what type of file this is!<br><br>
            <strong>Hint:</strong> This is a common image format that supports transparency.<br><br>
            <strong>Flag format:</strong> FLAG{FILE_EXTENSION}<br><br>
            <strong>💡 Learning Goal:</strong> Understanding file signatures and digital forensics.''',
            'category': 'Reverse Engineering',
            'points': 120,
            'flag': 'FLAG{PNG}',
            'hint': 'The hex signature 89 50 4E 47 0D 0A 1A 0A is the magic number for PNG image files!',
            'explanation': '''<strong>🎓 What you learned:</strong><br><br>
            <strong>File Signatures (Magic Numbers)</strong> identify file types regardless of extension.<br><br>
            <strong>Common file signatures:</strong><br>
            • PNG: 89 50 4E 47<br>
            • JPEG: FF D8 FF<br>
            • PDF: 25 50 44 46<br>
            • ZIP: 50 4B 03 04<br>
            • EXE: 4D 5A<br><br>
            <strong>Forensic importance:</strong><br>
            • Identify files with wrong extensions<br>
            • Detect hidden or disguised files<br>
            • File carving in deleted data recovery<br><br>
            <strong>🔍 Tools:</strong> file command (Linux), TrID, or hex editors can identify file types by signatures!''',
            'challenge_data': '89 50 4E 47 0D 0A 1A 0A',
            'difficulty': 'Easy'
        }
    ]
    
    # Clear existing challenges and insert new ones
    cursor.execute('DELETE FROM challenges')
    
    # Insert enhanced challenges
    for challenge in challenges:
        cursor.execute('''
            INSERT INTO challenges (title, description, category, points, flag, hint, explanation, challenge_data, difficulty)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (challenge['title'], challenge['description'], challenge['category'], 
              challenge['points'], challenge['flag'], challenge['hint'], 
              challenge['explanation'], challenge['challenge_data'], challenge['difficulty']))
    
    conn.commit()
    conn.close()

# All the existing routes remain the same...
# (I'll keep them the same as the previous version)

# Routes (keeping existing structure)
@app.route('/')
def index():
    if 'user_id' in session:
        return redirect(url_for('dashboard'))
    return render_template('index.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']
        
        if len(password) < 6:
            if request.headers.get('Accept') == 'application/json':
                return jsonify({'error': 'Password must be at least 6 characters long'})
            else:
                return render_template('register.html', error='Password must be at least 6 characters long')
        
        password_hash = generate_password_hash(password)
        
        try:
            conn = sqlite3.connect('ctf.db')
            cursor = conn.cursor()
            cursor.execute('INSERT INTO users (username, email, password_hash) VALUES (?, ?, ?)',
                          (username, email, password_hash))
            conn.commit()
            conn.close()
            
            if request.headers.get('Accept') == 'application/json':
                return jsonify({'success': 'Registration successful! Please login.'})
            else:
                return render_template('login.html', success='Registration successful! Please login.')
        except sqlite3.IntegrityError:
            if request.headers.get('Accept') == 'application/json':
                return jsonify({'error': 'Username or email already exists'})
            else:
                return render_template('register.html', error='Username or email already exists')
    
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        conn = sqlite3.connect('ctf.db')
        cursor = conn.cursor()
        cursor.execute('SELECT id, password_hash FROM users WHERE username = ?', (username,))
        user = cursor.fetchone()
        conn.close()
        
        if user and check_password_hash(user[1], password):
            session['user_id'] = user[0]
            session['username'] = username
            
            if request.headers.get('Accept') == 'application/json':
                return jsonify({'success': 'Login successful!'})
            else:
                return redirect(url_for('dashboard'))
        else:
            if request.headers.get('Accept') == 'application/json':
                return jsonify({'error': 'Invalid username or password'})
            else:
                return render_template('login.html', error='Invalid username or password')
    
    return render_template('login.html')

@app.route('/dashboard')
def dashboard():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    conn = sqlite3.connect('ctf.db')
    cursor = conn.cursor()
    
    # Get user stats
    cursor.execute('SELECT total_score FROM users WHERE id = ?', (session['user_id'],))
    user_score = cursor.fetchone()[0]
    
    # Get challenges by category
    cursor.execute('SELECT DISTINCT category FROM challenges')
    categories = [row[0] for row in cursor.fetchall()]
    
    # Get solved challenges
    cursor.execute('''
        SELECT challenge_id FROM submissions 
        WHERE user_id = ? AND is_correct = 1
    ''', (session['user_id'],))
    solved_challenges = [row[0] for row in cursor.fetchall()]
    
    conn.close()
    
    return render_template('dashboard.html', 
                         username=session['username'],
                         user_score=user_score,
                         categories=categories,
                         solved_count=len(solved_challenges))

@app.route('/challenges/<category>')
def challenges(category):
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    conn = sqlite3.connect('ctf.db')
    cursor = conn.cursor()
    
    cursor.execute('SELECT id, title, description, points, hint, difficulty FROM challenges WHERE category = ? ORDER BY points', (category,))
    challenges = cursor.fetchall()
    
    # Get solved challenges
    cursor.execute('''
        SELECT challenge_id FROM submissions 
        WHERE user_id = ? AND is_correct = 1
    ''', (session['user_id'],))
    solved_challenges = [row[0] for row in cursor.fetchall()]
    
    conn.close()
    
    challenges_data = []
    for challenge in challenges:
        challenges_data.append({
            'id': challenge[0],
            'title': challenge[1],
            'description': challenge[2],
            'points': challenge[3],
            'hint': challenge[4],
            'difficulty': challenge[5],
            'solved': challenge[0] in solved_challenges
        })
    
    return render_template('challenges.html', 
                         category=category, 
                         challenges=challenges_data)

@app.route('/submit_flag', methods=['POST'])
def submit_flag():
    if 'user_id' not in session:
        return jsonify({'error': 'Not logged in'})
    
    challenge_id = request.form['challenge_id']
    submitted_flag = request.form['flag'].strip()
    
    conn = sqlite3.connect('ctf.db')
    cursor = conn.cursor()
    
    # Check if already solved
    cursor.execute('''
        SELECT id FROM submissions 
        WHERE user_id = ? AND challenge_id = ? AND is_correct = 1
    ''', (session['user_id'], challenge_id))
    
    if cursor.fetchone():
        conn.close()
        return jsonify({'error': 'Challenge already solved!'})
    
    # Get correct flag and challenge info
    cursor.execute('SELECT flag, points, title, explanation FROM challenges WHERE id = ?', (challenge_id,))
    challenge = cursor.fetchone()
    
    if not challenge:
        conn.close()
        return jsonify({'error': 'Challenge not found'})
    
    correct_flag, points, title, explanation = challenge
    is_correct = submitted_flag == correct_flag
    
    # Record submission
    cursor.execute('''
        INSERT INTO submissions (user_id, challenge_id, submitted_flag, is_correct)
        VALUES (?, ?, ?, ?)
    ''', (session['user_id'], challenge_id, submitted_flag, is_correct))
    
    if is_correct:
        # Update user score
        cursor.execute('''
            UPDATE users SET total_score = total_score + ? WHERE id = ?
        ''', (points, session['user_id']))
        
        success_message = f'🎉 Correct! You earned {points} points for "{title}"!'
        if explanation:
            success_message += f'\n\n{explanation}'
        
        conn.commit()
        conn.close()
        return jsonify({'success': success_message})
    else:
        conn.commit()
        conn.close()
        return jsonify({'error': 'Incorrect flag. Try again! Check the hint if you need help.'})

@app.route('/leaderboard')
def leaderboard():
    conn = sqlite3.connect('ctf.db')
    cursor = conn.cursor()
    
    cursor.execute('''
        SELECT username, total_score, 
               (SELECT COUNT(*) FROM submissions 
                WHERE user_id = users.id AND is_correct = 1) as solved_count
        FROM users 
        ORDER BY total_score DESC 
        LIMIT 50
    ''')
    
    leaderboard_data = cursor.fetchall()
    conn.close()
    
    return render_template('leaderboard.html', leaderboard=leaderboard_data)

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('index'))

if __name__ == '__main__':
    init_db()
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port, debug=False)