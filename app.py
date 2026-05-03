"""
QuizMaster Pro — Flask Backend  (PostgreSQL / psycopg2 Edition)
────────────────────────────────────────────────────────────────
KEY CHANGES vs the original SQLite version
  1. import psycopg2 instead of sqlite3
  2. All SQL placeholders changed from  ?  →  %s   (psycopg2 style)
  3. AUTOINCREMENT  →  SERIAL   (PostgreSQL syntax)
  4. INTEGER 0/1 flags  →  BOOLEAN   (PostgreSQL native)
  5. LIKE  →  ILIKE   (case-insensitive search in PostgreSQL)
  6. AVG()::numeric cast added for ROUND() compatibility
  7. RETURNING id used on INSERT to get new primary keys
  8. get_db() returns a psycopg2 connection; RealDictCursor makes
     rows behave like dicts  (row['column'])
  9. SESSION_COOKIE_SECURE set to False for local dev — set True
     in production behind HTTPS

HOW TO SET YOUR DATABASE CREDENTIALS
  Option A – environment variable (recommended):
      export DATABASE_URL="postgresql://quizify_db_lxtb_user:PASSWORD@HOST:5432/quizify_db_lxtb"

  Option B – individual env vars:
      export DB_USER=quizify_db_lxtb_user
      export DB_PASSWORD=your_password
      export DB_HOST=localhost
      export DB_PORT=5432
      export DB_NAME=quizify_db_lxtb

INSTALL DEPENDENCIES
  pip install flask flask-limiter flask-talisman psycopg2-binary bleach werkzeug

RUN
  python app.py
  Default admin login:  username=admin  password=Admin@1234
"""
import os, re, logging
from datetime import timedelta, datetime
from functools import wraps

import bleach
import psycopg2
import psycopg2.extras          # RealDictCursor
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.middleware.proxy_fix import ProxyFix
from flask import Flask, render_template, request, jsonify, session, g, redirect, url_for
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_talisman import Talisman

# ── App ────────────────────────────────────────────────────────────────────────
app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "quizmaster-fallback-secret-change-me")
app.wsgi_app   = ProxyFix(app.wsgi_app, x_proto=1, x_host=1)

app.config.update(
    SESSION_COOKIE_HTTPONLY = True,
    SESSION_COOKIE_SAMESITE = 'Lax',
    SESSION_COOKIE_SECURE   = False,          # True in production (HTTPS)
    PERMANENT_SESSION_LIFETIME = timedelta(hours=2),
    MAX_CONTENT_LENGTH = 16 * 1024,
)

csp = {
    'default-src': ["'self'"],
    'style-src':   ["'self'", "'unsafe-inline'", "https://fonts.googleapis.com"],
    'font-src':    ["'self'", "https://fonts.gstatic.com"],
    'script-src':  ["'self'", "'unsafe-inline'"],
    'img-src':     ["'self'", "data:"],
    'connect-src': ["'self'"],
}
Talisman(app, force_https=False, strict_transport_security=False,
         content_security_policy=csp, x_content_type_options=True,
         x_xss_protection=True, referrer_policy='strict-origin-when-cross-origin')

limiter = Limiter(get_remote_address, app=app,
                  default_limits=["300 per hour", "100 per minute"],
                  storage_uri="memory://")

logging.basicConfig(level=logging.INFO, format='%(asctime)s [%(levelname)s] %(message)s')
logger = logging.getLogger("quizmaster.security")

MAX_NAME_LEN = 30
MIN_NAME_LEN = 2
MAX_LIMIT    = 20
VALID_ANS    = {"A", "B", "C", "D"}

# ── Database URL ───────────────────────────────────────────────────────────────
DATABASE_URL = os.environ.get("DATABASE_URL") or (
    "postgresql://{user}:{password}@{host}:{port}/{dbname}".format(
        user     = os.environ.get("DB_USER",     "quizify_db_lxtb_user"),
        password = os.environ.get("DB_PASSWORD", "your_password_here"),
        host     = os.environ.get("DB_HOST",     "localhost"),
        port     = os.environ.get("DB_PORT",     "5432"),
        dbname   = os.environ.get("DB_NAME",     "quizify_db_lxtb"),
    )
)

# ── DB helpers ─────────────────────────────────────────────────────────────────
def get_db():
    """Per-request psycopg2 connection (stored in Flask g)."""
    if 'db' not in g:
        g.db = psycopg2.connect(DATABASE_URL)
        g.db.autocommit = False
    return g.db

def get_cursor():
    """RealDictCursor so rows act like dicts: row['column']."""
    return get_db().cursor(cursor_factory=psycopg2.extras.RealDictCursor)

def db_commit():
    get_db().commit()

@app.teardown_appcontext
def close_db(e=None):
    db = g.pop('db', None)
    if db:
        db.close()

# ── Input helpers ──────────────────────────────────────────────────────────────
def sanitize(v):
    if not isinstance(v, str): return ""
    if '\x00' in v or any(ord(c) < 32 and c not in ('\t',) for c in v):
        return "\x00INVALID\x00"
    return bleach.clean(v, tags=[], strip=True).strip()

def validate_name(raw):
    if not isinstance(raw, str): return False, "Name must be a string."
    if '<' in raw or '>' in raw:  return False, "Name: HTML not allowed."
    if '\x00' in raw or any(ord(c) < 32 and c not in ('\t',) for c in raw):
        return False, "Name: invalid characters."
    name = bleach.clean(raw, tags=[], strip=True).strip()
    if len(name) < MIN_NAME_LEN: return False, f"Name needs at least {MIN_NAME_LEN} chars."
    if len(name) > MAX_NAME_LEN: return False, f"Name max {MAX_NAME_LEN} chars."
    if not re.match(r'^[A-Za-z0-9 _\-\.]+$', name): return False, "Name: letters/digits/spaces only."
    return True, ""

def sec_log(ev, detail="", level="info"):
    getattr(logger, level)(f"[{ev}] ip={request.remote_addr} | {detail}")

# ── DB init / seed ─────────────────────────────────────────────────────────────
def init_db():
    """Create tables and seed data (only runs once thanks to IF NOT EXISTS / count checks)."""
    conn = psycopg2.connect(DATABASE_URL)
    conn.autocommit = True
    c = conn.cursor()

    # ── Tables ────────────────────────────────────────────────────────────────
    c.execute("""
        CREATE TABLE IF NOT EXISTS categories (
            id    SERIAL PRIMARY KEY,
            name  TEXT NOT NULL,
            icon  TEXT NOT NULL,
            color TEXT NOT NULL
        )""")

    c.execute("""
        CREATE TABLE IF NOT EXISTS questions (
            id             SERIAL PRIMARY KEY,
            category_id    INTEGER NOT NULL REFERENCES categories(id),
            question       TEXT NOT NULL,
            option_a       TEXT NOT NULL,
            option_b       TEXT NOT NULL,
            option_c       TEXT NOT NULL,
            option_d       TEXT NOT NULL,
            correct_answer TEXT NOT NULL CHECK (correct_answer IN ('A','B','C','D')),
            difficulty     TEXT NOT NULL DEFAULT 'medium'
                           CHECK (difficulty IN ('easy','medium','hard'))
        )""")

    c.execute("""
        CREATE TABLE IF NOT EXISTS results (
            id              SERIAL PRIMARY KEY,
            player_name     TEXT NOT NULL,
            category_id     INTEGER NOT NULL REFERENCES categories(id),
            score           INTEGER NOT NULL CHECK (score >= 0),
            total_questions INTEGER NOT NULL CHECK (total_questions > 0),
            time_taken      INTEGER NOT NULL CHECK (time_taken >= 0),
            played_at       TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )""")

    c.execute("""
        CREATE TABLE IF NOT EXISTS audit_log (
            id         SERIAL PRIMARY KEY,
            event      TEXT NOT NULL,
            ip_address TEXT,
            detail     TEXT,
            ts         TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )""")

    c.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id            SERIAL PRIMARY KEY,
            username      TEXT NOT NULL UNIQUE,
            email         TEXT NOT NULL UNIQUE,
            password_hash TEXT NOT NULL,
            full_name     TEXT,
            created_at    TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            last_login    TIMESTAMP,
            is_active     BOOLEAN DEFAULT TRUE,
            is_admin      BOOLEAN DEFAULT FALSE
        )""")

    c.execute("""
        CREATE TABLE IF NOT EXISTS interview_companies (
            id      SERIAL PRIMARY KEY,
            name    TEXT NOT NULL,
            logo    TEXT NOT NULL,
            color   TEXT NOT NULL,
            type    TEXT NOT NULL,
            founded INTEGER,
            hq      TEXT
        )""")

    c.execute("""
        CREATE TABLE IF NOT EXISTS interview_questions (
            id          SERIAL PRIMARY KEY,
            company_id  INTEGER NOT NULL REFERENCES interview_companies(id),
            topic       TEXT NOT NULL,
            question    TEXT NOT NULL,
            answer      TEXT NOT NULL,
            notes       TEXT,
            difficulty  TEXT NOT NULL DEFAULT 'medium'
                        CHECK (difficulty IN ('easy','medium','hard')),
            rating      REAL NOT NULL DEFAULT 4.0,
            times_asked INTEGER NOT NULL DEFAULT 1,
            last_year   INTEGER,
            years_asked TEXT,
            role_level  TEXT NOT NULL DEFAULT 'Fresher',
            tags        TEXT
        )""")

    # ── Seed admin ────────────────────────────────────────────────────────────
    c.execute("SELECT COUNT(*) FROM users WHERE is_admin = TRUE")
    if c.fetchone()[0] == 0:
        c.execute(
            "INSERT INTO users(username,email,password_hash,full_name,is_admin) VALUES(%s,%s,%s,%s,%s)",
            ("admin", "admin@quizmaster.com",
             generate_password_hash("Admin@1234", method="pbkdf2:sha256", salt_length=16),
             "Administrator", True)
        )

    # ── Seed categories ───────────────────────────────────────────────────────
    c.execute("SELECT COUNT(*) FROM categories")
    if c.fetchone()[0] == 0:
        c.executemany("INSERT INTO categories(name,icon,color) VALUES(%s,%s,%s)", [
            ("Python Programming", "🐍", "#4ade80"),
            ("Cybersecurity",      "🔐", "#f472b6"),
            ("Data Structures",    "🌳", "#60a5fa"),
            ("Operating Systems",  "💻", "#fb923c"),
            ("Computer Networks",  "🌐", "#a78bfa"),
        ])

    # ── Seed quiz questions ───────────────────────────────────────────────────
    c.execute("SELECT COUNT(*) FROM questions")
    if c.fetchone()[0] == 0:
        questions = [
            # ── PYTHON (category 1) ────────────────────────────────────────
            (1,"Output of print(type([]))?","<class 'list'>","<class 'array'>","<class 'tuple'>","<class 'dict'>","A","easy"),
            (1,"Keyword to define a function?","func","def","define","function","B","easy"),
            (1,"'pip' stands for?","Python Install Package","Pip Installs Packages","Package Index Python","Python Index Package","B","medium"),
            (1,"Which is immutable?","List","Dictionary","Tuple","Set","C","medium"),
            (1,"What is a lambda?","A loop","An anonymous function","A class method","A module","B","medium"),
            (1,"GIL stands for?","Global Instance Lock","Generic Import Library","Global Interpreter Lock","General Index List","C","hard"),
            (1,"Method to add to list end?","add()","insert()","append()","extend()","C","easy"),
            (1,"Output of 2**10?","20","100","1024","512","C","easy"),
            (1,"What is a decorator?","A loop","Function wrapping another function","A variable type","A class modifier","B","medium"),
            (1,"len() of empty list?","None","Error","0","1","C","easy"),
            (1,"How to create a set?","[]","{}","()","set()","D","easy"),
            (1,"== vs is difference?","No difference","== checks value, is checks identity","is checks value","Both check identity","B","medium"),
            (1,"*args is used for?","Multiplication","Variable positional arguments","Keyword arguments","None","B","medium"),
            (1,"**kwargs is used for?","Power operator","Variable keyword arguments","Pointer to function","None","B","medium"),
            (1,"range(5) produces?","1 to 5","0 to 5","0 to 4","1 to 4","C","easy"),
            (1,"List comprehension syntax?","[x for x in list]","(x for x in list)","{x for x in list}","<x for x in list>","A","easy"),
            (1,"How to open a file?","openfile()","file.open()","open()","fopen()","C","easy"),
            (1,"bool(0) output?","True","False","None","Error","B","easy"),
            (1,"Not a Python data type?","int","float","char","str","C","easy"),
            (1,"strip() does what?","Splits string","Removes whitespace from ends","Converts to list","Reverses","B","easy"),
            (1,"Generator uses which keyword?","return","break","yield","pass","C","medium"),
            (1,"enumerate() does what?","Counts elements","Returns index-value pairs","Sorts list","Filters list","B","medium"),
            (1,"'hello'[1] output?","h","e","he","ello","B","easy"),
            (1,"Shallow vs deep copy?","Same thing","Shallow copies refs, deep copies values","Deep copies refs","Neither copies","B","hard"),
            (1,"deepcopy() is from which module?","os","sys","copy","shutil","C","medium"),
            (1,"None in Python means?","Zero","False","Null/empty value","Empty string","C","easy"),
            (1,"pass statement does?","Exits loop","Does nothing (placeholder)","Continues loop","Raises exception","B","easy"),
            (1,"map() function does?","Maps files","Applies function to all items","Creates dictionary","Sorts items","B","medium"),
            (1,"filter() returns?","List","Iterator matching condition","Dictionary","Set","B","medium"),
            (1,"Python module is?","A function","A file containing Python code","A variable","A loop","B","easy"),
            (1,"__init__ in a class is?","Destructor","Constructor method","Static method","Class method","B","easy"),
            (1,"self refers to?","The class","The parent class","The current instance","A module","C","easy"),
            (1,"Method overriding means?","Calling parent method","Child redefines parent method","Same method twice","None","B","medium"),
            (1,"type(3.14) output?","<class 'int'>","<class 'float'>","<class 'double'>","<class 'number'>","B","easy"),
            (1,"try-except is used for?","Looping","Exception handling","File reading","Sorting","B","easy"),
            (1,"finally block does?","Runs only on error","Runs only on success","Always runs","Never runs","C","easy"),
            (1,"Python dictionary is?","Ordered list","Key-value pair collection","A set","A tuple","B","easy"),
            (1,"Get all keys of dict?","dict.values()","dict.items()","dict.keys()","dict.list()","C","easy"),
            (1,"zip() does?","Compression","Combines iterables element-wise","Sorts lists","Filters list","B","medium"),
            (1,"sorted() returns?","Sorted in-place","New sorted list","None","Iterator","B","easy"),
            (1,"frozenset is?","Mutable set","Immutable set","Ordered set","Empty set","B","medium"),
            (1,"walrus operator := is?","Comparison","Assignment expression","Slicing","Unpacking","B","hard"),
            (1,"PEP 8 is?","Python error code","Python style guide","A module","A data type","B","medium"),
            (1,"10//3 output?","3.33","3","4","Error","B","easy"),
            (1,"assert raises what if False?","ValueError","AssertionError","TypeError","KeyError","B","medium"),
            (1,"Context manager works with?","try","with","for","while","B","medium"),
            (1,"Inheritance syntax in Python?","class Child extends Parent","class Child(Parent)","class Child::Parent","class Child implements Parent","B","easy"),
            (1,"'abc'*3 output?","Error","abcabcabc","abc3","abc abc abc","B","easy"),
            (1,"How to check if key in dict?","dict.has(key)","key in dict","dict.contains(key)","dict.find(key)","B","easy"),
            (1,"__str__ method is used for?","Deleting object","String representation of object","Copying object","Comparing objects","B","medium"),
            # ── CYBERSECURITY (category 2) ─────────────────────────────────
            (2,"SQL Injection exploits?","Buffer overflow","Insecure DB queries","XSS vulnerability","Weak passwords","B","easy"),
            (2,"Zero-day vulnerability is?","Bug fixed same day","Unknown unpatched exploit","A DDoS attack","Phishing attempt","B","medium"),
            (2,"HTTPS runs on port?","80","21","443","8080","C","easy"),
            (2,"XSS stands for?","Extra Secure Script","Cross-Site Scripting","Cross System Shell","Extended Script Service","B","easy"),
            (2,"Reverse shell means?","Shell facing backward","Target connects back to attacker","Firewall bypass","Rootkit technique","B","hard"),
            (2,"Tool for network scanning?","Metasploit","Wireshark","Nmap","Burp Suite","C","medium"),
            (2,"WAF purpose?","Monitor CPU","Block malicious web traffic","Encrypt DB","Manage accounts","B","medium"),
            (2,"CVE stands for?","Common Vulnerability Exposure","Cyber Vulnerability Entry","Critical Vulnerability Exploit","Common Vulnerabilities and Exposures","D","medium"),
            (2,"CSRF stands for?","Cross-Site Request Forgery","Code Security Restriction","Client-Side Request Failure","None","A","medium"),
            (2,"Brute force attack is?","Social engineering","Trying all possible passwords","Packet sniffing","SQL injection","B","easy"),
            (2,"Phishing is?","Network attack","Fraudulent communication to steal data","DDoS attack","Malware","B","easy"),
            (2,"CIA triad stands for?","Confidentiality Integrity Availability","Cyber Intelligence Attack","Code Integrity Access","None","A","easy"),
            (2,"Man-in-the-middle attack?","Server attack","Attacker intercepts communication","Password attack","File corruption","B","medium"),
            (2,"Honeypot is?","Sweet data","Decoy system to lure attackers","Password vault","Firewall type","B","medium"),
            (2,"Social engineering is?","Technical hacking","Manipulating people to reveal info","Software exploit","Network attack","B","easy"),
            (2,"IDS stands for?","Internet Defense System","Intrusion Detection System","Internal Data Storage","None","B","easy"),
            (2,"Botnet is?","A single bot","Network of infected computers","Security tool","Antivirus","B","medium"),
            (2,"Ransomware does?","Speeds up computer","Encrypts files for ransom","Improves security","Deletes logs","B","easy"),
            (2,"Two-factor authentication uses?","Two passwords","Two verification methods","Double encryption","None","B","easy"),
            (2,"Least privilege principle?","Give maximum access","Give only minimum needed access","Share all access","No authentication","B","medium"),
            (2,"VPN stands for?","Virtual Private Network","Virus Protection Network","Virtual Protocol Node","None","A","easy"),
            (2,"Port scanning does?","Opens ports","Probes ports to find open services","Closes ports","Port forwarding","B","medium"),
            (2,"ARP poisoning is?","Network routing","Corrupting ARP cache to intercept traffic","DNS attack","Password attack","B","hard"),
            (2,"Rootkit is?","Root access tool","Malware hiding deep in OS","Antivirus","Firewall bypass","B","hard"),
            (2,"Steganography is?","Data encryption","Hiding data inside other data","Password hashing","Network scanning","B","hard"),
            (2,"OWASP stands for?","Open Web Application Security Project","Online Website Attack System","Open Wireless Access Security Protocol","None","A","medium"),
            (2,"Directory traversal is?","File search","Accessing files outside intended directory","Creating directories","Deleting directories","B","medium"),
            (2,"Session hijacking is?","Server control","Stealing user's session token","DDoS attack","XSS variant","B","hard"),
            (2,"Fuzzing is?","Network test","Sending random inputs to find bugs","Password attack","Social engineering","B","medium"),
            (2,"Password salting prevents?","Slow hashing","Rainbow table attacks","Weak passwords","SQL injection","B","medium"),
            (2,"Digital certificate is?","Digital signature","Verifying identity via Certificate Authority","Encryption key","Password","B","medium"),
            (2,"SSRF stands for?","Server-Side Request Forgery","System Security Risk Framework","Secure Socket Routing Function","None","A","hard"),
            (2,"Ethical hacking is?","Illegal hacking","Authorized security testing","Social engineering","Password cracking","B","easy"),
            (2,"Penetration testing is?","Testing hardware","Simulating attacks to find vulnerabilities","Network speed test","Stress test","B","medium"),
            (2,"What is a WAF bypass?","Fixing WAF","Evading web application firewall detection","WAF configuration","None","B","hard"),
            (2,"SSH runs on which port?","21","22","23","25","B","easy"),
            (2,"What is a DMZ?","Military zone","Network segment between internet and internal network","DNS zone","None","B","hard"),
            (2,"What is privilege escalation?","Giving more RAM","Gaining higher access than authorized","Updating software","None","B","hard"),
            (2,"What does netcat do?","Antivirus scan","Network utility for reading/writing connections","Disk scanner","None","B","medium"),
            (2,"What is OSINT?","Security tool","Open-Source Intelligence gathering","Network scanning","Password cracking","B","medium"),
            (2,"What is Metasploit?","Antivirus","Penetration testing framework","Firewall","Network monitor","B","medium"),
            (2,"What is Wireshark used for?","Password cracking","Packet capture and analysis","Port scanning","Exploitation","B","easy"),
            # ── DATA STRUCTURES (category 3) ───────────────────────────────
            (3,"Binary search time complexity?","O(n)","O(n^2)","O(log n)","O(1)","C","medium"),
            (3,"LIFO data structure?","Queue","Stack","Heap","Linked List","B","easy"),
            (3,"Min-heap root contains?","Maximum","Median","Minimum","Random","C","easy"),
            (3,"Quicksort worst case?","O(n log n)","O(n^2)","O(n)","O(log n)","B","hard"),
            (3,"Preorder traversal visits?","Left, Root, Right","Root, Left, Right","Left, Right, Root","Right, Left, Root","B","easy"),
            (3,"Hash collision means?","Two keys hash to same index","Hash table full","Corrupted key","Empty bucket","A","medium"),
            (3,"Dijkstra's algorithm finds?","Shortest path","Min spanning tree","Topological sort","Components","A","medium"),
            (3,"Deque is?","Single-ended queue","Double-ended queue","Priority queue","Circular queue","B","easy"),
            (3,"Array access time?","O(n)","O(log n)","O(1)","O(n^2)","C","easy"),
            (3,"Linked list head insertion?","O(n)","O(log n)","O(1)","O(n^2)","C","easy"),
            (3,"Stack overflow is?","Stack is full","Call stack exceeds limit","Array overflow","Queue overflow","B","easy"),
            (3,"Priority queue serves?","First in first out","Highest priority first","Last in first out","Random","B","medium"),
            (3,"Merge sort time complexity?","O(n^2)","O(n log n)","O(n)","O(log n)","B","medium"),
            (3,"AVL tree is?","Self-balancing BST","Unbalanced BST","Heap structure","Graph type","A","hard"),
            (3,"BFS uses which structure?","Stack","Queue","Heap","Array","B","medium"),
            (3,"DFS uses which structure?","Queue","Heap","Stack","Array","C","medium"),
            (3,"Kruskal's algorithm finds?","Shortest path","Minimum spanning tree","Topological order","Connected components","B","hard"),
            (3,"Memoization means?","Memory management","Caching results of function calls","Sorting algorithm","Graph traversal","B","medium"),
            (3,"Trie is used for?","Number storage","String prefix search","Graph traversal","Sorting","B","hard"),
            (3,"Hash table insert average?","O(n)","O(log n)","O(1)","O(n^2)","C","easy"),
            (3,"Floyd-Warshall is for?","Single source shortest path","All-pairs shortest path","Minimum spanning tree","Topological sort","B","hard"),
            (3,"Backtracking does?","Goes forward only","Abandons invalid paths and tries others","DFS variant","Dynamic programming","B","hard"),
            (3,"Topological sort works on?","Any graph","Directed Acyclic Graph (DAG)","Undirected graph","Tree only","B","hard"),
            (3,"Insertion sort best case?","O(n^2)","O(n log n)","O(n)","O(1)","C","medium"),
            (3,"Segment tree is for?","String matching","Range queries and updates","Graph traversal","Sorting","B","hard"),
            (3,"Two pointer technique reduces?","O(n) to O(1)","O(n^2) to O(n)","O(log n) to O(1)","O(n) to O(log n)","B","medium"),
            # ── OPERATING SYSTEMS (category 4) ─────────────────────────────
            (4,"Deadlock means?","CPU overload","Processes waiting forever for each other","Memory leak","Kernel panic","B","medium"),
            (4,"BIOS stands for?","Basic I/O System","Binary Input Output System","Basic Input Output System","Base Internal OS","C","easy"),
            (4,"Thrashing means?","CPU spike","Excessive paging causing slowdown","Disk failure","Memory corruption","B","hard"),
            (4,"Semaphore is used for?","Memory allocation","Process synchronization","File management","CPU scheduling","B","medium"),
            (4,"PCB stores?","File paths","Process state info registers and resources","Network config","Disk partitions","B","easy"),
            (4,"Fastest memory is?","RAM","Cache (L1/L2/L3)","HDD","ROM","B","easy"),
            (4,"Virtual memory uses?","Extra physical RAM","Disk space as RAM extension","GPU memory","Cloud storage","B","medium"),
            (4,"Process is?","A file","Program in execution with its own resources","A thread","A semaphore","B","easy"),
            (4,"Thread is?","Independent process","Lightweight unit within a process sharing memory","Kernel module","File handle","B","easy"),
            (4,"Context switching is?","CPU switching processes","Process migration","Memory swap","Thread creation","A","medium"),
            (4,"Round Robin scheduling uses?","Priority order","Fixed time slice per process","FCFS order","Shortest job first","B","easy"),
            (4,"Page fault is?","Hard drive failure","Accessing page not currently in RAM","CPU error","Network error","B","medium"),
            (4,"Mutex provides?","Multi-user access","Mutual Exclusion - one thread at a time","Memory pooling","None","B","medium"),
            (4,"Zombie process is?","Dead process","Finished process with parent not collected exit status","Hanging process","Background process","B","hard"),
            (4,"Orphan process is?","Process with no threads","Process whose parent has died","Background process","Daemon","B","hard"),
            (4,"Fragmentation means?","Memory error","Wasted unusable gaps in memory","Cache miss","None","B","medium"),
            (4,"Kernel is?","User application","Core OS managing hardware resources","File manager","Network driver","B","easy"),
            (4,"LRU page replacement stands for?","Least Recently Used","Least Requested Update","Last Random Unit","None","A","medium"),
            (4,"Starvation means?","Low food supply","Low-priority process never gets CPU time","Memory shortage","Deadlock","B","medium"),
            (4,"Multiprogramming means?","Multiple programs installed","Multiple programs in memory at same time","Multi-core CPU","None","B","easy"),
            (4,"fork() in Linux does?","Splits file","Creates child process copy of parent","Deletes process","Switches process","B","medium"),
            (4,"Race condition means?","CPU speed","Unexpected results from concurrent shared data access","Network race","None","B","medium"),
            (4,"RAID stands for?","RAM Array Integrated Device","Redundant Array of Independent Disks","Random Access Integrated Disk","None","B","medium"),
            (4,"Belady's anomaly affects?","LRU","FIFO page replacement","LFU","Optimal","B","hard"),
            (4,"Paging eliminates?","Internal fragmentation","External fragmentation","Both","Neither","B","medium"),
            # ── COMPUTER NETWORKS (category 5) ─────────────────────────────
            (5,"DNS resolves?","IP to MAC","Domain name to IP address","IP to hostname","URL to port","B","easy"),
            (5,"IP operates at OSI layer?","Transport (4)","Application (7)","Network (3)","Data Link (2)","C","medium"),
            (5,"ARP is used for?","Routing packets","Resolving IP to MAC address","DNS lookup","Firewall rules","B","medium"),
            (5,"TTL stands for?","Time To Load","Total Transfer Limit","Time To Live","Transfer Through Layer","C","easy"),
            (5,"Connectionless protocol?","TCP","FTP","HTTP","UDP","D","easy"),
            (5,"Subnet mask identifies?","Encryption key","Network and host portions of IP","DNS server","Packet filter","B","medium"),
            (5,"BGP is used for?","LAN routing","Routing between autonomous systems","WiFi security","Load balancing","B","hard"),
            (5,"MAC address is?","IP identifier","Hardware network interface identifier","Domain name","Port number","B","easy"),
            (5,"DHCP stands for?","Dynamic Host Configuration Protocol","DNS Host Control Program","Data Hub Control Protocol","None","A","easy"),
            (5,"NAT stands for?","Network Address Translation","Node Access Token","Network Analysis Tool","None","A","medium"),
            (5,"Router does?","Connects same network devices","Connects different networks and routes packets","Acts as firewall","Acts as switch","B","easy"),
            (5,"HTTP is?","Secure protocol","HyperText Transfer Protocol for web","Email protocol","File transfer","B","easy"),
            (5,"FTP is used for?","Web browsing","File transfer between systems","Email sending","DNS resolution","B","easy"),
            (5,"SMTP is used for?","Web browsing","Sending email","File transfer","DNS","B","easy"),
            (5,"Bandwidth means?","Signal strength","Maximum data transfer rate","Latency","Packet loss","B","easy"),
            (5,"Latency means?","Data rate","Time delay for data to travel source to destination","Bandwidth","Packet size","B","easy"),
            (5,"TCP 3-way handshake?","SYN ACK FIN","SYN SYN-ACK ACK","ACK SYN FIN","HELLO OK DONE","B","medium"),
            (5,"SSL/TLS provides?","File transfer","Encryption of data in transit","Email protocol","DNS security","B","medium"),
            (5,"CDN stands for?","Code Delivery Network","Content Delivery Network","None","Central DNS Node","B","medium"),
            (5,"ICMP is used for?","File transfer","Error messages and diagnostics (ping)","Web traffic","Email","B","medium"),
            (5,"VLAN means?","Virtual LAN isolating network segments","Virtual Machine","VPN type","None","A","medium"),
            (5,"Port 22 is for?","HTTP","SSH - Secure Shell","FTP","SMTP","B","easy"),
            (5,"Port 443 is for?","HTTP","FTP","HTTPS","SMTP","C","easy"),
            (5,"IPv6 uses how many bits?","32","64","128","256","C","medium"),
            (5,"HTTPS vs HTTP?","Same thing","HTTPS encrypts data using TLS, HTTP does not","HTTP is newer","None","B","easy"),
            (5,"What is a default gateway?","Local router IP","IP that routes traffic to outside networks","DNS server","Firewall IP","B","medium"),
            (5,"What does ping test?","Download speed","Reachability and round-trip time to a host","Bandwidth","Upload speed","B","easy"),
        ]
        c.executemany(
            "INSERT INTO questions(category_id,question,option_a,option_b,option_c,option_d,correct_answer,difficulty) VALUES(%s,%s,%s,%s,%s,%s,%s,%s)",
            questions
        )

    # ── Seed interview companies ───────────────────────────────────────────────
    c.execute("SELECT COUNT(*) FROM interview_companies")
    if c.fetchone()[0] == 0:
        c.executemany("INSERT INTO interview_companies(name,logo,color,type,founded,hq) VALUES(%s,%s,%s,%s,%s,%s)", [
            ("TCS",           "🔷", "#0052CC", "Service", 1968, "Mumbai"),
            ("Wipro",         "🟡", "#341A6E", "Service", 1945, "Bengaluru"),
            ("Infosys",       "🔵", "#007CC3", "Service", 1981, "Bengaluru"),
            ("HCL",           "🟢", "#009A44", "Service", 1976, "Noida"),
            ("Accenture",     "🟣", "#A100FF", "Service", 1989, "Dublin"),
            ("Cognizant",     "🔶", "#0033A0", "Service", 1994, "New Jersey"),
            ("Tech Mahindra", "⚙️", "#C8102E", "Service", 1986, "Pune"),
            ("Amazon",        "🟠", "#FF9900", "Product", 1994, "Seattle"),
            ("Microsoft",     "🪟", "#00A4EF", "Product", 1975, "Redmond"),
            ("Google",        "🔴", "#EA4335", "Product", 1998, "Mountain View"),
        ])

    conn.commit()
    conn.close()

# ── Error handlers ─────────────────────────────────────────────────────────────
@app.errorhandler(400)
def bad_req(e):  return jsonify({"error": "Bad request"}), 400
@app.errorhandler(404)
def not_found(e): return jsonify({"error": "Not found"}), 404
@app.errorhandler(429)
def rate_hit(e):
    sec_log("RATE_LIMIT", "", level="warning")
    return jsonify({"error": "Too many requests. Slow down."}), 429
@app.errorhandler(500)
def srv_err(e):
    logger.error(f"500: {e}")
    return jsonify({"error": "Internal server error"}), 500

# ── Auth decorators ────────────────────────────────────────────────────────────
def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if 'user_id' not in session:
            return redirect(url_for('login_page'))
        return f(*args, **kwargs)
    return decorated

def admin_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if 'user_id' not in session:
            return redirect(url_for('login_page'))
        cur = get_cursor()
        cur.execute("SELECT is_admin FROM users WHERE id = %s", (session['user_id'],))
        u = cur.fetchone()
        if not u or not u['is_admin']:
            return jsonify({"error": "Admin access required"}), 403
        return f(*args, **kwargs)
    return decorated

def current_user():
    if 'user_id' not in session:
        return None
    cur = get_cursor()
    cur.execute("SELECT id, username, email, full_name FROM users WHERE id = %s", (session['user_id'],))
    return cur.fetchone()

# ── Pages ──────────────────────────────────────────────────────────────────────
@app.route("/login")
def login_page():
    if 'user_id' in session:
        return redirect(url_for('index'))
    return render_template("login.html")

@app.route("/register")
def register_page():
    if 'user_id' in session:
        return redirect(url_for('index'))
    return render_template("login.html", mode="register")

@app.route("/")
@login_required
def index():
    return render_template("index.html")

@app.route("/interview")
@login_required
def interview():
    return render_template("interview.html")

@app.route("/admin")
def admin_page():
    if 'user_id' not in session:
        return redirect(url_for('login_page'))
    cur = get_cursor()
    cur.execute("SELECT is_admin, username FROM users WHERE id = %s", (session['user_id'],))
    u = cur.fetchone()
    if not u or not u['is_admin']:
        return redirect(url_for('index'))
    return render_template("admin.html")

# ── Auth API ───────────────────────────────────────────────────────────────────
@app.route("/api/auth/register", methods=["POST"])
@limiter.limit("5 per minute")
def auth_register():
    data = request.get_json(silent=True)
    if not data:
        return jsonify({"error": "Invalid JSON"}), 400

    username  = sanitize(str(data.get("username", "")))
    email     = sanitize(str(data.get("email", "")))
    full_name = sanitize(str(data.get("full_name", "")))
    password  = str(data.get("password", ""))

    if not re.match(r'^[A-Za-z0-9_]{3,20}$', username):
        return jsonify({"error": "Username: 3-20 chars, letters/digits/underscore only"}), 400
    if not re.match(r'^[^@\s]+@[^@\s]+\.[^@\s]+$', email) or len(email) > 100:
        return jsonify({"error": "Enter a valid email address"}), 400
    if len(password) < 8:
        return jsonify({"error": "Password must be at least 8 characters"}), 400
    if not re.search(r'[A-Z]', password):
        return jsonify({"error": "Password must contain at least one uppercase letter"}), 400
    if not re.search(r'[0-9]', password):
        return jsonify({"error": "Password must contain at least one number"}), 400

    cur = get_cursor()
    cur.execute("SELECT id FROM users WHERE username = %s", (username,))
    if cur.fetchone():
        return jsonify({"error": "Username already taken"}), 409
    cur.execute("SELECT id FROM users WHERE email = %s", (email.lower(),))
    if cur.fetchone():
        return jsonify({"error": "Email already registered"}), 409

    pw_hash = generate_password_hash(password, method='pbkdf2:sha256', salt_length=16)
    cur.execute(
        "INSERT INTO users(username, email, password_hash, full_name) VALUES(%s,%s,%s,%s) RETURNING id",
        (username, email.lower(), pw_hash, full_name or username)
    )
    new_id = cur.fetchone()['id']
    db_commit()

    session.permanent  = True
    session['user_id']   = new_id
    session['username']  = username
    session['full_name'] = full_name or username

    sec_log("REGISTER", f"username={username!r}")
    return jsonify({"status": "ok", "username": username, "full_name": full_name or username})

@app.route("/api/auth/login", methods=["POST"])
@limiter.limit("10 per minute")
def auth_login():
    data = request.get_json(silent=True)
    if not data:
        return jsonify({"error": "Invalid JSON"}), 400

    username = sanitize(str(data.get("username", "")))
    password = str(data.get("password", ""))
    if not username or not password:
        return jsonify({"error": "Username and password required"}), 400

    cur = get_cursor()
    cur.execute(
        "SELECT id, username, email, password_hash, full_name, is_active FROM users WHERE username = %s OR email = %s",
        (username, username.lower())
    )
    row = cur.fetchone()

    if not row or not check_password_hash(row['password_hash'], password):
        sec_log("LOGIN_FAIL", f"username={username!r}", "warning")
        return jsonify({"error": "Invalid username or password"}), 401

    if not row['is_active']:
        return jsonify({"error": "Account disabled. Contact support."}), 403

    cur.execute("UPDATE users SET last_login = %s WHERE id = %s", (datetime.now(), row['id']))
    db_commit()

    session.permanent  = True
    session['user_id']   = row['id']
    session['username']  = row['username']
    session['full_name'] = row['full_name']

    sec_log("LOGIN_OK", f"username={row['username']!r}")
    return jsonify({"status": "ok", "username": row['username'], "full_name": row['full_name']})

@app.route("/api/auth/logout", methods=["POST"])
def auth_logout():
    username = session.get('username', 'unknown')
    session.clear()
    sec_log("LOGOUT", f"username={username!r}")
    return jsonify({"status": "ok"})

@app.route("/api/auth/me")
def auth_me():
    if 'user_id' not in session:
        return jsonify({"logged_in": False})
    u = current_user()
    if not u:
        session.clear()
        return jsonify({"logged_in": False})
    cur = get_cursor()
    cur.execute("SELECT is_admin FROM users WHERE id = %s", (session['user_id'],))
    admin_row = cur.fetchone()
    return jsonify({
        "logged_in": True,
        "username":  u['username'],
        "full_name": u['full_name'],
        "email":     u['email'],
        "is_admin":  bool(admin_row and admin_row['is_admin'])
    })

# ── Quiz API ───────────────────────────────────────────────────────────────────
@app.route("/api/categories")
@limiter.limit("200 per minute")
def get_categories():
    cur = get_cursor()
    cur.execute("""
        SELECT c.id, c.name, c.icon, c.color, COUNT(q.id) AS question_count
        FROM categories c
        LEFT JOIN questions q ON c.id = q.category_id
        GROUP BY c.id ORDER BY c.id
    """)
    return jsonify([dict(r) for r in cur.fetchall()])

@app.route("/api/questions/<int:cat_id>")
@limiter.limit("100 per minute")
def get_questions(cat_id):
    cur = get_cursor()
    cur.execute("SELECT id FROM categories WHERE id = %s", (cat_id,))
    if not cur.fetchone():
        return jsonify({"error": "Category not found"}), 404
    limit = min(max(request.args.get("limit", 10, type=int), 1), MAX_LIMIT)
    cur.execute(
        "SELECT id, question, option_a, option_b, option_c, option_d, difficulty FROM questions WHERE category_id = %s ORDER BY RANDOM() LIMIT %s",
        (cat_id, limit)
    )
    qs = cur.fetchall()
    result = [{
        "id": q["id"], "question": q["question"],
        "options": {"A": q["option_a"], "B": q["option_b"], "C": q["option_c"], "D": q["option_d"]},
        "difficulty": q["difficulty"]
    } for q in qs]
    session["active_qids"] = [r["id"] for r in result]
    session["cat_id"] = cat_id
    return jsonify(result)

@app.route("/api/check_answer", methods=["POST"])
@limiter.limit("200 per minute")
def check_answer():
    data = request.get_json(silent=True)
    if not data: return jsonify({"error": "Invalid JSON"}), 400
    qid      = data.get("question_id")
    user_ans = str(data.get("answer", "")).upper().strip()
    if not isinstance(qid, int) or qid < 1: return jsonify({"error": "Invalid question id"}), 400
    if user_ans not in VALID_ANS: return jsonify({"error": "Answer must be A, B, C or D"}), 400
    active = session.get("active_qids", [])
    if active and qid not in active:
        sec_log("OOB_QID", f"qid={qid}", "warning")
        return jsonify({"error": "Question not in active quiz"}), 403
    cur = get_cursor()
    cur.execute("SELECT correct_answer FROM questions WHERE id = %s", (qid,))
    row = cur.fetchone()
    if not row: return jsonify({"error": "Question not found"}), 404
    return jsonify({"correct": user_ans == row["correct_answer"], "correct_answer": row["correct_answer"]})

@app.route("/api/save_result", methods=["POST"])
@limiter.limit("50 per minute")
def save_result():
    data = request.get_json(silent=True)
    if not data: return jsonify({"error": "Invalid JSON"}), 400
    raw_name = str(data.get("player_name", ""))
    ok, msg  = validate_name(raw_name)
    if not ok:
        sec_log("INVALID_NAME", msg, "warning")
        return jsonify({"error": msg}), 400
    name   = sanitize(raw_name)
    cat_id = data.get("category_id"); score = data.get("score", 0)
    total  = data.get("total_questions", 10); ttime = data.get("time_taken", 0)
    if not isinstance(cat_id, int) or cat_id < 1: return jsonify({"error": "Invalid category"}), 400
    if not isinstance(score,  int) or score < 0:  return jsonify({"error": "Invalid score"}), 400
    if not isinstance(total,  int) or not (1 <= total <= MAX_LIMIT): return jsonify({"error": "Invalid total"}), 400
    if not isinstance(ttime,  int) or not (0 <= ttime <= 7200):      return jsonify({"error": "Invalid time"}), 400
    if score > total: return jsonify({"error": "Score cannot exceed total"}), 400
    cur = get_cursor()
    cur.execute("SELECT id FROM categories WHERE id = %s", (cat_id,))
    if not cur.fetchone(): return jsonify({"error": "Category not found"}), 404
    cur.execute(
        "INSERT INTO results(player_name, category_id, score, total_questions, time_taken) VALUES(%s,%s,%s,%s,%s)",
        (name, cat_id, score, total, ttime)
    )
    db_commit()
    sec_log("QUIZ_COMPLETE", f"player={name!r} cat={cat_id} score={score}/{total}")
    return jsonify({"status": "saved"})

@app.route("/api/leaderboard")
@limiter.limit("100 per minute")
def leaderboard():
    cat_id = request.args.get("category_id", type=int)
    cur    = get_cursor()
    if cat_id is not None:
        if cat_id < 1: return jsonify({"error": "Invalid category"}), 400
        cur.execute(
            "SELECT r.player_name,r.score,r.total_questions,r.time_taken,r.played_at,c.name AS category,c.icon FROM results r JOIN categories c ON r.category_id=c.id WHERE r.category_id=%s ORDER BY r.score DESC,r.time_taken ASC LIMIT 10",
            (cat_id,)
        )
    else:
        cur.execute("SELECT r.player_name,r.score,r.total_questions,r.time_taken,r.played_at,c.name AS category,c.icon FROM results r JOIN categories c ON r.category_id=c.id ORDER BY r.score DESC,r.time_taken ASC LIMIT 10")
    return jsonify([dict(r) for r in cur.fetchall()])

@app.route("/api/stats")
@limiter.limit("100 per minute")
def stats():
    cur = get_cursor()
    cur.execute("SELECT COUNT(*) AS c FROM results");                             total = cur.fetchone()["c"]
    cur.execute("SELECT AVG(CAST(score AS REAL)/total_questions*100) AS a FROM results"); avg = cur.fetchone()["a"]
    cur.execute("SELECT player_name, SUM(score) AS ts FROM results GROUP BY player_name ORDER BY ts DESC LIMIT 1")
    top = cur.fetchone()
    return jsonify({"total_games": total, "avg_score": round(avg or 0, 1), "top_player": dict(top) if top else None})

# ── Interview API ──────────────────────────────────────────────────────────────
@app.route("/api/interview/companies")
@limiter.limit("200 per minute")
def iv_companies():
    cur = get_cursor()
    cur.execute("""
        SELECT c.*, COUNT(q.id) AS q_count, ROUND(AVG(q.rating)::numeric, 1) AS avg_rating
        FROM interview_companies c
        LEFT JOIN interview_questions q ON c.id = q.company_id
        GROUP BY c.id ORDER BY c.id
    """)
    return jsonify([dict(r) for r in cur.fetchall()])

@app.route("/api/interview/questions")
@limiter.limit("100 per minute")
def iv_questions():
    company_id = request.args.get("company_id", type=int)
    topic      = sanitize(request.args.get("topic", ""))
    difficulty = request.args.get("difficulty", "")
    search     = sanitize(request.args.get("search", ""))
    if difficulty and difficulty not in ("easy", "medium", "hard"):
        return jsonify({"error": "Invalid difficulty"}), 400
    cur = get_cursor()
    sql = "SELECT q.*,c.name AS company_name,c.logo,c.color FROM interview_questions q JOIN interview_companies c ON q.company_id=c.id WHERE 1=1"
    params = []
    if company_id:
        if company_id < 1: return jsonify({"error": "Invalid company"}), 400
        sql += " AND q.company_id=%s"; params.append(company_id)
    if topic:      sql += " AND q.topic=%s";        params.append(topic)
    if difficulty: sql += " AND q.difficulty=%s";   params.append(difficulty)
    if search:
        sql += " AND (q.question ILIKE %s OR q.tags ILIKE %s OR q.topic ILIKE %s)"
        params += [f"%{search}%"] * 3
    sql += " ORDER BY q.times_asked DESC, q.rating DESC"
    cur.execute(sql, params)
    return jsonify([dict(r) for r in cur.fetchall()])

@app.route("/api/interview/topics")
@limiter.limit("200 per minute")
def iv_topics():
    cur = get_cursor()
    cur.execute("SELECT DISTINCT topic FROM interview_questions ORDER BY topic")
    return jsonify([r["topic"] for r in cur.fetchall()])

# ── Admin Stats ────────────────────────────────────────────────────────────────
@app.route("/api/admin/stats")
@admin_required
def admin_stats():
    cur = get_cursor()
    def count(sql):
        cur.execute(sql); return cur.fetchone()["c"]
    cur.execute("""
        SELECT c.id, c.name, c.icon, COUNT(q.id) AS cnt
        FROM categories c LEFT JOIN questions q ON c.id=q.category_id GROUP BY c.id
    """)
    cats = [dict(r) for r in cur.fetchall()]
    return jsonify({
        "total_users":     count("SELECT COUNT(*) AS c FROM users"),
        "total_quiz_q":    count("SELECT COUNT(*) AS c FROM questions"),
        "total_iv_q":      count("SELECT COUNT(*) AS c FROM interview_questions"),
        "total_games":     count("SELECT COUNT(*) AS c FROM results"),
        "total_companies": count("SELECT COUNT(*) AS c FROM interview_companies"),
        "categories": cats,
    })

# ── Admin: Quiz Questions CRUD ─────────────────────────────────────────────────
@app.route("/api/admin/quiz/questions")
@admin_required
def admin_quiz_list():
    cat_id = request.args.get("category_id", type=int)
    search = sanitize(request.args.get("search", ""))
    cur    = get_cursor()
    sql    = "SELECT q.*,c.name AS cat_name FROM questions q JOIN categories c ON q.category_id=c.id WHERE 1=1"
    params = []
    if cat_id: sql += " AND q.category_id=%s"; params.append(cat_id)
    if search: sql += " AND q.question ILIKE %s"; params.append(f"%{search}%")
    sql += " ORDER BY q.category_id, q.id"
    cur.execute(sql, params)
    return jsonify([dict(r) for r in cur.fetchall()])

@app.route("/api/admin/quiz/questions", methods=["POST"])
@admin_required
def admin_quiz_add():
    d = request.get_json(silent=True)
    if not d: return jsonify({"error": "Invalid JSON"}), 400
    cat_id = d.get("category_id")
    q = sanitize(str(d.get("question",""))); a = sanitize(str(d.get("option_a","")))
    b = sanitize(str(d.get("option_b",""))); c_ = sanitize(str(d.get("option_c","")))
    dd = sanitize(str(d.get("option_d",""))); correct = str(d.get("correct_answer","")).upper().strip()
    diff = str(d.get("difficulty","medium")).lower()
    if not all([q,a,b,c_,dd]): return jsonify({"error":"All fields required"}),400
    if correct not in VALID_ANS: return jsonify({"error":"Correct answer must be A/B/C/D"}),400
    if diff not in ("easy","medium","hard"): return jsonify({"error":"Invalid difficulty"}),400
    if not isinstance(cat_id,int) or cat_id<1: return jsonify({"error":"Invalid category"}),400
    cur = get_cursor()
    cur.execute("SELECT id FROM categories WHERE id=%s",(cat_id,))
    if not cur.fetchone(): return jsonify({"error":"Category not found"}),404
    cur.execute("INSERT INTO questions(category_id,question,option_a,option_b,option_c,option_d,correct_answer,difficulty) VALUES(%s,%s,%s,%s,%s,%s,%s,%s) RETURNING id",
                (cat_id,q,a,b,c_,dd,correct,diff))
    new_id = cur.fetchone()['id']; db_commit()
    sec_log("ADMIN_ADD_QUIZ_Q", f"id={new_id}")
    return jsonify({"status":"added","id":new_id})

@app.route("/api/admin/quiz/questions/<int:qid>", methods=["PUT"])
@admin_required
def admin_quiz_edit(qid):
    d = request.get_json(silent=True)
    if not d: return jsonify({"error":"Invalid JSON"}),400
    cur = get_cursor()
    cur.execute("SELECT id FROM questions WHERE id=%s",(qid,))
    if not cur.fetchone(): return jsonify({"error":"Question not found"}),404
    cat_id = d.get("category_id")
    q = sanitize(str(d.get("question",""))); a = sanitize(str(d.get("option_a","")))
    b = sanitize(str(d.get("option_b",""))); c_ = sanitize(str(d.get("option_c","")))
    dd = sanitize(str(d.get("option_d",""))); correct = str(d.get("correct_answer","")).upper().strip()
    diff = str(d.get("difficulty","medium")).lower()
    if not all([q,a,b,c_,dd]): return jsonify({"error":"All fields required"}),400
    if correct not in VALID_ANS: return jsonify({"error":"Correct answer must be A/B/C/D"}),400
    if diff not in ("easy","medium","hard"): return jsonify({"error":"Invalid difficulty"}),400
    cur.execute("UPDATE questions SET category_id=%s,question=%s,option_a=%s,option_b=%s,option_c=%s,option_d=%s,correct_answer=%s,difficulty=%s WHERE id=%s",
                (cat_id,q,a,b,c_,dd,correct,diff,qid))
    db_commit(); sec_log("ADMIN_EDIT_QUIZ_Q", f"id={qid}")
    return jsonify({"status":"updated"})

@app.route("/api/admin/quiz/questions/<int:qid>", methods=["DELETE"])
@admin_required
def admin_quiz_delete(qid):
    cur = get_cursor()
    cur.execute("SELECT id FROM questions WHERE id=%s",(qid,))
    if not cur.fetchone(): return jsonify({"error":"Question not found"}),404
    cur.execute("DELETE FROM questions WHERE id=%s",(qid,)); db_commit()
    sec_log("ADMIN_DEL_QUIZ_Q", f"id={qid}")
    return jsonify({"status":"deleted"})

# ── Admin: Interview Questions CRUD ───────────────────────────────────────────
@app.route("/api/admin/interview/questions")
@admin_required
def admin_iv_list():
    company_id = request.args.get("company_id", type=int)
    search = sanitize(request.args.get("search",""))
    cur = get_cursor()
    sql = "SELECT q.*,c.name AS company_name FROM interview_questions q JOIN interview_companies c ON q.company_id=c.id WHERE 1=1"
    params = []
    if company_id: sql += " AND q.company_id=%s"; params.append(company_id)
    if search:     sql += " AND q.question ILIKE %s"; params.append(f"%{search}%")
    sql += " ORDER BY q.company_id, q.id"
    cur.execute(sql, params)
    return jsonify([dict(r) for r in cur.fetchall()])

@app.route("/api/admin/interview/questions", methods=["POST"])
@admin_required
def admin_iv_add():
    d = request.get_json(silent=True)
    if not d: return jsonify({"error":"Invalid JSON"}),400
    company_id = d.get("company_id"); topic = sanitize(str(d.get("topic","")))
    question = sanitize(str(d.get("question",""))); answer = sanitize(str(d.get("answer","")))
    notes = sanitize(str(d.get("notes",""))); difficulty = str(d.get("difficulty","medium")).lower()
    rating = float(d.get("rating",4.0)); times_asked = int(d.get("times_asked",1))
    last_year = d.get("last_year"); years_asked = sanitize(str(d.get("years_asked","")))
    role_level = sanitize(str(d.get("role_level","Fresher"))); tags = sanitize(str(d.get("tags","")))
    if not all([topic,question,answer]): return jsonify({"error":"Topic, question and answer required"}),400
    if difficulty not in ("easy","medium","hard"): return jsonify({"error":"Invalid difficulty"}),400
    if not isinstance(company_id,int) or company_id<1: return jsonify({"error":"Invalid company"}),400
    if not (1.0 <= rating <= 5.0): return jsonify({"error":"Rating must be 1.0-5.0"}),400
    cur = get_cursor()
    cur.execute("SELECT id FROM interview_companies WHERE id=%s",(company_id,))
    if not cur.fetchone(): return jsonify({"error":"Company not found"}),404
    cur.execute("INSERT INTO interview_questions(company_id,topic,question,answer,notes,difficulty,rating,times_asked,last_year,years_asked,role_level,tags) VALUES(%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s) RETURNING id",
                (company_id,topic,question,answer,notes,difficulty,rating,times_asked,last_year,years_asked,role_level,tags))
    new_id = cur.fetchone()['id']; db_commit()
    sec_log("ADMIN_ADD_IV_Q", f"id={new_id}"); return jsonify({"status":"added","id":new_id})

@app.route("/api/admin/interview/questions/<int:qid>", methods=["PUT"])
@admin_required
def admin_iv_edit(qid):
    d = request.get_json(silent=True)
    if not d: return jsonify({"error":"Invalid JSON"}),400
    cur = get_cursor()
    cur.execute("SELECT id FROM interview_questions WHERE id=%s",(qid,))
    if not cur.fetchone(): return jsonify({"error":"Question not found"}),404
    company_id = d.get("company_id"); topic = sanitize(str(d.get("topic","")))
    question = sanitize(str(d.get("question",""))); answer = sanitize(str(d.get("answer","")))
    notes = sanitize(str(d.get("notes",""))); difficulty = str(d.get("difficulty","medium")).lower()
    rating = float(d.get("rating",4.0)); times_asked = int(d.get("times_asked",1))
    last_year = d.get("last_year"); years_asked = sanitize(str(d.get("years_asked","")))
    role_level = sanitize(str(d.get("role_level","Fresher"))); tags = sanitize(str(d.get("tags","")))
    if not all([topic,question,answer]): return jsonify({"error":"Topic, question and answer required"}),400
    if difficulty not in ("easy","medium","hard"): return jsonify({"error":"Invalid difficulty"}),400
    cur.execute("UPDATE interview_questions SET company_id=%s,topic=%s,question=%s,answer=%s,notes=%s,difficulty=%s,rating=%s,times_asked=%s,last_year=%s,years_asked=%s,role_level=%s,tags=%s WHERE id=%s",
                (company_id,topic,question,answer,notes,difficulty,rating,times_asked,last_year,years_asked,role_level,tags,qid))
    db_commit(); sec_log("ADMIN_EDIT_IV_Q", f"id={qid}")
    return jsonify({"status":"updated"})

@app.route("/api/admin/interview/questions/<int:qid>", methods=["DELETE"])
@admin_required
def admin_iv_delete(qid):
    cur = get_cursor()
    cur.execute("SELECT id FROM interview_questions WHERE id=%s",(qid,))
    if not cur.fetchone(): return jsonify({"error":"Question not found"}),404
    cur.execute("DELETE FROM interview_questions WHERE id=%s",(qid,)); db_commit()
    sec_log("ADMIN_DEL_IV_Q", f"id={qid}"); return jsonify({"status":"deleted"})

# ── Admin: Users ───────────────────────────────────────────────────────────────
@app.route("/api/admin/users")
@admin_required
def admin_users():
    cur = get_cursor()
    cur.execute("SELECT id,username,email,full_name,is_admin,is_active,created_at,last_login FROM users ORDER BY id")
    return jsonify([dict(r) for r in cur.fetchall()])

@app.route("/api/admin/users/<int:uid>/toggle", methods=["POST"])
@admin_required
def admin_toggle_user(uid):
    if uid == session['user_id']:
        return jsonify({"error":"Cannot deactivate yourself"}),400
    cur = get_cursor()
    cur.execute("SELECT is_active, username FROM users WHERE id=%s",(uid,))
    u = cur.fetchone()
    if not u: return jsonify({"error":"User not found"}),404
    new_state = not u['is_active']
    cur.execute("UPDATE users SET is_active=%s WHERE id=%s",(new_state,uid)); db_commit()
    sec_log("ADMIN_TOGGLE_USER", f"uid={uid} active={new_state}")
    return jsonify({"status":"ok","is_active":new_state})

@app.route("/api/admin/users/<int:uid>", methods=["DELETE"])
@admin_required
def admin_delete_user(uid):
    if uid == session['user_id']:
        return jsonify({"error":"Cannot delete yourself"}),400
    cur = get_cursor()
    cur.execute("SELECT username, is_admin FROM users WHERE id=%s",(uid,))
    u = cur.fetchone()
    if not u: return jsonify({"error":"User not found"}),404
    if u['is_admin']: return jsonify({"error":"Cannot delete admin accounts"}),403
    cur.execute("DELETE FROM users WHERE id=%s",(uid,)); db_commit()
    sec_log("ADMIN_DEL_USER", f"uid={uid} username={u['username']}")
    return jsonify({"status":"deleted"})

# ── Admin: Categories & Companies ─────────────────────────────────────────────
@app.route("/api/admin/categories")
@admin_required
def admin_categories():
    cur = get_cursor()
    cur.execute("SELECT * FROM categories ORDER BY id")
    return jsonify([dict(r) for r in cur.fetchall()])

@app.route("/api/admin/companies")
@admin_required
def admin_companies():
    cur = get_cursor()
    cur.execute("SELECT * FROM interview_companies ORDER BY id")
    return jsonify([dict(r) for r in cur.fetchall()])

# ── Entry point ────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    init_db()
    print("\n" + "="*58)
    print("  QuizMaster Pro  —  PostgreSQL Edition")
    print("  URL   : http://127.0.0.1:5000")
    print("  Admin : http://127.0.0.1:5000/admin")
    print("  Login : admin  /  Admin@1234")
    print("="*58 + "\n")
    app.run(host="0.0.0.0", port=5000, debug=False)
else:
    init_db()
