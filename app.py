"""
QuizMaster Pro — Flask Backend (Final Version)
OWASP Top 10 hardened | Quiz + Interview Prep
"""
import os, re, logging, secrets
from datetime import timedelta
import bleach, sqlite3
from datetime import datetime
from functools import wraps
from werkzeug.security import generate_password_hash, check_password_hash
from flask import Flask, render_template, request, jsonify, session, g, redirect, url_for
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_talisman import Talisman

app = Flask(__name__)
app.secret_key = secrets.token_hex(32)
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE='Lax',
    SESSION_COOKIE_SECURE=False,
    PERMANENT_SESSION_LIFETIME=timedelta(hours=2),
    MAX_CONTENT_LENGTH=16 * 1024,
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

DB_PATH      = os.path.join(os.path.dirname(os.path.abspath(__file__)), "quiz.db")
MAX_NAME_LEN = 30
MIN_NAME_LEN = 2
MAX_LIMIT    = 20
VALID_ANS    = {"A", "B", "C", "D"}

# ── Helpers ───────────────────────────────────────────────────────────────────
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

def get_db():
    if 'db' not in g:
        c = sqlite3.connect(DB_PATH)
        c.row_factory = sqlite3.Row
        c.execute("PRAGMA foreign_keys = ON")
        g.db = c
    return g.db

@app.teardown_appcontext
def close_db(e):
    db = g.pop('db', None)
    if db: db.close()

def sec_log(ev, detail="", level="info"):
    getattr(logger, level)(f"[{ev}] ip={request.remote_addr} | {detail}")

# ── DB Init ───────────────────────────────────────────────────────────────────
def init_db():
    conn = sqlite3.connect(DB_PATH)
    conn.execute("PRAGMA foreign_keys = ON")
    c = conn.cursor()

    c.execute("""CREATE TABLE IF NOT EXISTS categories(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL, icon TEXT NOT NULL, color TEXT NOT NULL)""")

    c.execute("""CREATE TABLE IF NOT EXISTS questions(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        category_id INTEGER NOT NULL,
        question TEXT NOT NULL,
        option_a TEXT NOT NULL, option_b TEXT NOT NULL,
        option_c TEXT NOT NULL, option_d TEXT NOT NULL,
        correct_answer TEXT NOT NULL CHECK(correct_answer IN('A','B','C','D')),
        difficulty TEXT NOT NULL DEFAULT 'medium' CHECK(difficulty IN('easy','medium','hard')),
        FOREIGN KEY(category_id) REFERENCES categories(id))""")

    c.execute("""CREATE TABLE IF NOT EXISTS results(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        player_name TEXT NOT NULL, category_id INTEGER NOT NULL,
        score INTEGER NOT NULL CHECK(score>=0),
        total_questions INTEGER NOT NULL CHECK(total_questions>0),
        time_taken INTEGER NOT NULL CHECK(time_taken>=0),
        played_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY(category_id) REFERENCES categories(id))""")

    c.execute("""CREATE TABLE IF NOT EXISTS audit_log(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        event TEXT NOT NULL, ip_address TEXT, detail TEXT,
        ts TIMESTAMP DEFAULT CURRENT_TIMESTAMP)""")

    c.execute("""CREATE TABLE IF NOT EXISTS users(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT NOT NULL UNIQUE,
        email TEXT NOT NULL UNIQUE,
        password_hash TEXT NOT NULL,
        full_name TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        last_login TIMESTAMP,
        is_active INTEGER DEFAULT 1,
        is_admin  INTEGER DEFAULT 0)""")


    # ── Seed default admin account
    c.execute("SELECT COUNT(*) FROM users WHERE is_admin=1")
    if c.fetchone()[0] == 0:
        from werkzeug.security import generate_password_hash as gph
        c.execute(
            "INSERT INTO users(username,email,password_hash,full_name,is_admin) VALUES(?,?,?,?,1)",
            ("admin","admin@quizmaster.com", gph("Admin@1234", method="pbkdf2:sha256", salt_length=16), "Administrator")
        )

    c.execute("""CREATE TABLE IF NOT EXISTS interview_companies(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL, logo TEXT NOT NULL, color TEXT NOT NULL,
        type TEXT NOT NULL, founded INTEGER, hq TEXT)""")

    c.execute("""CREATE TABLE IF NOT EXISTS interview_questions(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        company_id INTEGER NOT NULL, topic TEXT NOT NULL,
        question TEXT NOT NULL, answer TEXT NOT NULL, notes TEXT,
        difficulty TEXT NOT NULL DEFAULT 'medium' CHECK(difficulty IN('easy','medium','hard')),
        rating REAL NOT NULL DEFAULT 4.0,
        times_asked INTEGER NOT NULL DEFAULT 1,
        last_year INTEGER, years_asked TEXT,
        role_level TEXT NOT NULL DEFAULT 'Fresher', tags TEXT,
        FOREIGN KEY(company_id) REFERENCES interview_companies(id))""")

    # ── Seed categories
    c.execute("SELECT COUNT(*) FROM categories")
    if c.fetchone()[0] == 0:
        c.executemany("INSERT INTO categories(name,icon,color) VALUES(?,?,?)", [
            ("Python Programming","🐍","#4ade80"),
            ("Cybersecurity","🔐","#f472b6"),
            ("Data Structures","🌳","#60a5fa"),
            ("Operating Systems","💻","#fb923c"),
            ("Computer Networks","🌐","#a78bfa"),
        ])

    # ── Seed quiz questions (50+ per category)
    c.execute("SELECT COUNT(*) FROM questions")
    if c.fetchone()[0] == 0:
        q = [
            # PYTHON (cat 1)
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
            # CYBERSECURITY (cat 2)
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
            (2,"Logic bomb is?","Physical bomb","Malicious code triggered by condition","Network worm","Trojan horse","B","hard"),
            (2,"Ethical hacking is?","Illegal hacking","Authorized security testing","Social engineering","Password cracking","B","easy"),
            (2,"Penetration testing is?","Testing hardware","Simulating attacks to find vulnerabilities","Network speed test","Stress test","B","medium"),
            (2,"Trojan horse malware?","Legitimate-looking malware","A firewall","Antivirus program","A network protocol","A","medium"),
            (2,"Dark web is?","Unlit data center","Encrypted internet not indexed by search engines","Deep internet archive","None","B","medium"),
            (2,"Keylogger does?","Typing tutor","Records keystrokes to steal credentials","Keyboard driver","Input validator","B","medium"),
            (2,"Risk assessment in security?","Speed measurement","Identifying and evaluating threats","Testing hardware","Backing up data","B","medium"),
            (2,"SSH runs on which port?","21","22","23","25","B","easy"),
            (2,"What is a DMZ?","Military zone","Network segment between internet and internal network","DNS zone","None","B","hard"),
            (2,"What is privilege escalation?","Giving more RAM","Gaining higher access than authorized","Updating software","None","B","hard"),
            (2,"What is a WAF bypass?","Fixing WAF","Evading web application firewall detection","WAF configuration","None","B","hard"),
            (2,"What does netcat do?","Antivirus scan","Network utility for reading/writing connections","Disk scanner","None","B","medium"),
            (2,"What is OSINT?","Security tool","Open-Source Intelligence gathering","Network scanning","Password cracking","B","medium"),
            (2,"What is a payload in hacking?","Package weight","Malicious code executed on target","Network packet","Encryption key","B","medium"),
            (2,"What is enumeration in hacking?","Counting files","Extracting information about target system","Encrypting data","None","B","medium"),
            (2,"What is a bind shell?","Reverse shell","Shell listening on target machine for connection","Forward proxy","None","B","hard"),
            (2,"What is Metasploit?","Antivirus","Penetration testing framework","Firewall","Network monitor","B","medium"),
            (2,"What is Wireshark used for?","Password cracking","Packet capture and analysis","Port scanning","Exploitation","B","easy"),
            # DATA STRUCTURES (cat 3)
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
            (3,"Circular linked list means?","No end node","Last node points to head","Doubly linked","List with cycles","B","medium"),
            (3,"Stack overflow is?","Stack is full","Call stack exceeds limit","Array overflow","Queue overflow","B","easy"),
            (3,"Priority queue serves?","First in first out","Highest priority first","Last in first out","Random","B","medium"),
            (3,"Merge sort time complexity?","O(n^2)","O(n log n)","O(n)","O(log n)","B","medium"),
            (3,"Balanced BST height difference?","Exactly 0","At most 1","At most 2","Unlimited","B","medium"),
            (3,"AVL tree is?","Self-balancing BST","Unbalanced BST","Heap structure","Graph type","A","hard"),
            (3,"BFS uses which structure?","Stack","Queue","Heap","Array","B","medium"),
            (3,"DFS uses which structure?","Queue","Heap","Stack","Array","C","medium"),
            (3,"Spanning tree has?","All cycles","All vertices, no cycles","Complete graph","None","B","medium"),
            (3,"Kruskal's algorithm finds?","Shortest path","Minimum spanning tree","Topological order","Connected components","B","hard"),
            (3,"Dynamic programming requires?","Optimal substructure only","Overlapping subproblems only","Both optimal substructure and overlapping subproblems","Neither","C","hard"),
            (3,"Memoization means?","Memory management","Caching results of function calls","Sorting algorithm","Graph traversal","B","medium"),
            (3,"Trie is used for?","Number storage","String prefix search","Graph traversal","Sorting","B","hard"),
            (3,"Graph is made of?","Arrays only","Vertices and edges","Tree nodes","Queue elements","B","easy"),
            (3,"Adjacency matrix space?","O(V+E)","O(V^2)","O(E)","O(V)","B","medium"),
            (3,"Heap sort builds?","AVL tree","Max or min heap","BST","Hash table","B","medium"),
            (3,"BST inorder gives?","Random order","Sorted ascending","Descending","Level-by-level","B","medium"),
            (3,"Hash table insert average?","O(n)","O(log n)","O(1)","O(n^2)","C","easy"),
            (3,"Complete binary tree means?","All levels full except possibly last","All leaves same level","One child per node","None","A","medium"),
            (3,"Merge sort space complexity?","O(1)","O(log n)","O(n)","O(n^2)","C","medium"),
            (3,"Floyd-Warshall is for?","Single source shortest path","All-pairs shortest path","Minimum spanning tree","Topological sort","B","hard"),
            (3,"B-tree is used in?","RAM only","Databases and file systems","CPU cache","None","B","hard"),
            (3,"Backtracking does?","Goes forward only","Abandons invalid paths and tries others","DFS variant","Dynamic programming","B","hard"),
            (3,"Selection sort worst case?","O(n log n)","O(n^2)","O(n)","O(1)","B","easy"),
            (3,"Graph cycle is?","Disconnected graph","Path starting and ending at same vertex","Acyclic graph","None","B","medium"),
            (3,"Topological sort works on?","Any graph","Directed Acyclic Graph (DAG)","Undirected graph","Tree only","B","hard"),
            (3,"Union-Find tracks?","Minimum path","Set membership and connectivity","Shortest path","Tree height","B","hard"),
            (3,"Insertion sort best case?","O(n^2)","O(n log n)","O(n)","O(1)","C","medium"),
            (3,"Red-black tree property?","Random coloring","Balanced BST with color-based rules","Heap order","None","B","hard"),
            (3,"Linked list access time?","O(1)","O(log n)","O(n)","O(n^2)","C","easy"),
            (3,"Segment tree is for?","String matching","Range queries and updates","Graph traversal","Sorting","B","hard"),
            (3,"Counting sort works best for?","Large range float values","Small range integers","Strings","Linked lists","B","medium"),
            (3,"Two pointer technique reduces?","O(n) to O(1)","O(n^2) to O(n)","O(log n) to O(1)","O(n) to O(log n)","B","medium"),
            (3,"What is a sparse matrix?","Matrix with many zeros","Dense matrix","Square matrix","None","A","medium"),
            (3,"Post-order traversal visits?","Root, Left, Right","Left, Root, Right","Left, Right, Root","Right, Root, Left","C","medium"),
            (3,"Bubble sort best case?","O(n^2)","O(n log n)","O(n)","O(1)","C","medium"),
            (3,"What is a graph's in-degree?","Outgoing edges count","Incoming edges count","Total edges","None","B","medium"),
            (3,"Radix sort is based on?","Comparison","Digit-by-digit sorting","Divide and conquer","Hashing","B","hard"),
            (3,"Stack supports which operations?","Enqueue Dequeue","Push Pop Peek","Insert Delete Search","None","B","easy"),
            (3,"What is an undirected graph?","Edges have direction","Edges have no direction","Graph with weights","Graph with no cycles","B","easy"),
            # OPERATING SYSTEMS (cat 4)
            (4,"Deadlock means?","CPU overload","Processes waiting forever for each other","Memory leak","Kernel panic","B","medium"),
            (4,"BIOS stands for?","Basic I/O System","Binary Input Output System","Basic Input Output System","Base Internal OS","C","easy"),
            (4,"FCFS has minimum overhead because?","It is preemptive","It is non-preemptive and simple","It uses priorities","It uses time slices","B","medium"),
            (4,"Thrashing means?","CPU spike","Excessive paging causing slowdown","Disk failure","Memory corruption","B","hard"),
            (4,"Semaphore is used for?","Memory allocation","Process synchronization","File management","CPU scheduling","B","medium"),
            (4,"PCB stores?","File paths","Process state info registers and resources","Network config","Disk partitions","B","easy"),
            (4,"Fastest memory is?","RAM","Cache (L1/L2/L3)","HDD","ROM","B","easy"),
            (4,"Virtual memory uses?","Extra physical RAM","Disk space as RAM extension","GPU memory","Cloud storage","B","medium"),
            (4,"Process is?","A file","Program in execution with its own resources","A thread","A semaphore","B","easy"),
            (4,"Thread is?","Independent process","Lightweight unit within a process sharing memory","Kernel module","File handle","B","easy"),
            (4,"Context switching is?","CPU switching processes","Process migration","Memory swap","Thread creation","A","medium"),
            (4,"Scheduler decides?","File storage","Which process runs on CPU next","Memory allocation","Network routing","B","medium"),
            (4,"Round Robin scheduling uses?","Priority order","Fixed time slice per process","FCFS order","Shortest job first","B","easy"),
            (4,"Page fault is?","Hard drive failure","Accessing page not currently in RAM","CPU error","Network error","B","medium"),
            (4,"Spooling stands for?","Network buffering","Simultaneous Peripheral Operations On-Line","Thread pooling","None","B","medium"),
            (4,"Critical section is?","CPU register","Code accessing shared resources","Memory segment","Cache block","B","medium"),
            (4,"Mutex provides?","Multi-user access","Mutual Exclusion - one thread at a time","Memory pooling","None","B","medium"),
            (4,"Mutex vs Semaphore?","Same thing","Mutex is binary lock, semaphore has count","Semaphore is binary","None","B","hard"),
            (4,"Zombie process is?","Dead process","Finished process with parent not collected exit status","Hanging process","Background process","B","hard"),
            (4,"Orphan process is?","Process with no threads","Process whose parent has died","Background process","Daemon","B","hard"),
            (4,"Demand paging means?","Load all pages at start","Load pages only when needed","Swap all pages","None","B","medium"),
            (4,"Fragmentation means?","Memory error","Wasted unusable gaps in memory","Cache miss","None","B","medium"),
            (4,"Internal fragmentation is?","Wasted space outside block","Wasted space inside allocated block","RAM overflow","None","B","medium"),
            (4,"External fragmentation is?","Wasted space inside block","Non-contiguous free memory chunks","Cache issue","None","B","medium"),
            (4,"File system does?","Run programs","Organizes files on storage media","Network routing","User authentication","B","easy"),
            (4,"Inode in Linux stores?","File name","File metadata (size permissions timestamps)","Directory entry","None","B","hard"),
            (4,"System call is?","App calling another app","Program requesting OS kernel service","Network call","None","B","medium"),
            (4,"Kernel is?","User application","Core OS managing hardware resources","File manager","Network driver","B","easy"),
            (4,"Daemon is?","User program","Background service process","Kernel module","Thread","B","medium"),
            (4,"Cache memory is?","Hard disk buffer","Fast memory between CPU and RAM","RAM type","SSD","B","easy"),
            (4,"LRU page replacement stands for?","Least Recently Used","Least Requested Update","Last Random Unit","None","A","medium"),
            (4,"Preemptive scheduling means?","Non-interruptible","OS can forcibly interrupt running process","FCFS only","None","B","medium"),
            (4,"Starvation means?","Low food supply","Low-priority process never gets CPU time","Memory shortage","Deadlock","B","medium"),
            (4,"Aging prevents?","Cache misses","Starvation by increasing priority over time","Deadlocks","Page faults","B","medium"),
            (4,"Multiprogramming means?","Multiple programs installed","Multiple programs in memory at same time","Multi-core CPU","None","B","easy"),
            (4,"Time-sharing OS allows?","One user at a time","Multiple users to share CPU time","Batch only","Real-time only","B","easy"),
            (4,"fork() in Linux does?","Splits file","Creates child process copy of parent","Deletes process","Switches process","B","medium"),
            (4,"exec() system call does?","Execute shell script","Replaces current process with new program","Creates thread","None","B","hard"),
            (4,"Race condition means?","CPU speed","Unexpected results from concurrent shared data access","Network race","None","B","medium"),
            (4,"RAID stands for?","RAM Array Integrated Device","Redundant Array of Independent Disks","Random Access Integrated Disk","None","B","medium"),
            (4,"Interrupt is?","Program error","Signal causing CPU to pause and handle event","Memory fault","None","B","medium"),
            (4,"Belady's anomaly affects?","LRU","FIFO page replacement","LFU","Optimal","B","hard"),
            (4,"What is a pipe in OS?","Fluid transfer","IPC mechanism connecting output of one process to input of another","Memory segment","None","B","medium"),
            (4,"What is shared memory?","Common RAM","Memory region accessible by multiple processes simultaneously","Cache","None","B","medium"),
            (4,"What is a bootloader?","OS itself","Program that loads OS into memory at startup","BIOS replacement","None","B","medium"),
            (4,"Paging eliminates?","Internal fragmentation","External fragmentation","Both","Neither","B","medium"),
            (4,"What is segmentation?","Paging variant","Dividing memory into variable-size segments","Cache technique","None","B","hard"),
            (4,"What is a soft link (symlink)?","Hard copy of file","Pointer/shortcut to another file","Compressed file","None","B","medium"),
            (4,"What is swapping in OS?","Data exchange","Moving entire process between RAM and disk","File compression","None","B","medium"),
            (4,"What is a real-time OS?","Slow OS","OS that guarantees response within strict time constraints","Gaming OS","None","B","medium"),
            # COMPUTER NETWORKS (cat 5)
            (5,"DNS resolves?","IP to MAC","Domain name to IP address","IP to hostname","URL to port","B","easy"),
            (5,"IP operates at OSI layer?","Transport (4)","Application (7)","Network (3)","Data Link (2)","C","medium"),
            (5,"ARP is used for?","Routing packets","Resolving IP to MAC address","DNS lookup","Firewall rules","B","medium"),
            (5,"TTL stands for?","Time To Load","Total Transfer Limit","Time To Live","Transfer Through Layer","C","easy"),
            (5,"Connectionless protocol?","TCP","FTP","HTTP","UDP","D","easy"),
            (5,"Subnet mask identifies?","Encryption key","Network and host portions of IP","DNS server","Packet filter","B","medium"),
            (5,"BGP is used for?","LAN routing","Routing between autonomous systems","WiFi security","Load balancing","B","hard"),
            (5,"OSI layer handling encryption?","Network (3)","Transport (4)","Presentation (6)","Session (5)","C","medium"),
            (5,"MAC address is?","IP identifier","Hardware network interface identifier","Domain name","Port number","B","easy"),
            (5,"DHCP stands for?","Dynamic Host Configuration Protocol","DNS Host Control Program","Data Hub Control Protocol","None","A","easy"),
            (5,"NAT stands for?","Network Address Translation","Node Access Token","Network Analysis Tool","None","A","medium"),
            (5,"Router does?","Connects same network devices","Connects different networks and routes packets","Acts as firewall","Acts as switch","B","easy"),
            (5,"Switch uses?","IP addresses","MAC addresses to forward frames","Domain names","Port numbers","B","easy"),
            (5,"HTTP is?","Secure protocol","HyperText Transfer Protocol for web","Email protocol","File transfer","B","easy"),
            (5,"FTP is used for?","Web browsing","File transfer between systems","Email sending","DNS resolution","B","easy"),
            (5,"SMTP is used for?","Web browsing","Sending email","File transfer","DNS","B","easy"),
            (5,"Network packet is?","Complete file","Unit of data for transmission","Signal","Frame","B","easy"),
            (5,"Bandwidth means?","Signal strength","Maximum data transfer rate","Latency","Packet loss","B","easy"),
            (5,"Latency means?","Data rate","Time delay for data to travel source to destination","Bandwidth","Packet size","B","easy"),
            (5,"TCP 3-way handshake?","SYN ACK FIN","SYN SYN-ACK ACK","ACK SYN FIN","HELLO OK DONE","B","medium"),
            (5,"SSL/TLS provides?","File transfer","Encryption of data in transit","Email protocol","DNS security","B","medium"),
            (5,"Proxy server is?","Direct server","Intermediary between client and destination","Load balancer","DNS server","B","medium"),
            (5,"Load balancing does?","Speed test","Distributes traffic across multiple servers","Firewall function","Caching","B","medium"),
            (5,"CDN stands for?","Code Delivery Network","Content Delivery Network","None","Central DNS Node","B","medium"),
            (5,"ICMP is used for?","File transfer","Error messages and diagnostics (ping)","Web traffic","Email","B","medium"),
            (5,"VLAN means?","Virtual LAN isolating network segments","Virtual Machine","VPN type","None","A","medium"),
            (5,"Port 22 is for?","HTTP","SSH - Secure Shell","FTP","SMTP","B","easy"),
            (5,"Port 25 is for?","HTTP","SSH","FTP","SMTP","D","easy"),
            (5,"Hub does?","Smart routing","Broadcasts data to all connected devices","Routes between networks","Firewall","B","easy"),
            (5,"OSPF stands for?","Email protocol","Open Shortest Path First routing protocol","Firewall","DNS","B","hard"),
            (5,"Multicast sends to?","One host","Group of specific hosts","All hosts","Random host","B","medium"),
            (5,"IPv6 uses how many bits?","32","64","128","256","C","medium"),
            (5,"Socket is?","Hardware port","Software endpoint for network communication","IP address","DNS entry","B","medium"),
            (5,"Traceroute does?","Speed test","Traces path packets take to destination","Ping variant","None","B","medium"),
            (5,"QoS stands for?","Quality of Speed","Quality of Service - prioritizing traffic","Quantified Output System","None","B","medium"),
            (5,"STP prevents?","IP conflicts","Loops in switched networks","MAC conflicts","None","B","hard"),
            (5,"Port 443 is for?","HTTP","FTP","HTTPS","SMTP","C","easy"),
            (5,"Encapsulation in networking?","OOP concept","Wrapping data with protocol headers at each layer","Encryption","Compression","B","medium"),
            (5,"Broadcast domain is?","Routing area","Network area where broadcast reaches all devices","VLAN","Subnet","B","medium"),
            (5,"HTTPS vs HTTP?","Same thing","HTTPS encrypts data using TLS, HTTP does not","HTTP is newer","None","B","easy"),
            (5,"What is a collision domain?","MAC conflict zone","Network segment where collisions can occur","VLAN","None","B","medium"),
            (5,"What is IMAP?","Email sending protocol","Email retrieval protocol keeping mail on server","File protocol","DNS","B","medium"),
            (5,"What is a default gateway?","Local router IP","IP that routes traffic to outside networks","DNS server","Firewall IP","B","medium"),
            (5,"What is half-duplex?","Two-way simultaneous","One direction at a time","Full duplex","None","B","medium"),
            (5,"What is a network topology?","IP scheme","Physical or logical arrangement of network nodes","Routing protocol","None","B","easy"),
            (5,"Star topology has?","Nodes in a ring","All nodes connected to central hub/switch","Bus connection","None","B","easy"),
            (5,"What is a checksum?","Encryption","Value used for error detection in data","Compression","Routing","B","medium"),
            (5,"What is flow control in TCP?","Traffic routing","Managing rate of data transmission between sender and receiver","Firewall rule","None","B","hard"),
            (5,"What is congestion control?","Traffic jam detection","Preventing network overload by managing data rates","DNS issue","None","B","hard"),
            (5,"What does ping test?","Download speed","Reachability and round-trip time to a host","Bandwidth","Upload speed","B","easy"),
        ]
        c.executemany("INSERT INTO questions(category_id,question,option_a,option_b,option_c,option_d,correct_answer,difficulty) VALUES(?,?,?,?,?,?,?,?)", q)

    # ── Seed interview companies
    c.execute("SELECT COUNT(*) FROM interview_companies")
    if c.fetchone()[0] == 0:
        c.executemany("INSERT INTO interview_companies(name,logo,color,type,founded,hq) VALUES(?,?,?,?,?,?)", [
            ("TCS",          "🔷","#0052CC","Service",1968,"Mumbai"),
            ("Wipro",        "🟡","#341A6E","Service",1945,"Bengaluru"),
            ("Infosys",      "🔵","#007CC3","Service",1981,"Bengaluru"),
            ("HCL",          "🟢","#009A44","Service",1976,"Noida"),
            ("Accenture",    "🟣","#A100FF","Service",1989,"Dublin"),
            ("Cognizant",    "🔶","#0033A0","Service",1994,"New Jersey"),
            ("Tech Mahindra","⚙️","#C8102E","Service",1986,"Pune"),
            ("Amazon",       "🟠","#FF9900","Product",1994,"Seattle"),
            ("Microsoft",    "🪟","#00A4EF","Product",1975,"Redmond"),
            ("Google",       "🔴","#EA4335","Product",1998,"Mountain View"),
        ])

    # ── Seed interview questions (100+)
    c.execute("SELECT COUNT(*) FROM interview_questions")
    if c.fetchone()[0] == 0:
        iq = [
            # TCS (id=1) — 12 questions
            (1,"Python","What are Python key features?","Python is interpreted, dynamically typed, object-oriented, and garbage collected. Key features: simple readable syntax, extensive standard library (PyPI), portability, multiple paradigms (OOP, functional, procedural), and strong community. Used in web, AI, automation, and data science.","TCS asks this in 90% of fresher rounds. Memorize 6+ features with one real-world example each. Mention Flask, Django, NumPy as popular libraries.","easy",4.8,187,2024,"2019,2020,2021,2022,2023,2024","Fresher","python,basics"),
            (1,"OOP","Explain the 4 pillars of OOP with examples.","1. Encapsulation: Data hiding using private variables and getter/setter methods. Example: BankAccount class with private __balance. 2. Abstraction: Showing only interface, hiding implementation. Example: ATM machine - you press button, don't know internals. 3. Inheritance: Child class gets parent properties. Example: Dog extends Animal. 4. Polymorphism: Same method, different behavior. Example: area() works differently for Circle vs Rectangle.","Use real-world analogies. TCS interviewers love when you give industry examples. Also be ready to write code for each.","easy",4.9,203,2024,"2018,2019,2020,2021,2022,2023,2024","Fresher","oop,fundamentals"),
            (1,"DSA","Array vs Linked List — when to use which?","Array: Fixed size, contiguous memory, O(1) random access, O(n) insert/delete. Use when: frequent access by index, size known upfront, cache performance matters. Linked List: Dynamic size, nodes with pointers, O(n) access, O(1) head insert/delete. Use when: frequent insertion/deletion, size unknown, memory is fragmented.","TCS coding rounds often ask: Reverse a linked list, Find middle element, Detect cycle. Practice these before interview.","medium",4.7,145,2024,"2020,2021,2022,2023,2024","Fresher","dsa,arrays,linkedlist"),
            (1,"Database","What is normalization? Explain 1NF, 2NF, 3NF with example.","Goal: Eliminate redundancy. 1NF: Atomic values, no repeating groups. Example: Split Phone1,Phone2 into separate rows. 2NF: 1NF + No partial dependency (every non-key attribute depends on FULL primary key). 3NF: 2NF + No transitive dependency (non-key attributes depend only on primary key, not on other non-key attributes). BCNF is stricter version of 3NF.","Walk through a Student(RollNo, Name, CourseID, CourseName, Dept) table. Decompose step by step. TCS SQL written test has normalization questions.","medium",4.6,132,2023,"2019,2020,2021,2022,2023","Fresher","dbms,normalization"),
            (1,"OS","Process vs Thread — differences and use cases?","Process: Independent program execution, own memory space, PCB, file descriptors. Heavyweight. IPC needed for communication. Thread: Lightweight unit within process. Shares memory, code, data of parent process. Faster context switch. Use Threads: parallel tasks sharing data (web server handling requests). Use Processes: isolation needed (Chrome tabs as separate processes for crash safety).","TCS follow-up: 'Why does Chrome use processes not threads for tabs?' Security isolation and one tab crash doesn't kill browser.","medium",4.5,98,2024,"2021,2022,2023,2024","Fresher","os,process,thread"),
            (1,"Networks","What happens when you type google.com in browser?","1. Browser checks cache. 2. DNS resolution: browser → OS → resolver → root → TLD → authoritative NS → IP returned. 3. TCP 3-way handshake (SYN, SYN-ACK, ACK). 4. TLS handshake (ClientHello, ServerHello, Certificate verify, Session keys). 5. HTTP GET request. 6. Server processes, sends HTTP response. 7. Browser parses HTML, fetches CSS/JS/images. 8. DOM constructed, page rendered.","TCS loves depth here. Mention CDN, browser caching, HTTP/2, and HSTS for extra marks. The more layers you explain, the better impression.","medium",4.8,156,2024,"2020,2021,2022,2023,2024","Fresher","networks,http,dns"),
            (1,"Python","List vs Tuple vs Set vs Dictionary — complete comparison.","List: ordered, mutable, allows duplicates, O(1) index access. [] syntax. Tuple: ordered, immutable, allows duplicates, hashable (can be dict key). () syntax. Set: unordered, mutable, NO duplicates, O(1) lookup. {} syntax. Dictionary: key-value pairs, ordered (Python 3.7+), mutable, keys unique. {} with colons. Use set for membership testing, dict for lookups, tuple for fixed data.","TCS written test often has MCQs on output of operations on these. Practice edge cases like: set from list, tuple with mutable elements.","easy",4.4,89,2023,"2021,2022,2023","Fresher","python,collections"),
            (1,"OOP","What is method overloading vs overriding in Python?","Overriding: Child class provides own implementation of parent method. Runtime polymorphism. Use super() to call parent. Example: Animal.speak() overridden by Dog.speak() to say 'Woof'. Overloading: Python doesn't support true overloading. Simulate with default args or *args. Example: def add(a, b=0, c=0). Java has true overloading based on parameter types.","Prepare code for both. TCS may ask: 'What happens if you call parent method in overriding?' Answer: use super().method_name()","medium",4.5,94,2024,"2022,2023,2024","Fresher","oop,python"),
            (1,"DSA","Explain sorting algorithms with time complexities.","Bubble: O(n²) all cases. Selection: O(n²) all. Insertion: O(n) best, O(n²) worst. Merge: O(n log n) always, O(n) space. Quick: O(n log n) avg, O(n²) worst (bad pivot). Heap: O(n log n) always, O(1) space. Counting: O(n+k). Radix: O(nk). Best for nearly sorted: Insertion. Best overall: Merge or Heap. Python's sorted() uses Timsort (hybrid Merge+Insertion).","TCS coding test: 'Sort array without using library functions.' Practice implementing merge sort from scratch.","medium",4.6,108,2024,"2021,2022,2023,2024","Fresher","dsa,sorting,complexity"),
            (1,"Database","ACID properties with real-world banking example.","A-Atomicity: Transfer ₹500 from A to B. Deduct A AND credit B must both succeed, or both rollback. C-Consistency: DB moves from valid state to valid state. Balance can't go below 0 if constraint set. I-Isolation: Two transfers happening simultaneously don't interfere. Levels: Read Uncommitted < Read Committed < Repeatable Read < Serializable. D-Durability: Committed transfer persists even if server crashes immediately after.","TCS SQL round often asks: 'What isolation level prevents dirty reads?' Answer: Read Committed and above.","easy",4.8,134,2024,"2019,2020,2021,2022,2023,2024","Fresher","dbms,transactions,acid"),
            (1,"OS","Explain deadlock with Coffman conditions and prevention.","Deadlock: Circular wait among processes. Example: P1 holds R1, wants R2. P2 holds R2, wants R1. Both wait forever. Coffman Conditions (ALL must hold): 1.Mutual Exclusion, 2.Hold and Wait, 3.No Preemption, 4.Circular Wait. Prevention: Break any one condition. Avoidance: Banker's Algorithm. Detection: Resource Allocation Graph. Recovery: Kill process or preempt resource.","TCS OS question: 'What is the Banker's Algorithm?' It's deadlock avoidance - checks if granting resource keeps system in safe state.","medium",4.6,91,2023,"2020,2021,2022,2023","Fresher","os,deadlock"),
            (1,"Networks","OSI Model - all 7 layers with protocols.","7-Application: HTTP, FTP, SMTP, DNS. 6-Presentation: SSL/TLS, JPEG, ASCII. 5-Session: NetBIOS, PPTP. 4-Transport: TCP, UDP, port numbers. 3-Network: IP, ICMP, routers. 2-Data Link: Ethernet, MAC, switches. 1-Physical: cables, hubs, signals, bits. Mnemonic top-down: All People Seem To Need Data Processing. Data unit per layer: 7-6-5: Data. 4: Segment. 3: Packet. 2: Frame. 1: Bits.","TCS networking MCQ: 'Which layer adds port numbers?' Transport. 'Which layer adds IP?' Network. Know data units for each layer.","easy",4.9,178,2024,"2018,2019,2020,2021,2022,2023,2024","Fresher","networks,osi"),
            # WIPRO (id=2) — 10 questions
            (2,"Python","What are decorators? Write a timing decorator.","Decorators wrap functions to add behavior. Syntax: @decorator before function. Internally: func = decorator(func). Example timing decorator: def timer(func): def wrapper(*args,**kwargs): start=time.time(); result=func(*args,**kwargs); print(f'Time: {time.time()-start}'); return result; return wrapper. @timer above any function now measures it. Used in Flask: @app.route(), @login_required.","Wipro loves practical decorators. Also know: @staticmethod (no self/cls), @classmethod (cls not self), @property (getter). Write all three in interview.","medium",4.7,112,2024,"2021,2022,2023,2024","Fresher/1yr","python,advanced"),
            (2,"OOP","What is abstraction? Abstract classes vs interfaces in Python?","Abstraction: Hiding implementation details, showing only interface. Example: Car's accelerate() - you press pedal, don't know engine internals. In Python: from abc import ABC, abstractmethod. Abstract class: Has both abstract (no body) and concrete (with body) methods. Can have constructors and instance vars. Interface (conceptually): ALL methods abstract. Python uses ABC for both. @abstractmethod forces subclass to implement.","Common mistake: confusing abstraction with encapsulation. Abstraction = what to show. Encapsulation = how to protect data. Be crystal clear.","medium",4.4,87,2023,"2021,2022,2023","Fresher","oop,abstraction"),
            (2,"DSA","Explain recursion with Fibonacci example and memoization.","Recursion: Function calls itself with smaller input + base case. Fibonacci naive: fib(n) = fib(n-1) + fib(n-2), base: fib(0)=0, fib(1)=1. Time: O(2^n) - exponential, very slow. With memoization (cache results): memo={} fib(n): if n in memo return memo[n]; memo[n]=fib(n-1)+fib(n-2); return memo[n]. Time becomes O(n). Dynamic programming tabulation (bottom-up) also O(n), O(1) space with rolling array.","Wipro coding round has Fibonacci variations. Also know: Tower of Hanoi recursion, factorial. Always state time/space complexity.","medium",4.6,108,2024,"2021,2022,2023,2024","Fresher","dsa,recursion,dp"),
            (2,"Database","SQL Joins - INNER, LEFT, RIGHT, FULL OUTER with examples.","INNER JOIN: Only matching rows from both tables. LEFT JOIN: ALL rows from left + matching from right (NULL if no match). RIGHT JOIN: ALL from right + matching from left (NULL if no match). FULL OUTER JOIN: ALL rows from both, NULLs where no match. CROSS JOIN: Cartesian product (every combination). Example: Employee LEFT JOIN Department shows all employees even if not assigned to department (dept_id = NULL).","Wipro SQL test: Write query to find employees with no department. Answer: SELECT e.* FROM Employee e LEFT JOIN Department d ON e.dept_id=d.id WHERE d.id IS NULL","medium",4.8,167,2024,"2019,2020,2021,2022,2023,2024","Fresher","dbms,sql,joins"),
            (2,"Networks","TCP vs UDP - detailed comparison with use cases.","TCP: Connection-oriented (3-way handshake). Reliable, ordered, error-checked. Flow control, congestion control. Slower. Uses: HTTP/HTTPS, FTP, SMTP, SSH, databases. UDP: Connectionless. Unreliable, no ordering, no error recovery. Fast, low overhead. Uses: DNS (small queries), live streaming, gaming, VoIP, DHCP. Why DNS uses UDP: queries are tiny, speed > reliability, retransmit if no response. Why video streaming uses UDP: dropped frame better than buffering.","Wipro follow-up: 'Can UDP be made reliable?' Yes - implement ACK at application layer (like QUIC protocol does).","easy",4.7,126,2024,"2020,2021,2022,2023,2024","Fresher","networks,tcp,udp"),
            (2,"OS","Memory management - paging vs segmentation?","Paging: Fixed-size pages/frames. Eliminates external fragmentation. Has internal fragmentation (last page may be partial). Page table per process maps virtual pages to physical frames. TLB caches frequent page table entries. Segmentation: Variable-size segments (code, data, stack). Eliminates internal fragmentation. Has external fragmentation. Supports logical view of memory. Modern systems use both: segmented paging.","Wipro OS question: 'What is a page table and why is it large?' For 32-bit system: 2^32/4096 = 1M entries × 4 bytes = 4MB per process. Multi-level paging solves this.","medium",4.5,82,2023,"2021,2022,2023","Fresher","os,memory,paging"),
            (2,"Python","Generators vs iterators vs list comprehensions?","Iterator: Object with __iter__ and __next__ methods. Any for loop uses iterator protocol. Generator: Function with yield. Lazy evaluation - produces one value at a time. Memory efficient for large datasets. Generator expression: (x**2 for x in range(1000000)) uses O(1) memory vs list [x**2...] uses O(n). When to use generators: reading large files line by line, infinite sequences, pipeline processing.","Wipro: 'How to read a 10GB file without loading it all in RAM?' Use generator: def read_chunks(file): while chunk=file.read(1024): yield chunk","medium",4.4,72,2024,"2022,2023,2024","Fresher/1yr","python,generators"),
            (2,"DSA","Graph traversal - BFS and DFS with code logic.","BFS (Breadth-First): Level by level. Uses Queue. Start: add root to queue. Loop: dequeue, process, add unvisited neighbors to queue. Uses: shortest path unweighted, level-order tree, web crawling. DFS (Depth-First): Go deep first. Uses Stack/recursion. Uses: topological sort, cycle detection, connected components, maze solving. BFS guarantees shortest path in unweighted graph. DFS uses less memory for deep graphs.","Wipro coding: 'Find number of islands in a grid' - DFS/BFS both work. 'Find shortest path in matrix' - always BFS.","medium",4.9,134,2024,"2021,2022,2023,2024","Any","dsa,graphs,bfs,dfs"),
            (2,"Database","What are indexes? B-tree index vs hash index?","Index: Data structure for faster query execution at cost of write speed and storage. B-tree index: Default in most DBs. Supports range queries (BETWEEN, >, <), ORDER BY, LIKE 'prefix%'. Balanced tree. Hash index: Exact match only (=). Not for ranges. Faster for equality. When to use: Index on columns in WHERE, JOIN conditions, ORDER BY. Don't index: Small tables, high-NULL columns, frequently updated columns, low-cardinality (gender: only M/F).","Wipro: 'Clustered vs non-clustered index?' Clustered: physically orders rows (one per table, usually PK). Non-clustered: separate structure with pointers to rows (multiple allowed).","medium",4.6,95,2024,"2021,2022,2023,2024","Fresher","dbms,sql,indexing"),
            (2,"OS","CPU scheduling algorithms comparison.","FCFS: Simple, non-preemptive, convoy effect problem (long job blocks others). SJF: Shortest job first, optimal average waiting time, but needs future knowledge. SRTF: Preemptive SJF, can starve long processes. Round Robin: Each process gets time quantum (usually 10-100ms). Good for time-sharing. Priority: Each job has priority. Can starve low-priority (solved by aging). Multilevel Queue: Different queues for system, interactive, batch jobs.","Wipro HR: 'Which scheduling is best for interactive systems?' Round Robin. 'Which minimizes average waiting time?' SJF.","medium",4.5,88,2024,"2021,2022,2023,2024","Fresher","os,scheduling"),
            # INFOSYS (id=3) — 10 questions
            (3,"Python","Shallow copy vs deep copy - when does it matter?","Shallow copy (copy.copy()): Creates new object but nested objects are references. Changing nested mutable (list inside list) affects both. Deep copy (copy.deepcopy()): Completely independent copy including all nested objects. Changing anything doesn't affect original. Example where it matters: config = {'servers': ['s1','s2']}; cfg2 = config.copy(); cfg2['servers'].append('s3') - this ALSO changes config['servers']! Deep copy prevents this.","Infosys coding test: Often has output-based questions on copy behavior. Practice with nested lists and dicts to master this.","medium",4.5,78,2024,"2022,2023,2024","Fresher/1yr","python,memory"),
            (3,"DSA","Reverse a linked list - write iterative and recursive code.","Iterative: prev=None; curr=head; while curr: next_node=curr.next; curr.next=prev; prev=curr; curr=next_node; return prev. Recursive: if not head or not head.next: return head; new_head=reverse(head.next); head.next.next=head; head.next=None; return new_head. Iterative: O(n) time, O(1) space. Recursive: O(n) time, O(n) stack space.","Infosys asks this in almost every technical round. Practice until you can write iterative version in under 90 seconds. Also know: reverse in groups of k.","hard",4.7,143,2024,"2019,2020,2021,2022,2023,2024","Fresher","dsa,linkedlist,coding"),
            (3,"OOP","Explain SOLID principles with Python examples.","S-Single Responsibility: One class, one reason to change. Example: UserAuth class only does auth, not logging. O-Open/Closed: Open for extension, closed for modification. Use inheritance/composition not editing existing code. L-Liskov Substitution: Subclass should be replaceable for parent without breaking code. I-Interface Segregation: Don't force clients to implement unused methods. D-Dependency Inversion: Depend on abstractions, not concretions. Use dependency injection.","Infosys senior/experienced roles ask SOLID. For freshers: at least explain S and O with example. Gets you extra points.","hard",4.3,65,2023,"2022,2023","1yr+","oop,solid,design"),
            (3,"Database","Write SQL queries for common interview problems.","1. Second highest salary: SELECT MAX(salary) FROM emp WHERE salary < (SELECT MAX(salary) FROM emp). 2. Department wise max salary: SELECT dept, MAX(salary) FROM emp GROUP BY dept. 3. Employees not in any project: SELECT * FROM emp WHERE id NOT IN (SELECT emp_id FROM project). 4. Duplicate records: SELECT name, COUNT(*) FROM emp GROUP BY name HAVING COUNT(*) > 1. 5. Nth highest: SELECT salary FROM emp ORDER BY salary DESC LIMIT 1 OFFSET N-1.","Infosys SQL test always has 3-4 subquery problems. Master: NOT IN, NOT EXISTS, correlated subqueries, HAVING vs WHERE, ROW_NUMBER().","hard",4.7,112,2024,"2020,2021,2022,2023,2024","Fresher","dbms,sql,queries"),
            (3,"Networks","What is subnetting? Calculate subnet for 192.168.1.0/26.","Subnetting: Dividing network into smaller sub-networks. /26 means 26 bits for network, 6 bits for hosts. Subnet mask: 255.255.255.192 (11000000). Hosts per subnet: 2^6 - 2 = 62 (subtract network and broadcast). Number of subnets from /24: 2^2 = 4 subnets. Ranges: .0-.63 (hosts .1-.62), .64-.127, .128-.191, .192-.255. CIDR notation: /24=255.255.255.0, /25=.128, /26=.192, /27=.224, /28=.240, /29=.248, /30=.252.","Infosys networking: Quick formula - hosts = 2^(32-prefix) - 2. For /26: 2^6-2 = 62 hosts. Practice VLSM for experienced roles.","hard",4.4,67,2023,"2021,2022,2023","Fresher","networks,subnetting"),
            (3,"Python","Exception handling - custom exceptions, exception hierarchy.","Hierarchy: BaseException > Exception > (ArithmeticError, LookupError, OSError...) > specific errors. Custom exception: class InsufficientFunds(Exception): def __init__(self, amount): super().__init__(f'Need {amount} more'); self.amount=amount. Best practices: Catch specific exceptions not bare except. Use finally for cleanup (file close, DB connection). Don't suppress exceptions silently. Re-raise: raise in except block. Chaining: raise NewError from original_error.","Infosys: 'Difference between except Exception and except BaseException?' BaseException catches SystemExit and KeyboardInterrupt - almost never do this.","medium",4.5,94,2024,"2021,2022,2023,2024","Fresher","python,exceptions"),
            (3,"OOP","What is multiple inheritance? Python MRO with diamond example.","Multiple inheritance: class C(A, B). Python uses C3 linearization (MRO) to resolve method order. Diamond problem: D inherits B and C, both inherit A. D.method() → check D, then B, then C, then A. See MRO: D.__mro__ = (D, B, C, A, object). super() follows MRO, so each class called once. Example: class D(B,C): super().__init__() in D calls B.__init__, which calls C.__init__ via super(), then A.__init__. NEVER calling A twice.","Infosys asks: 'What is cooperative multiple inheritance?' Each class uses super() and they cooperate through MRO chain without duplication.","hard",4.3,58,2023,"2022,2023","1yr+","python,oop,mro"),
            (3,"DSA","Binary search and its variations.","Standard: Find target in sorted array. O(log n). Variations: 1.First occurrence: when arr[mid]==target, don't stop, hi=mid-1 to continue left. 2.Last occurrence: when arr[mid]==target, lo=mid+1 to continue right. 3.Search in rotated sorted array: check which half is sorted, decide which half target is in. 4.Find peak element: if arr[mid]>arr[mid+1], peak in left half. 5.Square root: binary search on answer space.","Infosys coding: 'Find first bad version' is classic binary search on answer. Also: 'Search in 2D sorted matrix' - treat as 1D array.","medium",4.6,89,2024,"2022,2023,2024","Fresher","dsa,binary-search"),
            (3,"Database","What is a transaction? SAVEPOINT and ROLLBACK.","Transaction: Group of operations treated as one unit. Either all succeed (COMMIT) or all fail (ROLLBACK). Commands: BEGIN/START TRANSACTION, COMMIT, ROLLBACK. SAVEPOINT: Named point within transaction to partially rollback. SAVEPOINT sp1; ... ROLLBACK TO sp1; (undoes after sp1 but keeps before). Useful: Long transactions where you want to undo only recent part. Example: Order system - SAVEPOINT after each item added, rollback to cancel specific item.","Infosys: 'What is implicit vs explicit transaction?' Implicit: each DML auto-commits. Explicit: programmer controls with BEGIN/COMMIT.","medium",4.4,76,2023,"2021,2022,2023","Fresher","dbms,transactions"),
            (3,"OS","Virtual memory, page replacement algorithms.","Virtual memory: Process sees large address space (e.g., 4GB on 32-bit) even if RAM is smaller. OS + hardware (MMU) translate virtual to physical. Page replacement (when page fault and no free frame): FIFO: Replace oldest page. Simple but Belady's anomaly (more frames → more faults!). LRU: Replace least recently used. Good approximation of optimal. Optimal: Replace page not needed for longest time. Best but impractical (needs future). LFU: Replace least frequently used. Good for frequency patterns.","Infosys: 'Why is FIFO bad?' Belady's anomaly. 'Why is LRU used in practice?' Good approximation of optimal, implementable with timestamp/stack.","medium",4.4,78,2023,"2021,2022,2023","Fresher","os,memory,virtual"),
            # HCL (id=4) — 8 questions
            (4,"Python","List comprehensions, dict comprehensions, generator expressions.","List: [x**2 for x in range(10) if x%2==0] → [0,4,16,36,64]. Dict: {k:v for k,v in zip(keys,vals)} or {word:len(word) for word in words}. Set: {x%5 for x in range(20)}. Generator: (x**2 for x in range(10)) - lazy, memory efficient. Nested: [cell for row in matrix for cell in row] flattens 2D list. Conditional expression: [x if x>0 else -x for x in nums] (absolute value).","HCL loves one-liners. Also: 'What is the difference between generator expression and list comprehension?' Gen uses (), lazy eval, O(1) memory. List uses [], eager eval, O(n) memory.","easy",4.4,67,2023,"2021,2022,2023","Fresher","python,comprehension"),
            (4,"DSA","Binary Search Tree operations and balancing.","BST property: left < node < right. Search: O(log n) avg, O(n) worst (skewed). Insert: O(log n) avg. Delete: 3 cases: leaf→just remove, one child→replace with child, two children→replace with inorder successor (smallest in right subtree) then delete successor. Inorder traversal gives sorted sequence. Problem: Can degenerate (sorted input → linked list). Solution: AVL (height-balanced, rotations on insert/delete) or Red-Black tree (color-based balancing). Python: sortedcontainers.SortedList.","HCL: 'How to check if BST is valid?' Pass min/max range down recursion: isValid(node, min, max) checking min < node.val < max for each node.","medium",4.5,82,2024,"2022,2023,2024","Fresher","dsa,trees,bst"),
            (4,"OS","Memory allocation strategies - first fit, best fit, worst fit.","First Fit: Allocate first hole that is big enough. Fast, simple. Some external fragmentation. Best Fit: Allocate smallest hole that fits. Minimizes wasted space but leaves tiny unusable fragments. Slow (search all). Worst Fit: Allocate largest hole. Leaves largest remaining fragment (useful for future). Bad utilization. Compaction: Move all processes to one end, free space to other end. But expensive. Buddy system: Split/merge in powers of 2.","HCL OS question: 'Compare first fit and best fit.' First fit faster, best fit better space utilization but creates small unusable fragments.","medium",4.3,71,2023,"2021,2022,2023","Fresher","os,memory"),
            (4,"Database","SQL: WHERE vs HAVING, GROUP BY, aggregate functions.","WHERE: Filters ROWS before grouping. Works on individual row values. Cannot use aggregate functions. HAVING: Filters GROUPS after GROUP BY. Works on aggregated values. CAN use COUNT, SUM, AVG, MAX, MIN. Example: Find departments with more than 5 employees above 50k salary: SELECT dept, COUNT(*) FROM emp WHERE salary>50000 GROUP BY dept HAVING COUNT(*)>5. Order: FROM → WHERE → GROUP BY → HAVING → SELECT → ORDER BY → LIMIT.","HCL SQL: 'What is the difference between COUNT(*) and COUNT(column)?' COUNT(*) counts all rows including NULLs. COUNT(col) skips NULLs.","easy",4.6,112,2024,"2020,2021,2022,2023,2024","Fresher","dbms,sql"),
            (4,"Networks","IP addressing - classes, private ranges, CIDR.","Class A: 0.0.0.0-127.255.255.255, /8 mask, 16M hosts. Class B: 128.0-191.255, /16 mask, 65K hosts. Class C: 192.0.0-223.255.255, /24 mask, 254 hosts. Private (RFC 1918): 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16. Loopback: 127.0.0.1. CIDR: /24 = 254 hosts, /25 = 126, /26 = 62, /30 = 2 hosts (point-to-point links). IPv6: 128-bit, no classes, uses /64 prefix typically. ::1 is loopback.","HCL networking: 'What IP range is used in private networks?' 192.168.x.x most common. 'Why 127.0.0.1?' Loopback - talks to yourself, never leaves machine.","medium",4.5,79,2023,"2022,2023","Fresher","networks,ipaddressing"),
            (4,"Python","What is GIL? How does it affect multithreading?","GIL (Global Interpreter Lock): Mutex in CPython that allows only ONE thread to execute Python bytecode at a time. Why: Memory management (reference counting) isn't thread-safe without it. Effect: CPU-bound multithreaded Python doesn't utilize multiple cores. IO-bound threads still work well (GIL released during IO). Solutions: multiprocessing module (separate processes, no GIL), async/await for IO-bound, C extensions can release GIL. PyPy and Jython don't have GIL.","HCL: 'Does Python have true parallelism?' Not with threads due to GIL. Use multiprocessing for CPU-bound tasks. This is a very common Python-specific interview question.","hard",4.5,84,2024,"2022,2023,2024","1yr+","python,gil,concurrency"),
            (4,"DSA","Dynamic programming - common problems.","DP conditions: Optimal substructure + Overlapping subproblems. Approach: Identify state, write recurrence, implement bottom-up (tabulation) or top-down (memoization). Classic problems: Fibonacci: dp[i]=dp[i-1]+dp[i-2]. 0/1 Knapsack: dp[i][w]=max(dp[i-1][w], val[i]+dp[i-1][w-wt[i]]). LCS: dp[i][j]=dp[i-1][j-1]+1 if match, else max(dp[i-1][j],dp[i][j-1]). Coin Change: dp[amount]=min(dp[amount-coin]+1 for coin in coins). Edit Distance: Levenshtein distance.","HCL coding round has DP problems. Start with Fibonacci (easy), then Coin Change, then 0/1 Knapsack. Always code both approaches.","hard",4.6,88,2024,"2022,2023,2024","1yr+","dsa,dp,algorithms"),
            (4,"Database","Stored procedures vs functions vs triggers.","Stored Procedure: Precompiled SQL code stored in DB. Can have input/output params. Can modify data (INSERT/UPDATE/DELETE). Called with EXEC/CALL. Function: Returns single value or table. Cannot have side effects (no DML in most DBs). Used in SELECT. Trigger: Automatically executes on INSERT/UPDATE/DELETE events. Types: BEFORE/AFTER INSERT, UPDATE, DELETE. Use for: audit logging, enforcing business rules, cascading changes. Difference from procedure: triggered automatically not called.","HCL: 'When would you use a trigger instead of application code?' When you need enforcement at DB level regardless of which application writes data.","medium",4.4,73,2023,"2022,2023","Fresher","dbms,stored-procedures,triggers"),
            # ACCENTURE (id=5) — 8 questions
            (5,"Python","*args, **kwargs, and function parameter ordering.","*args: Collects extra positional args as tuple. def f(*args): for x in args: print(x). **kwargs: Collects extra keyword args as dict. def f(**kwargs): for k,v in kwargs.items(): print(k,v). Combined: def f(pos, *args, keyword_only, **kwargs). Order: positional → *args → keyword-only (after *) → **kwargs. Unpacking: f(*[1,2,3]) passes list as positional. f(**{'a':1}) passes dict as kwargs. Useful for: wrapper functions, decorators, flexible APIs.","Accenture: 'How to pass a dictionary as keyword arguments?' Use ** unpacking: func(**my_dict). Very common in Django/Flask patterns.","medium",4.5,89,2024,"2022,2023,2024","Fresher","python,functions"),
            (5,"OOP","Design patterns - Singleton, Factory, Observer.","Singleton: Only one instance. Python: class Singleton: _instance=None; def __new__(cls): if not cls._instance: cls._instance=super().__new__(cls); return cls._instance. OR simply use a module (module imported once). Factory: Create objects without specifying class. class AnimalFactory: def create(type): return Dog() if type=='dog' else Cat(). Observer: Publisher notifies subscribers. class EventSystem: subscribers={}; def subscribe(event,callback): ...; def publish(event,data): for cb in subscribers[event]: cb(data). Used in Django signals, UI event systems.","Accenture senior interviews: Know when to use each. Singleton: DB connection pool, config. Factory: creating different object types. Observer: event systems, MVC.","hard",4.6,112,2024,"2021,2022,2023,2024","1yr+","oop,design-patterns"),
            (5,"DSA","Stack and Queue - implementations and applications.","Stack (LIFO): Push/pop from top. Applications: Function call stack, undo/redo, expression evaluation (postfix), DFS, balanced brackets. Implement with list: stack=[]; stack.append(x) push; stack.pop() pop; stack[-1] peek. Queue (FIFO): Enqueue rear, dequeue front. Applications: BFS, job scheduling, printer queue, process scheduling. Python: from collections import deque; q=deque(); q.append(x); q.popleft(). Circular queue solves wasted space. Priority queue: heapq module.","Accenture coding: 'Implement stack using two queues' or vice versa. Also: 'Check balanced parentheses' using stack. Classic problems.","easy",4.6,134,2024,"2020,2021,2022,2023,2024","Fresher","dsa,stack,queue"),
            (5,"Networks","HTTP methods, status codes, REST API principles.","HTTP Methods: GET (retrieve, idempotent), POST (create, not idempotent), PUT (replace, idempotent), PATCH (partial update), DELETE (remove, idempotent), HEAD (like GET but no body), OPTIONS (check allowed methods). Status codes: 2xx success (200 OK, 201 Created, 204 No Content). 3xx redirect (301 Permanent, 302 Temporary). 4xx client error (400 Bad Request, 401 Unauthorized, 403 Forbidden, 404 Not Found, 429 Rate Limited). 5xx server error (500 Internal, 503 Unavailable). REST: Stateless, resource-based URLs (/users/1), uses HTTP methods.","Accenture web roles: 'Difference between 401 and 403?' 401: Not authenticated (need to login). 403: Authenticated but not authorized (no permission).","medium",4.7,98,2024,"2021,2022,2023,2024","Fresher","networks,http,rest"),
            (5,"Database","What are NoSQL databases? SQL vs NoSQL comparison.","SQL: Relational, fixed schema, ACID, tables/rows, vertical scaling. Best for: complex queries, transactions, structured data. Examples: MySQL, PostgreSQL, SQLite. NoSQL: Non-relational, flexible schema, eventual consistency (CAP theorem). Types: Document (MongoDB - JSON docs), Key-Value (Redis - caching), Column-family (Cassandra - time-series), Graph (Neo4j - social networks). Best for: large-scale, unstructured data, horizontal scaling, real-time apps. CAP theorem: Can only guarantee 2 of: Consistency, Availability, Partition tolerance.","Accenture: 'When would you choose MongoDB over MySQL?' Large unstructured data, rapid schema changes, horizontal scaling needed, hierarchical data.","medium",4.5,84,2024,"2022,2023,2024","Fresher","dbms,nosql"),
            (5,"OS","Inter-process communication (IPC) mechanisms.","IPC Methods: 1.Pipes: Unidirectional, related processes. Named pipes (FIFOs): unrelated processes. 2.Message Queues: Send structured messages. Persistent, asynchronous. 3.Shared Memory: Fastest IPC. Multiple processes map same memory segment. Need synchronization (semaphore/mutex). 4.Semaphores: Synchronization primitive. Binary (mutex) or counting. 5.Sockets: Network communication. Also for same machine (Unix domain sockets). 6.Signals: Async notifications (kill -9, Ctrl+C = SIGINT). 7.Memory-mapped files: File mapped to virtual memory.","Accenture OS: 'Which IPC is fastest?' Shared memory - no data copying. 'Why need semaphore with shared memory?' Prevent race conditions.","medium",4.4,71,2023,"2022,2023","Fresher","os,ipc,communication"),
            (5,"Python","Context managers - with statement and __enter__/__exit__.","Context manager: Guarantees setup and cleanup even if exception occurs. with statement calls __enter__ on entry and __exit__ on exit (even on exception). File example: with open('f.txt') as f: data=f.read() → file auto-closed. Custom context manager: class Timer: def __enter__(self): self.start=time.time(); return self. def __exit__(self,*args): print(time.time()-self.start). Also: @contextmanager decorator: def managed(): setup(); try: yield value; finally: cleanup(). Used for: file handling, DB connections, thread locks, timing.","Accenture: 'Why use with open() over f=open()?' Exception safety - file always closed even if exception raised inside block.","medium",4.3,65,2023,"2022,2023","Fresher","python,context-manager"),
            (5,"DSA","Hashing - hash functions, collisions, applications.","Hash function: Maps data to fixed-size value. Good hash: Fast, uniform distribution, minimal collisions, deterministic. Collision resolution: Chaining (linked list per bucket, O(1) avg, O(n) worst), Open addressing (linear probing: next slot, quadratic probing: skip i^2 slots, double hashing). Load factor: n/m (elements/buckets). Rehashing when load factor > 0.7. Python dict: open addressing with pseudo-random probing. Applications: Hash maps (O(1) lookup), hash sets (O(1) contains), cryptography (MD5, SHA), caching.","Accenture: 'Design a HashSet from scratch.' Need hash function, array of lists for chaining, resize when load factor exceeds threshold.","medium",4.5,76,2024,"2022,2023,2024","Fresher","dsa,hashing"),
            # COGNIZANT (id=6) — 7 questions
            (6,"Database","SQL subqueries, correlated subqueries, CTEs.","Subquery: Query inside query. Types: Scalar (returns 1 value), Row (returns 1 row), Table (returns multiple rows). Correlated: References outer query, executes once per outer row. Example: SELECT * FROM emp e WHERE salary > (SELECT AVG(salary) FROM emp WHERE dept=e.dept). CTE (Common Table Expression): WITH cte AS (SELECT...) SELECT * FROM cte. Reusable within query. Recursive CTE: WITH RECURSIVE cte AS (base_case UNION ALL recursive_case). For hierarchies.","Cognizant SQL: 'Find employees earning more than their manager.' SELECT e.name FROM emp e JOIN emp m ON e.mgr_id=m.id WHERE e.salary > m.salary.","hard",4.8,167,2024,"2019,2020,2021,2022,2023,2024","Fresher","dbms,sql,subqueries"),
            (6,"Python","Exception handling best practices and custom exceptions.","Best practices: 1.Catch specific exceptions (except ValueError not except Exception). 2.Don't suppress silently (avoid bare except: pass). 3.Use finally for cleanup. 4.Use else for code that runs only if no exception. 5.Re-raise with context: raise RuntimeError('failed') from original_error. 6.Custom exceptions for domain errors: class OrderError(Exception): pass; class OutOfStockError(OrderError): def __init__(self, item): super().__init__(f'{item} not available'). 7.Document what exceptions functions can raise (docstring).","Cognizant HR: 'What is the difference between error and exception?' Errors: serious issues (MemoryError, RecursionError). Exceptions: recoverable conditions (ValueError, FileNotFoundError).","easy",4.5,94,2024,"2021,2022,2023,2024","Fresher","python,exceptions"),
            (6,"OS","Linux commands every developer must know.","File: ls -la (list all with permissions), cd, pwd, cp, mv, rm -rf, find / -name file, grep -r pattern ., chmod 755, chown user:group. Process: ps aux, top, kill -9 PID, nohup cmd &, jobs, bg/fg. Network: netstat -tulpn, ss -tulpn, ping, traceroute, wget, curl, ifconfig/ip addr. Text: cat, head -n 10, tail -f (live log), less, awk, sed, sort | uniq -c | sort -rn. Archive: tar -xzf file.tar.gz, tar -czf archive.tar.gz dir. Admin: sudo, su, df -h, du -sh, free -h, uname -a, which python3.","Cognizant Linux: Very common 'what does this command do' questions. Know: chmod 777 (rwx for all), grep -v (exclude lines), pipe |, redirect > and >>.","medium",4.6,103,2024,"2021,2022,2023,2024","Fresher","os,linux,commands"),
            (6,"Networks","DNS record types and resolution process.","DNS Record Types: A: hostname → IPv4. AAAA: hostname → IPv6. CNAME: alias → another hostname (www → example.com). MX: mail server for domain. NS: nameserver for domain. TXT: text info (SPF, DKIM for email). PTR: IP → hostname (reverse DNS). SOA: Start of Authority, zone info. Resolution: Browser cache → OS cache → /etc/hosts → Recursive resolver → Root NS (13 sets worldwide) → TLD NS (.com, .in) → Authoritative NS → A record returned. TTL determines cache duration.","Cognizant: 'What is a CDN and how does DNS help it?' CDN uses DNS to return IP of nearest edge server based on requestor's location (GeoDNS).","medium",4.5,82,2024,"2022,2023,2024","Fresher","networks,dns"),
            (6,"DSA","Greedy algorithms - when to use and examples.","Greedy: Make locally optimal choice at each step hoping for global optimum. Works when greedy choice property and optimal substructure hold. Examples: Activity Selection: Sort by end time, pick non-overlapping. Huffman Coding: Build optimal prefix codes using priority queue. Dijkstra's: Always relax shortest known edge (greedy on priority queue). Kruskal's: Add cheapest edge that doesn't create cycle. Fractional Knapsack: Take items by value/weight ratio (greedy works, unlike 0/1 Knapsack which needs DP). When greedy fails: 0/1 Knapsack, coin change with arbitrary denominations.","Cognizant: 'Can greedy solve all optimization problems?' No. Counter-example: Coins [1,3,4], amount=6. Greedy: 4+1+1=3 coins. Optimal: 3+3=2 coins. DP needed.","medium",4.4,68,2023,"2022,2023","Fresher","dsa,greedy"),
            (6,"Python","Python memory management and garbage collection.","Memory management: Python uses private heap. Everything is object with reference count. CPython uses reference counting + cyclic garbage collector. Reference counting: Object deleted when count reaches 0. Problem: Circular references (A→B, B→A, both count=1 but unreachable). Solution: Cyclic GC runs periodically, detects cycles. Generations: 0 (new, collected often), 1, 2 (old, collected rarely). Memory pools: Small objects (< 512 bytes) use pooled allocator. gc module: gc.collect(), gc.disable(). Memory leak: Objects still referenced but logically done with.","Cognizant: 'How to find memory leak in Python?' objgraph library, tracemalloc module, gc.get_objects() to see what's in memory.","hard",4.4,58,2023,"2022,2023","1yr+","python,memory,gc"),
            (6,"Database","Database design - ER diagram to schema with constraints.","ER to Schema: Entity → Table. Attributes → Columns. PK → PRIMARY KEY. One-to-Many: FK on many side. Many-to-Many: Junction table with both FKs. Optional (0..1): Allow NULL FK. Mandatory (1..1): NOT NULL FK. Constraints: PRIMARY KEY (unique + not null), FOREIGN KEY (referential integrity), UNIQUE (no duplicates), NOT NULL, CHECK (domain constraint, e.g., age>0), DEFAULT (default value). Index FK columns for join performance. Denormalization: Sometimes intentionally add redundancy for read performance.","Cognizant: 'Design database for library system.' Entities: Book, Member, Loan. Book-Loan (1:N), Member-Loan (1:N), Loan junction ensures many books per member.","medium",4.5,77,2024,"2022,2023,2024","Fresher","dbms,design,er"),
            # TECH MAHINDRA (id=7) — 7 questions
            (7,"Python","Functional programming in Python - map, filter, reduce, lambda.","Lambda: Anonymous function. lambda x: x**2. map(): Apply function to all. list(map(lambda x: x*2, nums)). filter(): Keep items matching condition. list(filter(lambda x: x>0, nums)). reduce(): Aggregate (from functools). reduce(lambda a,b: a+b, nums) sums all. Comprehensions often cleaner: [x*2 for x in nums]. functools module: partial() for partial application, lru_cache() for memoization decorator. itertools: chain, combinations, permutations, groupby, islice for lazy operations.","Tech Mahindra: 'Rewrite this for loop as a single line.' Always have map/filter/list comprehension equivalent ready. functional style is valued.","medium",4.4,72,2024,"2022,2023,2024","Fresher/1yr","python,functional"),
            (7,"DSA","Dynamic programming - coin change and 0/1 knapsack.","Coin Change (min coins): dp[0]=0; for amount in 1..target: dp[amount]=min(dp[amount-coin]+1 for coin in coins if coin<=amount). Return dp[target] or -1 if unreachable. 0/1 Knapsack: dp[i][w]=max value using first i items with capacity w. dp[i][w]=dp[i-1][w] if wt[i]>w, else max(dp[i-1][w], val[i]+dp[i-1][w-wt[i]]). Space: O(n*W). Optimization: 1D array traversed backward. Return dp[W]. Fractional Knapsack: Greedy (sort by val/wt), 0/1 needs DP.","Tech Mahindra coding: Coin change is most common DP question. Practice both min-coins and count-ways variants.","hard",4.6,88,2024,"2022,2023,2024","1yr+","dsa,dp,knapsack"),
            (7,"OOP","Interface vs Abstract class - design decisions.","Abstract class (Python ABC): Mix of abstract + concrete methods. Has state (instance vars). Single inheritance in Java, multiple in Python. Use when: Sharing code among related classes. Example: Animal ABC with abstract speak() but concrete eat() implementation. Interface (Java/conceptual): All abstract, no state. Multiple implementation. Use when: Defining capability contract for unrelated classes. Example: Flyable interface for Bird and Airplane (unrelated). Python via ABC: All @abstractmethod = interface. Duck typing alternative: Don't inherit, just implement the methods.","Tech Mahindra: 'Would you use abstract class or interface for Shape hierarchy?' Abstract class (related shapes share area() structure). For Printable? Interface (unrelated classes can be printable).","medium",4.3,65,2023,"2022,2023","Fresher","oop,interface,abstract"),
            (7,"Database","Query optimization techniques.","Explain plan: EXPLAIN SELECT... shows query execution plan. Key metrics: rows examined, join type, indexes used. Optimization: 1.Use indexes on WHERE/JOIN columns. 2.Avoid SELECT * (fetch only needed columns). 3.Avoid functions on indexed columns in WHERE (WHERE YEAR(date)=2024 doesn't use index; WHERE date BETWEEN is better). 4.Use JOIN instead of subqueries when possible. 5.Limit result sets (LIMIT). 6.Use EXISTS instead of IN for large subqueries. 7.Partition large tables. 8.Proper data types (INT vs VARCHAR for IDs). 9.Connection pooling.","Tech Mahindra: 'Query is slow, what do you do?' EXPLAIN first, check indexes, look for full table scans, check join types, verify data types match.","hard",4.5,79,2024,"2022,2023,2024","1yr+","dbms,optimization,sql"),
            (7,"Networks","Wireless networking - WiFi standards, security protocols.","WiFi Standards: 802.11a (5GHz, 54Mbps), 802.11b (2.4GHz, 11Mbps), 802.11g (2.4GHz, 54Mbps), 802.11n (WiFi 4, both bands, 600Mbps, MIMO), 802.11ac (WiFi 5, 5GHz, multi-Gbps), 802.11ax (WiFi 6, both bands, OFDMA). Security: WEP (broken, don't use), WPA (TKIP, vulnerable), WPA2 (AES-CCMP, current standard), WPA3 (SAE, latest). Channels: 2.4GHz has 14 channels (1,6,11 non-overlapping). 5GHz has many non-overlapping channels. Frequency: Higher = faster but shorter range.","Tech Mahindra: 'Why is 5GHz faster but shorter range than 2.4GHz?' Higher frequency = more data per second but absorbed more by walls/distance.","medium",4.2,54,2023,"2022,2023","Fresher","networks,wireless"),
            (7,"Python","Multithreading vs multiprocessing in Python.","Threading (threading module): Shares memory, good for IO-bound (file reads, API calls, DB queries). GIL prevents true CPU parallelism. Use: ThreadPoolExecutor. thread = threading.Thread(target=func); thread.start(); thread.join(). Multiprocessing (multiprocessing module): Separate memory space, true parallelism, good for CPU-bound (calculations, image processing). Higher overhead. Use: ProcessPoolExecutor. Process = multiprocessing.Process(target=func); process.start(); process.join(). Async/Await: Single thread, event loop, best for many concurrent IO operations (web servers).","Tech Mahindra: 'When to use async vs multiprocessing?' Async: many concurrent IO tasks (web server). Multiprocessing: CPU-heavy computations (data processing).","hard",4.5,76,2024,"2022,2023,2024","1yr+","python,threading,multiprocessing"),
            (7,"OS","File system internals - FAT, NTFS, ext4.","FAT (File Allocation Table): Simple, widely compatible. FAT32: max 4GB file, 8TB volume. No journaling, no permissions. Good for USB drives. NTFS (New Technology File System): Windows. Journaling (prevents corruption), permissions (ACL), encryption (EFS), compression, max 16TB file. Metadata in MFT (Master File Table). ext4 (Linux): Most common Linux FS. Journaling, large file support (16TB), extents (contiguous block groups = faster), delayed allocation. Inodes: Store metadata but not filename. Directory maps filename → inode number. Blocks: Data storage units.","Tech Mahindra Linux: 'What happens when you delete a file on ext4?' Directory entry removed (inode reference count decremented). Inode freed when count reaches 0. Blocks marked free. Recovery possible if blocks not overwritten.","hard",4.3,62,2023,"2022,2023","1yr+","os,filesystem"),
            # AMAZON (id=8) — 8 questions
            (8,"DSA","Two-pointer and sliding window techniques.","Two-pointer: Two indices moving toward each other or same direction. Reduces O(n^2) to O(n). Example: Two Sum in sorted array, Remove duplicates, Container with most water, 3Sum. Sliding Window: Fixed or variable size window over array. Fixed: Maximum sum of k elements: maintain sum, slide (subtract left, add right). Variable: Longest substring without repeating: expand right, shrink left when duplicate. Examples: Minimum window substring, Longest subarray with sum k.","Amazon LOVES these. Must-practice: Longest substring without repeats, minimum window substring, max sliding window, trapping rain water.","medium",4.8,201,2024,"2020,2021,2022,2023,2024","Any","dsa,twopointer,sliding-window"),
            (8,"DSA","HashMap internals and design problems.","HashMap O(1) avg get/put. Java: array of LinkedList (chaining). Load factor 0.75, resize at 75% capacity. Hash code → bucket index = hash % capacity. Python dict: open addressing, 2/3 load factor threshold. Design problems: LRU Cache: HashMap + DoublyLinkedList. O(1) get and put. HashMap maps key to node, DLL maintains order. Move accessed to front, evict from back. Two Sum: Store value→index in hashmap, check if target-current in map. Group Anagrams: Use sorted string as hashmap key. Find first non-repeating: OrderedDict or two-pass with frequency map.","Amazon: 'Design LRU Cache' is one of the most famous interview questions. Must know cold. HashMap for O(1) lookup, DLL for O(1) move to front/remove from end.","hard",4.7,156,2024,"2021,2022,2023,2024","Any","dsa,hashmap,design"),
            (8,"DSA","Tree traversals, height, diameter, LCA problems.","Traversals: Inorder(L-Root-R), Preorder(Root-L-R), Postorder(L-R-Root), Level-order(BFS). Height: max(height(left), height(right)) + 1. Diameter: Longest path through any node. At each node: left_height + right_height. Max over all nodes. LCA (Lowest Common Ancestor): If both p,q less than node: go left. Both greater: go right. Else: current node is LCA. BST LCA: O(h). General tree: O(n) using recursion. Serialize/Deserialize tree: Preorder with null markers.","Amazon tree problems: Path sum equals target, invert binary tree, check if symmetric, count good nodes, construct tree from traversals. Know recursive and iterative versions.","hard",4.9,189,2024,"2020,2021,2022,2023,2024","Any","dsa,trees,traversal"),
            (8,"System Design","Design URL Shortener like bit.ly.","Requirements: Shorten URL, redirect to original, handle millions of requests. Components: 1.Hash function: MD5 or base62 encoding of counter. 6 chars base62 = 62^6 = 56 billion unique URLs. 2.DB: Store short→long URL mapping. 3.Cache: Redis for hot URLs (90% traffic to 10% URLs). 4.API: POST /shorten → short_url, GET /shortcode → 301 redirect. Scaling: Read-heavy, use read replicas. Rate limiting: 100 requests/min per IP. Analytics: Click tracking with Kafka → data warehouse. Custom aliases, expiry support.","Amazon system design for experienced: Always discuss scale, trade-offs, bottlenecks. Start with requirements, then API, then data model, then scale. Use numbers.","hard",4.7,134,2024,"2022,2023,2024","1yr+","system-design,amazon"),
            (8,"DSA","Graphs - BFS/DFS applications and shortest path.","BFS Applications: Shortest path unweighted graph, level-order tree, bipartite check, word ladder, minimum steps. DFS Applications: Topological sort, cycle detection, strongly connected components, maze solving, count islands. Shortest path algorithms: Dijkstra: weighted, no negative edges, O((V+E)logV) with priority queue. Bellman-Ford: negative edges OK, detects negative cycles, O(VE). Floyd-Warshall: All pairs, O(V^3). A*: Heuristic-based, best for single target. BFS for unweighted = Dijkstra with all weights=1.","Amazon: 'Find if path exists between two nodes.' BFS/DFS. 'Find shortest transformation sequence (word ladder).' BFS. 'Number of provinces (friend circles).' Union-Find or DFS.","medium",4.8,178,2024,"2021,2022,2023,2024","Any","dsa,graphs,shortest-path"),
            (8,"Behavioral","Amazon Leadership Principles in interviews.","Amazon's 16 LPs: Customer Obsession, Ownership, Invent & Simplify, Are Right A Lot, Learn & Be Curious, Hire & Develop the Best, Insist on the Highest Standards, Think Big, Bias for Action, Frugality, Earn Trust, Dive Deep, Have Backbone; Disagree & Commit, Deliver Results, Strive to be Earth's best employer, Success and Scale. Answer format: STAR (Situation, Task, Action, Result with metrics). Example: 'Tell me about a time you disagreed with your manager.' Describe disagreement → data you gathered → how you presented → outcome.","ALL Amazon interviews heavily test LPs. Prepare 2-3 STAR stories covering: conflict resolution, taking initiative, customer focus, failure and learning. Be specific with numbers.","medium",4.8,198,2024,"2021,2022,2023,2024","Any","behavioral,amazon,leadership"),
            (8,"System Design","Design a Rate Limiter.","Types: Token Bucket (tokens added at rate, consumed per request - allows bursts), Leaky Bucket (constant output rate, queue overflows), Fixed Window Counter (count per time window - boundary problem), Sliding Window Log (log timestamps, count last N seconds - accurate but memory), Sliding Window Counter (hybrid - less memory). Implementation: Redis + Lua script for atomic operations. Key: user_id:endpoint. Storage: Hash for token count + timestamp. Distributed rate limiting: Centralized Redis. Headers: X-RateLimit-Limit, X-RateLimit-Remaining, X-RateLimit-Reset. 429 Too Many Requests response.","Amazon asks rate limiter design for senior roles. Know token bucket in detail - it's used in AWS API Gateway. Trade-offs between accuracy and memory.","hard",4.6,112,2024,"2022,2023,2024","1yr+","system-design,rate-limiting"),
            (8,"DSA","Heap and Priority Queue applications.","Heap: Complete binary tree. Min-heap: parent ≤ children, root = minimum. Operations: Insert O(log n), Extract-min O(log n), Build heap O(n) (not O(n log n)!). Python: heapq (min-heap only; negate for max-heap). heapq.heappush(h, val), heapq.heappop(h), heapq.heappushpop, heapq.nlargest(k, arr)=O(n log k). Applications: K largest/smallest elements: push all, maintain size-k heap. Merge K sorted lists: use (val, list_idx, element_idx) tuples. Top K frequent: frequency heap. Median in stream: Two heaps (max-heap lower half, min-heap upper half).","Amazon: 'Find K closest points to origin.' Heap problem: use max-heap of size K, keep closest. Also: Find the running median - two heaps approach.","medium",4.7,145,2024,"2021,2022,2023,2024","Any","dsa,heap,priority-queue"),
            # MICROSOFT (id=9) — 8 questions
            (9,"DSA","Binary search on answer - monotonic function approach.","Not just searching in sorted array. Search on the ANSWER SPACE when there's a monotonic function. Template: lo=min_possible, hi=max_possible; while lo<hi: mid=(lo+hi)//2; if can(mid): hi=mid; else: lo=mid+1; return lo. Problems: Find square root (binary search 1..n). Minimum days to make M bouquets. Koko eating bananas (min speed). Capacity to ship packages. Minimum time to complete tasks. Aggressive cows (maximum minimum distance). Key: Identify that 'if possible with mid, also possible with larger' (or smaller).","Microsoft loves binary search variations. Practice: 'Search in rotated array', 'Find minimum in rotated sorted array', 'Find peak element', 'Kth smallest in BST'.","hard",4.8,145,2024,"2022,2023,2024","Any","dsa,binary-search,advanced"),
            (9,"OOP","SOLID principles deep dive with refactoring examples.","S-Single Responsibility: God class problem. Split UserManager into UserAuth, UserProfile, UserNotification. O-Open/Closed: Adding new shape type shouldn't modify existing code. Use polymorphism (Shape.area() overridden) not if-else chains. L-Liskov: Rectangle and Square problem. Square IS-A Rectangle but setting width changes height violating Rectangle contract. Better: Both extend Shape. I-Interface Segregation: Printer interface with print, scan, fax. SimplePrinter can't fax. Split into Printable, Scannable, Faxable. D-Dependency Inversion: OrderService depends on MySQLDatabase (concrete). Bad. Depend on DatabaseInterface. Inject any implementation.","Microsoft: 'Refactor this code following SOLID.' Be ready to identify violations and explain the correct design. Very common for experienced roles.","hard",4.6,98,2024,"2022,2023,2024","1yr+","oop,solid,refactoring"),
            (9,"System Design","Design a Notification System.","Requirements: Send email, SMS, push notifications. Millions of notifications/day. Components: 1.API Layer: POST /notifications with type, recipient, content. 2.Message Queue (Kafka/RabbitMQ): Decouple producers from consumers. Topic per channel. 3.Workers: Email worker (SMTP/SendGrid), SMS worker (Twilio), Push worker (FCM/APNs). 4.Rate Limiting: Don't overwhelm users. 5.Retry with exponential backoff for failures. 6.Templates: Stored in DB, populate with user data. 7.Preferences: User opt-out stored in DB/cache. 8.Analytics: Track delivery, open rates. Reliability: At-least-once delivery with idempotency keys.","Microsoft system design: Always mention: scalability, fault tolerance, exactly-once vs at-least-once delivery trade-offs. Kafka for high throughput notifications.","hard",4.6,87,2024,"2022,2023,2024","1yr+","system-design,notifications"),
            (9,"DSA","Recursion and divide-and-conquer.","Divide & Conquer: Split problem into subproblems, solve independently, combine. Examples: Merge Sort (split, sort each, merge), Quick Sort (partition around pivot, sort each side), Binary Search (eliminate half), Strassen's Matrix Multiplication. Master Theorem for complexity: T(n) = aT(n/b) + f(n). a=subproblems, b=size reduction factor. Recursion pitfalls: No base case → infinite recursion. Overlapping subproblems → use memoization (becomes DP). Stack overflow → convert to iterative with explicit stack. Tail recursion: Last operation is recursive call (Python doesn't optimize this).","Microsoft: 'Implement merge sort and analyze complexity.' T(n) = 2T(n/2) + O(n) → O(n log n) by Master Theorem. Also know: Quick sort average case analysis.","medium",4.5,134,2024,"2021,2022,2023,2024","Any","dsa,recursion,divide-conquer"),
            (9,"Python","Async programming - asyncio, async/await, event loop.","async def: Defines coroutine. await: Pause coroutine until awaitable completes. Event loop: Single thread, schedules coroutines. asyncio.run(main()): Entry point. asyncio.gather(*coros): Run concurrently. asyncio.create_task(): Schedule without waiting. aiohttp for async HTTP. asyncpg for async DB. Example: async def fetch(url): async with aiohttp.ClientSession() as session: async with session.get(url) as resp: return await resp.json(). vs threads: async is cooperative (yields control explicitly). Threads: preemptive (OS decides). Async better for IO-bound with many concurrent connections.","Microsoft: 'Build async web scraper.' Use asyncio + aiohttp + asyncio.gather() to fetch multiple URLs concurrently vs sequential requests.","hard",4.5,89,2024,"2022,2023,2024","1yr+","python,async,asyncio"),
            (9,"Database","Database sharding, replication, and consistency.","Replication: Copy data to multiple servers. Master-Slave (primary-replica): Writes to master, reads from replicas. Eventual consistency. Master-Master: Both accept writes. Conflict resolution needed. Sharding: Horizontal partitioning. Split data across multiple DBs. Strategies: Hash sharding (user_id % num_shards), Range sharding (A-M shard1, N-Z shard2), Directory sharding (lookup table). Problems: Cross-shard joins expensive, rebalancing hard, transactions across shards. Consistent hashing: Minimizes data movement when adding/removing nodes.","Microsoft: 'How would you scale a DB for 1 billion users?' Read replicas first, then caching (Redis), then sharding. Discuss trade-offs of each.","hard",4.5,82,2024,"2022,2023,2024","1yr+","dbms,sharding,scaling"),
            (9,"DSA","String algorithms - pattern matching, palindromes.","Pattern matching: Naive O(nm). KMP: O(n+m) using failure function (partial match table). Rabin-Karp: Rolling hash O(n+m) average. Boyer-Moore: Most practical, O(n/m) average. Palindrome: isPalindrome: two pointers from ends. Longest palindromic substring: Expand around center O(n^2). Manacher's algorithm O(n). Anagram check: Sort both strings or frequency count. String hashing: Convert to hash for O(1) comparison. Trie: O(L) insert/search for strings. Longest common prefix: Vertical scan or binary search on length.","Microsoft coding: 'Check if permutation of palindrome' - frequency map, at most one odd-count char. 'Implement strstr' - KMP or brute force. 'Group anagrams' - sort as key.","medium",4.5,112,2024,"2021,2022,2023,2024","Any","dsa,strings,pattern-matching"),
            (9,"OOP","Design a parking lot system - OOP design.","Classes: ParkingLot (floors, entry/exit), ParkingFloor (spots), ParkingSpot (Small/Medium/Large), Vehicle (Car/Bike/Truck), Ticket (entry time, spot), PaymentProcessor. Patterns: Strategy for pricing (hourly, flat rate). Observer for spot availability updates. Factory for creating vehicles. Relationships: ParkingLot has ParkingFloors. Floor has Spots. Spot can have Vehicle. Ticket links Vehicle to Spot. Methods: parkVehicle(vehicle) → Ticket, exitVehicle(ticket) → amount, getAvailableSpots(type). Edge cases: Oversized vehicles, reserved spots, handicapped spots, electric vehicle charging.","Microsoft OOP design favorite. Draw class diagram first! Interviewers want to see: proper encapsulation, right relationships (has-a vs is-a), extensibility.","hard",4.7,125,2024,"2022,2023,2024","1yr+","oop,design,parking-lot"),
            # GOOGLE (id=10) — 8 questions
            (10,"DSA","Heap and top-K problems.","Min-heap: parent ≤ children, O(log n) insert/extract. Max-heap: negate values in Python's heapq. Top K largest: Min-heap of size K. For each element: if larger than heap top, replace. O(n log k) - better than sorting O(n log n). Top K frequent: Count frequencies, then heap on (freq, element). Kth largest in stream: Maintain min-heap of size K, top is answer. Merge K sorted lists: (value, list_idx, element_idx) in heap, extract min, push next from same list. Find median in stream: Max-heap (lower half) + min-heap (upper half). Balance heaps to differ by at most 1.","Google: 'Find top 10 search queries from a file with 1 billion entries.' External sort or reservoir sampling or hash counting + heap. Discuss memory constraints.","hard",4.9,189,2024,"2021,2022,2023,2024","Any","dsa,heap,topk"),
            (10,"DSA","Big-O notation, amortized analysis, space complexity.","Big-O basics: O(1)<O(log n)<O(n)<O(n log n)<O(n²)<O(2^n)<O(n!). Amortized analysis: Average cost over sequence of operations. Dynamic array doubling: Each element O(1) amortized even though resize is O(n). Banker's method: each cheap op pays for future expensive ops. Space complexity: Extra memory beyond input. O(1) space: Iterative in-place. O(log n): Recursive binary search (call stack). O(n): Storing copy of input. O(n²): 2D DP table. Trade-offs: Time vs space. Memoization trades O(n) space for O(n) time improvement.","Google expects instant O analysis for all code. For every solution: state time AND space complexity unprompted. Common mistake: forgetting recursion stack space.","medium",4.9,267,2024,"2018,2019,2020,2021,2022,2023,2024","Any","dsa,complexity,big-o"),
            (10,"System Design","Design Google Search.","Web Crawler: BFS from seed URLs, respect robots.txt, politeness delay per domain, distributed with consistent hashing. Indexer: Parse HTML, extract text, build inverted index (word → [doc_ids]). TF-IDF + PageRank for ranking. Storage: Bigtable for crawled pages, distributed inverted index. Query Processing: Tokenize, remove stopwords, stem. Look up index, rank by relevance. Query suggestion: Trie on historical queries. Caching: Top 1% queries serve 50% traffic. Scale: Handle 8.5B searches/day. Personalization: User history affects ranking. SafeSearch: ML classifier on content.","Google system design flagship question. Show knowledge of: inverted index, MapReduce for building index, consistent hashing for distribution. Mention Bigtable and GFS.","hard",4.8,176,2024,"2022,2023,2024","1yr+","system-design,google,search"),
            (10,"DSA","Graph algorithms - advanced problems.","Topological Sort: DFS-based: post-order reversal. Kahn's: BFS with in-degree. For scheduling, build order. Strongly Connected Components: Tarjan's or Kosaraju's algorithm. Minimum Spanning Tree: Kruskal's (sort edges, Union-Find) or Prim's (greedy with priority queue). Bipartite: BFS/DFS, 2-color. If odd cycle → not bipartite. Articulation Points: DFS with discovery time and low values (Tarjan's). Bridges: Edges whose removal disconnects graph. Maximum Flow: Ford-Fulkerson with BFS (Edmonds-Karp) O(VE²).","Google: 'Course schedule problem' (detect cycle in directed graph, topological sort). 'Number of islands' (DFS). 'Alien dictionary' (topological sort from word ordering).","hard",4.7,143,2024,"2021,2022,2023,2024","Any","dsa,graphs,advanced"),
            (10,"System Design","Design YouTube.","Upload: Chunked upload to object storage (GCS). Transcoding pipeline: Multiple resolutions (360p/720p/1080p/4K) using distributed workers. CDN: Cache popular videos at edge nodes globally. Streaming: Adaptive bitrate (DASH/HLS) - switches quality based on bandwidth. Metadata DB: Video info, user info. Recommendation: Collaborative filtering + content-based. Comments: Separate DB, paginated. Thumbnails: Stored in CDN, generated during transcoding. View count: Approximate with probabilistic counting (HyperLogLog). Scale: 500 hours of video uploaded per minute.","Google: Discuss trade-offs: consistency vs availability for view counts. Explain why exact view counts are impractical at scale. Mention hot/cold storage for old videos.","hard",4.7,134,2024,"2022,2023,2024","1yr+","system-design,youtube,streaming"),
            (10,"DSA","Trie data structure - implementation and applications.","Trie (Prefix tree): Each node has map of children, isEndOfWord flag. Insert: For each char, create node if not exists, move to child. O(L). Search: Follow chars, check isEnd. O(L). StartsWith: Like search but don't check isEnd. O(L). Space: O(ALPHABET_SIZE × N × L). Applications: Autocomplete (return all words with prefix), spell checker, IP routing (longest prefix match), word search in grid, dictionary. Compressed Trie (Radix tree): Merge single-child chains. Used in Linux routing tables.","Google: Implement autocomplete. DFS from prefix node to collect all words. Add frequency to each node, use priority queue to return top-K suggestions efficiently.","hard",4.6,121,2024,"2021,2022,2023,2024","Any","dsa,trie,strings"),
            (10,"Behavioral","How to approach Google behavioral interviews.","Google values: Googleyness (collaboration, comfort with ambiguity), Leadership, Role-related knowledge, General cognitive ability. STAR format mandatory. Googliness questions: 'How do you handle working on something you disagree with?' 'Tell me about a time you took initiative.' Cognitive: 'Estimate how many piano tuners in Chicago' - Fermi estimation. Think out loud. Structure: City pop (3M) × households (1.5M) × pianos owned (1 in 20 = 75K) × tunings/year (1) = 75K tunings. Per tuner: 4/day × 250 days = 1000/year. Tuners needed: 75.","Google interviews are holistic. Prepare 5+ STAR stories, know your resume deeply, be ready for Fermi estimates, and show structured thinking for all problems.","medium",4.8,156,2024,"2022,2023,2024","Any","behavioral,google,estimation"),
            (10,"DSA","Segment trees and advanced range queries.","Segment Tree: Array-based tree for range queries and point/range updates. Build: O(n). Query (range sum/min/max): O(log n). Update: O(log n). Implementation: tree array of size 4n. Build: tree[node]=tree[2*node]+tree[2*node+1]. Query: if range outside return 0; if inside return tree[node]; else return query(left)+query(right). Lazy propagation: Defer range updates. O(log n) range update with lazy array. Fenwick Tree (BIT): Simpler, O(log n) point update and prefix query. Less code than segment tree. Use for: Range sum, range min/max, count of inversions, order statistics.","Google: 'Range sum query with updates' - Segment tree or Fenwick. 'Count smaller numbers after self' - Fenwick tree with coordinate compression.","hard",4.6,98,2024,"2022,2023,2024","Any","dsa,segment-tree,advanced"),
        ]
        c.executemany("INSERT INTO interview_questions(company_id,topic,question,answer,notes,difficulty,rating,times_asked,last_year,years_asked,role_level,tags) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)", iq)

    conn.commit()
    conn.close()

# ── Error handlers ─────────────────────────────────────────────────────────────
@app.errorhandler(400)
def bad_req(e): return jsonify({"error":"Bad request"}), 400
@app.errorhandler(404)
def not_found(e): return jsonify({"error":"Not found"}), 404
@app.errorhandler(429)
def rate_hit(e):
    sec_log("RATE_LIMIT","",level="warning")
    return jsonify({"error":"Too many requests. Slow down."}), 429
@app.errorhandler(500)
def srv_err(e):
    logger.error(f"500: {e}")
    return jsonify({"error":"Internal server error"}), 500

# ── Auth Helpers ─────────────────────────────────────────────────────────────
def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if 'user_id' not in session:
            return redirect(url_for('login_page'))
        return f(*args, **kwargs)
    return decorated

def current_user():
    if 'user_id' not in session:
        return None
    return get_db().execute("SELECT id,username,email,full_name FROM users WHERE id=?", (session['user_id'],)).fetchone()

# ── Auth Routes ───────────────────────────────────────────────────────────────
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

    # Validate username
    if not re.match(r'^[A-Za-z0-9_]{3,20}$', username):
        return jsonify({"error": "Username: 3-20 chars, letters/digits/underscore only"}), 400

    # Validate email
    if not re.match(r'^[^@\s]+@[^@\s]+\.[^@\s]+$', email) or len(email) > 100:
        return jsonify({"error": "Enter a valid email address"}), 400

    # Validate password strength
    if len(password) < 8:
        return jsonify({"error": "Password must be at least 8 characters"}), 400
    if not re.search(r'[A-Z]', password):
        return jsonify({"error": "Password must contain at least one uppercase letter"}), 400
    if not re.search(r'[0-9]', password):
        return jsonify({"error": "Password must contain at least one number"}), 400

    db = get_db()
    # Check username taken
    if db.execute("SELECT id FROM users WHERE username=?", (username,)).fetchone():
        return jsonify({"error": "Username already taken"}), 409
    # Check email taken
    if db.execute("SELECT id FROM users WHERE email=?", (email,)).fetchone():
        return jsonify({"error": "Email already registered"}), 409

    pw_hash = generate_password_hash(password, method='pbkdf2:sha256', salt_length=16)
    db.execute(
        "INSERT INTO users(username,email,password_hash,full_name) VALUES(?,?,?,?)",
        (username, email.lower(), pw_hash, full_name or username)
    )
    db.commit()

    # Auto login after register
    user = db.execute("SELECT id,username,full_name FROM users WHERE username=?", (username,)).fetchone()
    session.permanent = True
    session['user_id']   = user['id']
    session['username']  = user['username']
    session['full_name'] = user['full_name']

    sec_log("REGISTER", f"username={username!r}")
    return jsonify({"status": "ok", "username": username, "full_name": user['full_name']})

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

    db  = get_db()
    row = db.execute(
        "SELECT id,username,email,password_hash,full_name,is_active FROM users WHERE username=? OR email=?",
        (username, username.lower())
    ).fetchone()

    if not row or not check_password_hash(row['password_hash'], password):
        sec_log("LOGIN_FAIL", f"username={username!r}", "warning")
        return jsonify({"error": "Invalid username or password"}), 401

    if not row['is_active']:
        return jsonify({"error": "Account disabled. Contact support."}), 403

    # Update last login
    db.execute("UPDATE users SET last_login=? WHERE id=?", (datetime.now(), row['id']))
    db.commit()

    session.permanent = True
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
    admin_row = get_db().execute("SELECT is_admin FROM users WHERE id=?", (session['user_id'],)).fetchone()
    return jsonify({"logged_in": True, "username": u['username'], "full_name": u['full_name'], "email": u['email'], "is_admin": bool(admin_row and admin_row['is_admin'])})

# ── Quiz Routes ───────────────────────────────────────────────────────────────
@app.route("/")
@login_required
def index(): return render_template("index.html")

@app.route("/api/categories")
@limiter.limit("200 per minute")
def get_categories():
    db = get_db()
    rows = db.execute("SELECT c.id,c.name,c.icon,c.color,COUNT(q.id) AS qc FROM categories c LEFT JOIN questions q ON c.id=q.category_id GROUP BY c.id ORDER BY c.id").fetchall()
    return jsonify([dict(r) for r in rows])

@app.route("/api/questions/<int:cat_id>")
@limiter.limit("100 per minute")
def get_questions(cat_id):
    db = get_db()
    if not db.execute("SELECT id FROM categories WHERE id=?", (cat_id,)).fetchone():
        return jsonify({"error":"Category not found"}), 404
    limit = min(max(request.args.get("limit",10,type=int),1), MAX_LIMIT)
    qs = db.execute("SELECT id,question,option_a,option_b,option_c,option_d,difficulty FROM questions WHERE category_id=? ORDER BY RANDOM() LIMIT ?", (cat_id,limit)).fetchall()
    result = [{"id":q["id"],"question":q["question"],"options":{"A":q["option_a"],"B":q["option_b"],"C":q["option_c"],"D":q["option_d"]},"difficulty":q["difficulty"]} for q in qs]
    session["active_qids"] = [r["id"] for r in result]
    session["cat_id"] = cat_id
    return jsonify(result)

@app.route("/api/check_answer", methods=["POST"])
@limiter.limit("200 per minute")
def check_answer():
    data = request.get_json(silent=True)
    if not data: return jsonify({"error":"Invalid JSON"}), 400
    qid = data.get("question_id")
    user_ans = str(data.get("answer","")).upper().strip()
    if not isinstance(qid,int) or qid < 1: return jsonify({"error":"Invalid question id"}), 400
    if user_ans not in VALID_ANS: return jsonify({"error":"Answer must be A, B, C or D"}), 400
    active = session.get("active_qids",[])
    if active and qid not in active:
        sec_log("OOB_QID",f"qid={qid}","warning")
        return jsonify({"error":"Question not in active quiz"}), 403
    row = get_db().execute("SELECT correct_answer FROM questions WHERE id=?",(qid,)).fetchone()
    if not row: return jsonify({"error":"Question not found"}), 404
    return jsonify({"correct":user_ans==row["correct_answer"],"correct_answer":row["correct_answer"]})

@app.route("/api/save_result", methods=["POST"])
@limiter.limit("50 per minute")
def save_result():
    data = request.get_json(silent=True)
    if not data: return jsonify({"error":"Invalid JSON"}), 400
    raw_name = str(data.get("player_name",""))
    ok, msg = validate_name(raw_name)
    if not ok:
        sec_log("INVALID_NAME",msg,"warning")
        return jsonify({"error":msg}), 400
    name = sanitize(raw_name)
    cat_id=data.get("category_id"); score=data.get("score",0); total=data.get("total_questions",10); ttime=data.get("time_taken",0)
    if not isinstance(cat_id,int) or cat_id<1: return jsonify({"error":"Invalid category"}), 400
    if not isinstance(score,int) or score<0: return jsonify({"error":"Invalid score"}), 400
    if not isinstance(total,int) or not(1<=total<=MAX_LIMIT): return jsonify({"error":"Invalid total"}), 400
    if not isinstance(ttime,int) or not(0<=ttime<=7200): return jsonify({"error":"Invalid time"}), 400
    if score>total: return jsonify({"error":"Score cannot exceed total"}), 400
    db = get_db()
    if not db.execute("SELECT id FROM categories WHERE id=?",(cat_id,)).fetchone(): return jsonify({"error":"Category not found"}), 404
    db.execute("INSERT INTO results(player_name,category_id,score,total_questions,time_taken) VALUES(?,?,?,?,?)",(name,cat_id,score,total,ttime))
    db.commit()
    sec_log("QUIZ_COMPLETE",f"player={name!r} cat={cat_id} score={score}/{total}")
    return jsonify({"status":"saved"})

@app.route("/api/leaderboard")
@limiter.limit("100 per minute")
def leaderboard():
    cat_id = request.args.get("category_id",type=int)
    db = get_db()
    if cat_id is not None:
        if cat_id<1: return jsonify({"error":"Invalid category"}), 400
        rows = db.execute("SELECT r.player_name,r.score,r.total_questions,r.time_taken,r.played_at,c.name AS category,c.icon FROM results r JOIN categories c ON r.category_id=c.id WHERE r.category_id=? ORDER BY r.score DESC,r.time_taken ASC LIMIT 10",(cat_id,)).fetchall()
    else:
        rows = db.execute("SELECT r.player_name,r.score,r.total_questions,r.time_taken,r.played_at,c.name AS category,c.icon FROM results r JOIN categories c ON r.category_id=c.id ORDER BY r.score DESC,r.time_taken ASC LIMIT 10").fetchall()
    return jsonify([dict(r) for r in rows])

@app.route("/api/stats")
@limiter.limit("100 per minute")
def stats():
    db = get_db()
    total = db.execute("SELECT COUNT(*) AS c FROM results").fetchone()["c"]
    avg   = db.execute("SELECT AVG(CAST(score AS REAL)/total_questions*100) AS a FROM results").fetchone()["a"]
    top   = db.execute("SELECT player_name,SUM(score) AS ts FROM results GROUP BY player_name ORDER BY ts DESC LIMIT 1").fetchone()
    return jsonify({"total_games":total,"avg_score":round(avg or 0,1),"top_player":dict(top) if top else None})

# ── Interview Routes ───────────────────────────────────────────────────────────
@app.route("/interview")
@login_required
def interview(): return render_template("interview.html")

@app.route("/api/interview/companies")
@limiter.limit("200 per minute")
def iv_companies():
    rows = get_db().execute("SELECT c.*,COUNT(q.id) AS q_count,ROUND(AVG(q.rating),1) AS avg_rating FROM interview_companies c LEFT JOIN interview_questions q ON c.id=q.company_id GROUP BY c.id ORDER BY c.id").fetchall()
    return jsonify([dict(r) for r in rows])

@app.route("/api/interview/questions")
@limiter.limit("100 per minute")
def iv_questions():
    company_id = request.args.get("company_id",type=int)
    topic      = sanitize(request.args.get("topic",""))
    difficulty = request.args.get("difficulty","")
    search     = sanitize(request.args.get("search",""))
    if difficulty and difficulty not in ("easy","medium","hard"):
        return jsonify({"error":"Invalid difficulty"}), 400
    db = get_db()
    sql = "SELECT q.*,c.name AS company_name,c.logo,c.color FROM interview_questions q JOIN interview_companies c ON q.company_id=c.id WHERE 1=1"
    params = []
    if company_id:
        if company_id<1: return jsonify({"error":"Invalid company"}), 400
        sql += " AND q.company_id=?"; params.append(company_id)
    if topic: sql += " AND q.topic=?"; params.append(topic)
    if difficulty: sql += " AND q.difficulty=?"; params.append(difficulty)
    if search: sql += " AND (q.question LIKE ? OR q.tags LIKE ? OR q.topic LIKE ?)"; params += [f"%{search}%"]*3
    sql += " ORDER BY q.times_asked DESC, q.rating DESC"
    rows = db.execute(sql, params).fetchall()
    return jsonify([dict(r) for r in rows])

@app.route("/api/interview/topics")
@limiter.limit("200 per minute")
def iv_topics():
    rows = get_db().execute("SELECT DISTINCT topic FROM interview_questions ORDER BY topic").fetchall()
    return jsonify([r["topic"] for r in rows])


# ── Admin Helpers ─────────────────────────────────────────────────────────────
def admin_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if 'user_id' not in session:
            return redirect(url_for('login_page'))
        u = get_db().execute("SELECT is_admin FROM users WHERE id=?", (session['user_id'],)).fetchone()
        if not u or not u['is_admin']:
            return jsonify({"error": "Admin access required"}), 403
        return f(*args, **kwargs)
    return decorated

# ── Admin Page ────────────────────────────────────────────────────────────────
@app.route("/admin")
def admin_page():
    if 'user_id' not in session:
        return redirect(url_for('login_page'))
    u = get_db().execute("SELECT is_admin,username FROM users WHERE id=?", (session['user_id'],)).fetchone()
    if not u or not u['is_admin']:
        return redirect(url_for('index'))
    return render_template("admin.html")

# ── Admin Stats ───────────────────────────────────────────────────────────────
@app.route("/api/admin/stats")
@admin_required
def admin_stats():
    db = get_db()
    return jsonify({
        "total_users":     db.execute("SELECT COUNT(*) FROM users").fetchone()[0],
        "total_quiz_q":    db.execute("SELECT COUNT(*) FROM questions").fetchone()[0],
        "total_iv_q":      db.execute("SELECT COUNT(*) FROM interview_questions").fetchone()[0],
        "total_games":     db.execute("SELECT COUNT(*) FROM results").fetchone()[0],
        "total_companies": db.execute("SELECT COUNT(*) FROM interview_companies").fetchone()[0],
        "categories":      [dict(r) for r in db.execute("SELECT c.id,c.name,c.icon,COUNT(q.id) AS cnt FROM categories c LEFT JOIN questions q ON c.id=q.category_id GROUP BY c.id").fetchall()],
    })

# ── Admin: Quiz Questions CRUD ────────────────────────────────────────────────
@app.route("/api/admin/quiz/questions")
@admin_required
def admin_quiz_list():
    cat_id = request.args.get("category_id", type=int)
    search = sanitize(request.args.get("search",""))
    db = get_db()
    sql = "SELECT q.*,c.name AS cat_name FROM questions q JOIN categories c ON q.category_id=c.id WHERE 1=1"
    params = []
    if cat_id: sql += " AND q.category_id=?"; params.append(cat_id)
    if search: sql += " AND q.question LIKE ?"; params.append(f"%{search}%")
    sql += " ORDER BY q.category_id, q.id"
    rows = db.execute(sql, params).fetchall()
    return jsonify([dict(r) for r in rows])

@app.route("/api/admin/quiz/questions", methods=["POST"])
@admin_required
def admin_quiz_add():
    d = request.get_json(silent=True)
    if not d: return jsonify({"error":"Invalid JSON"}), 400
    cat_id   = d.get("category_id")
    question = sanitize(str(d.get("question","")))
    opt_a    = sanitize(str(d.get("option_a","")))
    opt_b    = sanitize(str(d.get("option_b","")))
    opt_c    = sanitize(str(d.get("option_c","")))
    opt_d    = sanitize(str(d.get("option_d","")))
    correct  = str(d.get("correct_answer","")).upper().strip()
    diff     = str(d.get("difficulty","medium")).lower()
    if not all([question, opt_a, opt_b, opt_c, opt_d]):
        return jsonify({"error":"All fields required"}), 400
    if correct not in VALID_ANS: return jsonify({"error":"Correct answer must be A/B/C/D"}), 400
    if diff not in ("easy","medium","hard"): return jsonify({"error":"Invalid difficulty"}), 400
    if not isinstance(cat_id, int) or cat_id < 1: return jsonify({"error":"Invalid category"}), 400
    db = get_db()
    if not db.execute("SELECT id FROM categories WHERE id=?", (cat_id,)).fetchone():
        return jsonify({"error":"Category not found"}), 404
    cur = db.execute(
        "INSERT INTO questions(category_id,question,option_a,option_b,option_c,option_d,correct_answer,difficulty) VALUES(?,?,?,?,?,?,?,?)",
        (cat_id,question,opt_a,opt_b,opt_c,opt_d,correct,diff)
    )
    db.commit()
    sec_log("ADMIN_ADD_QUIZ_Q", f"id={cur.lastrowid} cat={cat_id}")
    return jsonify({"status":"added","id":cur.lastrowid})

@app.route("/api/admin/quiz/questions/<int:qid>", methods=["PUT"])
@admin_required
def admin_quiz_edit(qid):
    d = request.get_json(silent=True)
    if not d: return jsonify({"error":"Invalid JSON"}), 400
    db = get_db()
    if not db.execute("SELECT id FROM questions WHERE id=?", (qid,)).fetchone():
        return jsonify({"error":"Question not found"}), 404
    question = sanitize(str(d.get("question","")))
    opt_a    = sanitize(str(d.get("option_a","")))
    opt_b    = sanitize(str(d.get("option_b","")))
    opt_c    = sanitize(str(d.get("option_c","")))
    opt_d    = sanitize(str(d.get("option_d","")))
    correct  = str(d.get("correct_answer","")).upper().strip()
    diff     = str(d.get("difficulty","medium")).lower()
    cat_id   = d.get("category_id")
    if not all([question, opt_a, opt_b, opt_c, opt_d]):
        return jsonify({"error":"All fields required"}), 400
    if correct not in VALID_ANS: return jsonify({"error":"Correct answer must be A/B/C/D"}), 400
    if diff not in ("easy","medium","hard"): return jsonify({"error":"Invalid difficulty"}), 400
    db.execute(
        "UPDATE questions SET category_id=?,question=?,option_a=?,option_b=?,option_c=?,option_d=?,correct_answer=?,difficulty=? WHERE id=?",
        (cat_id,question,opt_a,opt_b,opt_c,opt_d,correct,diff,qid)
    )
    db.commit()
    sec_log("ADMIN_EDIT_QUIZ_Q", f"id={qid}")
    return jsonify({"status":"updated"})

@app.route("/api/admin/quiz/questions/<int:qid>", methods=["DELETE"])
@admin_required
def admin_quiz_delete(qid):
    db = get_db()
    if not db.execute("SELECT id FROM questions WHERE id=?", (qid,)).fetchone():
        return jsonify({"error":"Question not found"}), 404
    db.execute("DELETE FROM questions WHERE id=?", (qid,))
    db.commit()
    sec_log("ADMIN_DEL_QUIZ_Q", f"id={qid}")
    return jsonify({"status":"deleted"})

# ── Admin: Interview Questions CRUD ──────────────────────────────────────────
@app.route("/api/admin/interview/questions")
@admin_required
def admin_iv_list():
    company_id = request.args.get("company_id", type=int)
    search     = sanitize(request.args.get("search",""))
    db = get_db()
    sql = "SELECT q.*,c.name AS company_name FROM interview_questions q JOIN interview_companies c ON q.company_id=c.id WHERE 1=1"
    params = []
    if company_id: sql += " AND q.company_id=?"; params.append(company_id)
    if search:     sql += " AND q.question LIKE ?"; params.append(f"%{search}%")
    sql += " ORDER BY q.company_id, q.id"
    rows = db.execute(sql, params).fetchall()
    return jsonify([dict(r) for r in rows])

@app.route("/api/admin/interview/questions", methods=["POST"])
@admin_required
def admin_iv_add():
    d = request.get_json(silent=True)
    if not d: return jsonify({"error":"Invalid JSON"}), 400
    company_id  = d.get("company_id")
    topic       = sanitize(str(d.get("topic","")))
    question    = sanitize(str(d.get("question","")))
    answer      = sanitize(str(d.get("answer","")))
    notes       = sanitize(str(d.get("notes","")))
    difficulty  = str(d.get("difficulty","medium")).lower()
    rating      = float(d.get("rating", 4.0))
    times_asked = int(d.get("times_asked", 1))
    last_year   = d.get("last_year")
    years_asked = sanitize(str(d.get("years_asked","")))
    role_level  = sanitize(str(d.get("role_level","Fresher")))
    tags        = sanitize(str(d.get("tags","")))
    if not all([topic, question, answer]):
        return jsonify({"error":"Topic, question and answer are required"}), 400
    if difficulty not in ("easy","medium","hard"):
        return jsonify({"error":"Invalid difficulty"}), 400
    if not isinstance(company_id, int) or company_id < 1:
        return jsonify({"error":"Invalid company"}), 400
    if not (1.0 <= rating <= 5.0):
        return jsonify({"error":"Rating must be 1.0-5.0"}), 400
    db = get_db()
    if not db.execute("SELECT id FROM interview_companies WHERE id=?", (company_id,)).fetchone():
        return jsonify({"error":"Company not found"}), 404
    cur = db.execute(
        "INSERT INTO interview_questions(company_id,topic,question,answer,notes,difficulty,rating,times_asked,last_year,years_asked,role_level,tags) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)",
        (company_id,topic,question,answer,notes,difficulty,rating,times_asked,last_year,years_asked,role_level,tags)
    )
    db.commit()
    sec_log("ADMIN_ADD_IV_Q", f"id={cur.lastrowid} company={company_id}")
    return jsonify({"status":"added","id":cur.lastrowid})

@app.route("/api/admin/interview/questions/<int:qid>", methods=["PUT"])
@admin_required
def admin_iv_edit(qid):
    d = request.get_json(silent=True)
    if not d: return jsonify({"error":"Invalid JSON"}), 400
    db = get_db()
    if not db.execute("SELECT id FROM interview_questions WHERE id=?", (qid,)).fetchone():
        return jsonify({"error":"Question not found"}), 404
    company_id  = d.get("company_id")
    topic       = sanitize(str(d.get("topic","")))
    question    = sanitize(str(d.get("question","")))
    answer      = sanitize(str(d.get("answer","")))
    notes       = sanitize(str(d.get("notes","")))
    difficulty  = str(d.get("difficulty","medium")).lower()
    rating      = float(d.get("rating", 4.0))
    times_asked = int(d.get("times_asked", 1))
    last_year   = d.get("last_year")
    years_asked = sanitize(str(d.get("years_asked","")))
    role_level  = sanitize(str(d.get("role_level","Fresher")))
    tags        = sanitize(str(d.get("tags","")))
    if not all([topic, question, answer]): return jsonify({"error":"Topic, question and answer required"}), 400
    if difficulty not in ("easy","medium","hard"): return jsonify({"error":"Invalid difficulty"}), 400
    db.execute(
        "UPDATE interview_questions SET company_id=?,topic=?,question=?,answer=?,notes=?,difficulty=?,rating=?,times_asked=?,last_year=?,years_asked=?,role_level=?,tags=? WHERE id=?",
        (company_id,topic,question,answer,notes,difficulty,rating,times_asked,last_year,years_asked,role_level,tags,qid)
    )
    db.commit()
    sec_log("ADMIN_EDIT_IV_Q", f"id={qid}")
    return jsonify({"status":"updated"})

@app.route("/api/admin/interview/questions/<int:qid>", methods=["DELETE"])
@admin_required
def admin_iv_delete(qid):
    db = get_db()
    if not db.execute("SELECT id FROM interview_questions WHERE id=?", (qid,)).fetchone():
        return jsonify({"error":"Question not found"}), 404
    db.execute("DELETE FROM interview_questions WHERE id=?", (qid,))
    db.commit()
    sec_log("ADMIN_DEL_IV_Q", f"id={qid}")
    return jsonify({"status":"deleted"})

# ── Admin: Users Management ───────────────────────────────────────────────────
@app.route("/api/admin/users")
@admin_required
def admin_users():
    rows = get_db().execute(
        "SELECT id,username,email,full_name,is_admin,is_active,created_at,last_login FROM users ORDER BY id"
    ).fetchall()
    return jsonify([dict(r) for r in rows])

@app.route("/api/admin/users/<int:uid>/toggle", methods=["POST"])
@admin_required
def admin_toggle_user(uid):
    if uid == session['user_id']:
        return jsonify({"error":"Cannot deactivate yourself"}), 400
    db = get_db()
    u = db.execute("SELECT is_active,username FROM users WHERE id=?", (uid,)).fetchone()
    if not u: return jsonify({"error":"User not found"}), 404
    new_state = 0 if u['is_active'] else 1
    db.execute("UPDATE users SET is_active=? WHERE id=?", (new_state, uid))
    db.commit()
    sec_log("ADMIN_TOGGLE_USER", f"uid={uid} username={u['username']} active={new_state}")
    return jsonify({"status":"ok","is_active":new_state})

@app.route("/api/admin/users/<int:uid>", methods=["DELETE"])
@admin_required
def admin_delete_user(uid):
    if uid == session['user_id']:
        return jsonify({"error":"Cannot delete yourself"}), 400
    db = get_db()
    u = db.execute("SELECT username,is_admin FROM users WHERE id=?", (uid,)).fetchone()
    if not u: return jsonify({"error":"User not found"}), 404
    if u['is_admin']: return jsonify({"error":"Cannot delete admin accounts"}), 403
    db.execute("DELETE FROM users WHERE id=?", (uid,))
    db.commit()
    sec_log("ADMIN_DEL_USER", f"uid={uid} username={u['username']}")
    return jsonify({"status":"deleted"})

# ── Admin: Categories ─────────────────────────────────────────────────────────
@app.route("/api/admin/categories")
@admin_required
def admin_categories():
    rows = get_db().execute("SELECT * FROM categories ORDER BY id").fetchall()
    return jsonify([dict(r) for r in rows])

@app.route("/api/admin/companies")
@admin_required
def admin_companies():
    rows = get_db().execute("SELECT * FROM interview_companies ORDER BY id").fetchall()
    return jsonify([dict(r) for r in rows])

if __name__ == "__main__":
    init_db()
    print("\n" + "="*50)
    print(" QuizMaster Pro is running!")
    print(" Open: http://127.0.0.1:5000")
    print(" Interview Prep: http://127.0.0.1:5000/interview")
    print("="*50 + "\n")

    app.run(host="0.0.0.0", port=10000)