// Deliberately vulnerable JavaScript file for testing Anty
// DO NOT use any of this code in production!

const AWS_KEY = "AKIAIOSFODNN7EXAMPLE";
const AWS_SECRET = process.env.AWS_SECRET; // This one is fine

// Bad: hardcoded database password
const DB_PASSWORD = "super_secret_password_123!";

// Bad: database connection string with credentials
const mongoUrl = "mongodb://admin:p4ssw0rd@db.example.com:27017/myapp";

// Bad: GitHub token
const token = "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij";

// Bad: Stripe key
const stripeKey = "sk_live_abc123def456ghi789jkl012mno";

// Bad: eval usage
function handleUserInput(input) {
    return eval(input);
}

// Bad: SQL injection via string concatenation
function getUser(userId) {
    const query = "SELECT * FROM users WHERE id = " + userId;
    return db.execute(query);
}

// Bad: SQL injection via template literal
function findByEmail(email) {
    return db.query(`SELECT * FROM accounts WHERE email = '${email}'`);
}

// Bad: innerHTML
function renderContent(html) {
    document.getElementById("output").innerHTML = html;
}

// Bad: dangerouslySetInnerHTML
function RawHtml({ content }) {
    return <div dangerouslySetInnerHTML={{ __html: content }} />;
}

// Bad: MD5 usage
const crypto = require('crypto');
const hash = crypto.createHash('md5').update(data).digest('hex');

// Bad: CORS wildcard
app.use(cors({ origin: '*' }));

// Bad: Debug mode
const config = { DEBUG: true, port: 3000 };

// Bad: SSL verification disabled
const agent = new https.Agent({ rejectUnauthorized: false });

// Bad: hardcoded JWT secret
const JWT_SECRET = "my_super_secret_jwt_key_do_not_share";

// Good: using environment variables (should NOT trigger)
const apiKey = process.env.API_KEY;
const dbUrl = process.env.DATABASE_URL;
