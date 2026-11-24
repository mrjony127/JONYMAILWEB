
const express = require("express");
const cors = require("cors");
const crypto = require("crypto");
const admin = require("firebase-admin");
const { google } = require("googleapis");

const app = express();
app.use(express.json());

const PORT = process.env.PORT || 3000;
const FRONTEND_URL =
  process.env.FRONTEND_URL ||
  "https://mrjony127.github.io/JONYMAILWEB/";

const ALLOWED_ORIGINS = [
  "https://mrjony127.github.io",
  "http://localhost:3000"
];

app.use(cors({
  origin(origin, callback) {
    if (!origin || ALLOWED_ORIGINS.includes(origin)) {
      return callback(null, true);
    }
    callback(new Error("Origin not allowed"));
  },
  methods: ["GET", "POST", "DELETE", "OPTIONS"],
  allowedHeaders: ["Content-Type", "Authorization"]
}));

const {
  FIREBASE_PROJECT_ID,
  FIREBASE_CLIENT_EMAIL,
  FIREBASE_PRIVATE_KEY,
  GOOGLE_CLIENT_ID,
  GOOGLE_CLIENT_SECRET,
  GOOGLE_REDIRECT_URI,
  TOKEN_ENCRYPTION_KEY,
  STATE_SECRET
} = process.env;

let db;

try {
  if (!admin.apps.length) {
    admin.initializeApp({
      credential: admin.credential.cert({
        projectId: FIREBASE_PROJECT_ID,
        clientEmail: FIREBASE_CLIENT_EMAIL,
        privateKey: (FIREBASE_PRIVATE_KEY || "").replace(/\\n/g, "\n")
      })
    });
  }
  db = admin.firestore();
  console.log("Firebase connected");
} catch (error) {
  console.error("Firebase initialization failed:", error.message);
}

const SCOPES = [
  "openid",
  "email",
  "https://www.googleapis.com/auth/gmail.readonly"
];

function newOAuthClient() {
  return new google.auth.OAuth2(
    GOOGLE_CLIENT_ID,
    GOOGLE_CLIENT_SECRET,
    GOOGLE_REDIRECT_URI
  );
}

function getEncryptionKey() {
  if (!/^[a-f0-9]{64}$/i.test(TOKEN_ENCRYPTION_KEY || "")) {
    throw new Error("Invalid TOKEN_ENCRYPTION_KEY");
  }
  return Buffer.from(TOKEN_ENCRYPTION_KEY, "hex");
}

function encryptToken(token) {
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv(
    "aes-256-gcm",
    getEncryptionKey(),
    iv
  );
  const data = Buffer.concat([
    cipher.update(token, "utf8"),
    cipher.final()
  ]);

  return {
    iv: iv.toString("hex"),
    data: data.toString("hex"),
    tag: cipher.getAuthTag().toString("hex")
  };
}

function decryptToken(value) {
  const decipher = crypto.createDecipheriv(
    "aes-256-gcm",
    getEncryptionKey(),
    Buffer.from(value.iv, "hex")
  );
  decipher.setAuthTag(Buffer.from(value.tag, "hex"));

  return Buffer.concat([
    decipher.update(Buffer.from(value.data, "hex")),
    decipher.final()
  ]).toString("utf8");
}

function makeState(uid) {
  if (!STATE_SECRET) throw new Error("STATE_SECRET missing");

  const payload = Buffer.from(JSON.stringify({
    uid,
    time: Date.now(),
    nonce: crypto.randomBytes(16).toString("hex")
  })).toString("base64url");

  const signature = crypto
    .createHmac("sha256", STATE_SECRET)
    .update(payload)
    .digest("hex");

  return payload + "." + signature;
}

function readState(state) {
  const parts = String(state || "").split(".");
  if (parts.length !== 2) throw new Error("Invalid OAuth state");

  const [payload, signature] = parts;
  const expected = crypto
    .createHmac("sha256", STATE_SECRET)
    .update(payload)
    .digest("hex");

  const a = Buffer.from(signature, "hex");
  const b = Buffer.from(expected, "hex");

  if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) {
    throw new Error("Invalid OAuth signature");
  }

  const data = JSON.parse(
    Buffer.from(payload, "base64url").toString("utf8")
  );

  if (
    !data.uid ||
    !Number.isFinite(data.time) ||
    Date.now() - data.time > 10 * 60 * 1000 ||
    data.time > Date.now() + 60 * 1000
  ) {
    throw new Error("OAuth state expired");
  }

  return data.uid;
}

async function requireAuth(req, res, next) {
  try {
    if (!db) {
      return res.status(503).json({
        success: false,
        message: "Firebase is not configured"
      });
    }

    const header = req.headers.authorization || "";
    if (!header.startsWith("Bearer ")) {
      return res.status(401).json({
        success: false,
        message: "Login required"
      });
    }

    req.user = await admin.auth().verifyIdToken(header.substring(7));
    next();
  } catch (error) {
    res.status(401).json({
      success: false,
      message: "Invalid or expired login. Please sign in again."
    });
  }
}

function accountCollection(uid) {
  return db.collection("users")
    .doc(uid)
    .collection("gmailAccounts");
}

app.get("/api/health", (req, res) => {
  res.json({
    project: "JONY MAIL",
    backend: "online",
    firebase: db ? "connected" : "not configured",
    status: db ? "success" : "configuration required"
  });
});

// Start Gmail OAuth connection
app.post("/api/gmail/connect", requireAuth, async (req, res) => {
  try {
    const snapshot = await accountCollection(req.user.uid)
      .where("connected", "==", true)
      .get();

    if (snapshot.size >= 20) {
      return res.status(400).json({
        success: false,
        message: "Maximum 20 Gmail accounts allowed"
      });
    }

    const oauth = newOAuthClient();
    const authUrl = oauth.generateAuthUrl({
      access_type: "offline",
      prompt: "consent",
      include_granted_scopes: true,
      scope: SCOPES,
      state: makeState(req.user.uid)
    });

    res.json({ success: true, authUrl });
  } catch (error) {
    console.error("Connect error:", error.message);
    res.status(500).json({
      success: false,
      message: "Could not start Gmail connection"
    });
  }
});

// Google OAuth callback
app.get("/api/gmail/callback", async (req, res) => {
  try {
    if (req.query.error) {
      return res.redirect(
        FRONTEND_URL + "?gmail_error=" +
        encodeURIComponent(req.query.error)
      );
    }

    const uid = readState(req.query.state);
    const oauth = newOAuthClient();

    const { tokens } = await oauth.getToken(req.query.code);
    oauth.setCredentials(tokens);

    const oauth2 = google.oauth2({
      auth: oauth,
      version: "v2"
    });

    const profile = await oauth2.userinfo.get();
    const email = profile.data.email;

    if (!email) throw new Error("Google email missing");

    const id = Buffer
      .from(email.toLowerCase())
      .toString("base64url");

    const ref = accountCollection(uid).doc(id);
    const old = await ref.get();

    let refreshToken = old.exists
      ? old.data().refreshToken
      : null;

    if (tokens.refresh_token) {
      refreshToken = encryptToken(tokens.refresh_token);
    }

    if (!refreshToken) {
      throw new Error("Refresh token unavailable");
    }

    await ref.set({
      email,
      refreshToken,
      connected: true,
      updatedAt: admin.firestore.FieldValue.serverTimestamp()
    }, { merge: true });

    res.redirect(FRONTEND_URL + "?gmail_connected=1");
  } catch (error) {
    console.error("Google callback error:", error.message);
    res.redirect(FRONTEND_URL + "?gmail_error=connection_failed");
  }
});

// List saved Gmail accounts
app.get("/api/gmail/accounts", requireAuth, async (req, res) => {
  try {
    const snapshot = await accountCollection(req.user.uid)
      .where("connected", "==", true)
      .get();

    const accounts = snapshot.docs.map(doc => ({
      id: doc.id,
      email: doc.data().email
    }));

    res.json({ success: true, accounts });
  } catch (error) {
    console.error("Accounts error:", error.message);
    res.status(500).json({
      success: false,
      message: "Accounts could not load"
    });
  }
});

// Create authenticated Gmail API client
async function getGmail(uid, accountId) {
  const snap = await accountCollection(uid).doc(accountId).get();

  if (!snap.exists || !snap.data().connected) {
    throw new Error("Account not found");
  }

  const refreshToken = decryptToken(snap.data().refreshToken);
  const auth = newOAuthClient();

  auth.setCredentials({ refresh_token: refreshToken });

  return google.gmail({ version: "v1", auth });
}

// List inbox messages for one account
app.get("/api/gmail/messages", requireAuth, async (req, res) => {
  try {
    const accountId = String(req.query.accountId || "");
    if (!accountId) {
      return res.status(400).json({
        success: false,
        message: "accountId required"
      });
    }

    const maxResults = Math.min(
      Math.max(Number(req.query.maxResults) || 30, 1),
      50
    );

    const gmail = await getGmail(req.user.uid, accountId);

    const params = {
      userId: "me",
      labelIds: ["INBOX"],
      maxResults
    };

    if (req.query.pageToken) {
      params.pageToken = String(req.query.pageToken);
    }

    const result = await gmail.users.messages.list(params);

    const messages = await Promise.all(
      (result.data.messages || []).map(async item => {
        const response = await gmail.users.messages.get({
          userId: "me",
          id: item.id,
          format: "metadata",
          metadataHeaders: ["From", "To", "Subject", "Date"]
        });

        const headers = response.data.payload?.headers || [];
        const get = name =>
          headers.find(h =>
            h.name.toLowerCase() === name.toLowerCase()
          )?.value || "";

        return {
          id: item.id,
          threadId: item.threadId,
          from: get("From"),
          to: get("To"),
          subject: get("Subject") || "(No subject)",
          date: get("Date"),
          snippet: response.data.snippet || "",
          unread: (response.data.labelIds || []).includes("UNREAD"),
          accountId,
          email: (await accountCollection(req.user.uid)
            .doc(accountId).get()).data()?.email || ""
        };
      })
    );

    res.json({
      success: true,
      messages,
      nextPageToken: result.data.nextPageToken || null
    });
  } catch (error) {
    console.error("Inbox error:", error.message);
    res.status(500).json({
      success: false,
      message: "Inbox could not load. Reconnect the Gmail account if needed."
    });
  }
});

// Read one email
app.get("/api/gmail/message", requireAuth, async (req, res) => {
  try {
    const accountId = String(req.query.accountId || "");
    const id = String(req.query.id || "");

    if (!accountId || !id) {
      return res.status(400).json({
        success: false,
        message: "accountId and id required"
      });
    }

    const gmail = await getGmail(req.user.uid, accountId);
    const result = await gmail.users.messages.get({
      userId: "me",
      id,
      format: "full"
    });

    const headers = result.data.payload?.headers || [];
    const get = name =>
      headers.find(h =>
        h.name.toLowerCase() === name.toLowerCase()
      )?.value || "";

    function decode(part) {
      if (!part) return "";

      if (part.mimeType === "text/plain" && part.body?.data) {
        return Buffer.from(part.body.data, "base64url").toString("utf8");
      }

      for (const child of (part.parts || [])) {
        const body = decode(child);
        if (body) return body;
      }

      if (part.body?.data && !part.mimeType?.includes("html")) {
        return Buffer.from(part.body.data, "base64url").toString("utf8");
      }

      return "";
    }

    res.json({
      success: true,
      message: {
        id,
        from: get("From"),
        to: get("To"),
        subject: get("Subject"),
        date: get("Date"),
        snippet: result.data.snippet || "",
        body: decode(result.data.payload)
      }
    });
  } catch (error) {
    console.error("Read message error:", error.message);
    res.status(500).json({
      success: false,
      message: "Message could not load"
    });
  }
});

// Disconnect Gmail account
app.delete("/api/gmail/accounts/:id", requireAuth, async (req, res) => {
  try {
    await accountCollection(req.user.uid).doc(req.params.id).delete();
    res.json({ success: true, message: "Gmail disconnected" });
  } catch (error) {
    console.error("Disconnect error:", error.message);
    res.status(500).json({
      success: false,
      message: "Disconnect failed"
    });
  }
});

app.listen(PORT, "0.0.0.0", () => {
  console.log("JONY MAIL Backend running on port " + PORT);
});
