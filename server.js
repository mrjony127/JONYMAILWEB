
const express = require("express");
const cors = require("cors");
const crypto = require("crypto");
const admin = require("firebase-admin");
const { google } = require("googleapis");

const app = express();

app.use(express.json());

app.use(cors({
  origin: [
    "https://mrjony127.github.io",
    "http://localhost:3000"
  ],
  methods: ["GET", "POST", "DELETE", "OPTIONS"],
  allowedHeaders: ["Content-Type", "Authorization"]
}));

const PORT = process.env.PORT || 3000;

const {
  FIREBASE_PROJECT_ID,
  FIREBASE_CLIENT_EMAIL,
  FIREBASE_PRIVATE_KEY,
  GOOGLE_CLIENT_ID,
  GOOGLE_CLIENT_SECRET,
  GOOGLE_REDIRECT_URI,
  TOKEN_ENCRYPTION_KEY,
  STATE_SECRET,
  FRONTEND_URL
} = process.env;

const frontend = FRONTEND_URL ||
  "https://mrjony127.github.io/JONYMAILWEB/";

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
} catch (error) {
  console.error("Firebase initialization failed:", error.message);
}

const oauthClient = new google.auth.OAuth2(
  GOOGLE_CLIENT_ID,
  GOOGLE_CLIENT_SECRET,
  GOOGLE_REDIRECT_URI
);

const SCOPES = [
  "openid",
  "email",
  "https://www.googleapis.com/auth/gmail.readonly"
];

// Health check
app.get("/api/health", (req, res) => {
  res.json({
    project: "JONY MAIL",
    backend: "online",
    firebase: db ? "connected" : "not configured",
    status: db ? "success" : "configuration required"
  });
});

// Firebase authentication
async function requireAuth(req, res, next) {
  try {
    const header = req.headers.authorization || "";

    if (!header.startsWith("Bearer ")) {
      return res.status(401).json({
        success: false,
        message: "Login required"
      });
    }

    const token = header.substring(7);
    req.user = await admin.auth().verifyIdToken(token);

    next();
  } catch (error) {
    res.status(401).json({
      success: false,
      message: "Invalid Firebase login"
    });
  }
}

// Encryption
function getEncryptionKey() {
  if (!TOKEN_ENCRYPTION_KEY ||
      !/^[a-f0-9]{64}$/i.test(TOKEN_ENCRYPTION_KEY)) {
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

// OAuth state
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

  if (parts.length !== 2) {
    throw new Error("Invalid OAuth state");
  }

  const [payload, signature] = parts;

  const expected = crypto
    .createHmac("sha256", STATE_SECRET)
    .update(payload)
    .digest("hex");

  const a = Buffer.from(signature, "hex");
  const b = Buffer.from(expected, "hex");

  if (a.length !== b.length ||
      !crypto.timingSafeEqual(a, b)) {
    throw new Error("Invalid OAuth signature");
  }

  const data = JSON.parse(
    Buffer.from(payload, "base64url").toString("utf8")
  );

  if (!data.uid ||
      Date.now() - data.time > 10 * 60 * 1000) {
    throw new Error("OAuth state expired");
  }

  return data.uid;
}

// Connect Gmail
app.get("/api/gmail/connect", requireAuth, (req, res) => {
  try {
    const url = oauthClient.generateAuthUrl({
      access_type: "offline",
      prompt: "consent",
      include_granted_scopes: true,
      scope: SCOPES,
      state: makeState(req.user.uid)
    });

    res.redirect(url);
  } catch (error) {
    res.status(500).json({
      success: false,
      message: error.message
    });
  }
});

// Google callback
app.get("/api/gmail/callback", async (req, res) => {
  try {
    if (req.query.error) {
      return res.redirect(
        frontend + "?gmail_error=" +
        encodeURIComponent(req.query.error)
      );
    }

    const uid = readState(req.query.state);

    const { tokens } = await oauthClient.getToken(req.query.code);

    oauthClient.setCredentials(tokens);

    const oauth2 = google.oauth2({
      auth: oauthClient,
      version: "v2"
    });

    const profile = await oauth2.userinfo.get();
    const email = profile.data.email;

    if (!email) throw new Error("Google email missing");

    const id = Buffer
      .from(email.toLowerCase())
      .toString("base64url");

    const ref = db.collection("users")
      .doc(uid)
      .collection("gmailAccounts")
      .doc(id);

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

    res.redirect(frontend + "?gmail_connected=1");

  } catch (error) {
    console.error("Google callback:", error.message);

    res.redirect(frontend + "?gmail_error=connection_failed");
  }
});

// Get connected accounts
app.get("/api/gmail/accounts", requireAuth, async (req, res) => {
  try {
    const snapshot = await db.collection("users")
      .doc(req.user.uid)
      .collection("gmailAccounts")
      .where("connected", "==", true)
      .get();

    const accounts = snapshot.docs.map(doc => ({
      id: doc.id,
      email: doc.data().email
    }));

    res.json({ success: true, accounts });

  } catch (error) {
    res.status(500).json({
      success: false,
      message: "Accounts could not load"
    });
  }
});

// Gmail API client
async function getGmail(uid, accountId) {
  const ref = db.collection("users")
    .doc(uid)
    .collection("gmailAccounts")
    .doc(accountId);

  const snap = await ref.get();

  if (!snap.exists || !snap.data().connected) {
    throw new Error("Account not found");
  }

  const refreshToken = decryptToken(
    snap.data().refreshToken
  );

  const auth = new google.auth.OAuth2(
    GOOGLE_CLIENT_ID,
    GOOGLE_CLIENT_SECRET,
    GOOGLE_REDIRECT_URI
  );

  auth.setCredentials({
    refresh_token: refreshToken
  });

  return google.gmail({
    version: "v1",
    auth
  });
}

// Inbox messages
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
      Math.max(Number(req.query.maxResults) || 20, 1),
      50
    );

    const gmail = await getGmail(req.user.uid, accountId);

    const result = await gmail.users.messages.list({
      userId: "me",
      labelIds: ["INBOX"],
      maxResults
    });

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
          subject: get("Subject"),
          date: get("Date"),
          snippet: response.data.snippet || "",
          unread: (response.data.labelIds || []).includes("UNREAD")
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
      message: "Inbox could not load"
    });
  }
});

// Single message
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

      if (part.body?.data) {
        return Buffer.from(
          part.body.data,
          "base64url"
        ).toString("utf8");
      }

      return (part.parts || []).map(decode).join("\n");
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
    res.status(500).json({
      success: false,
      message: "Message could not load"
    });
  }
});

// Disconnect account
app.delete("/api/gmail/accounts/:id", requireAuth, async (req, res) => {
  try {
    await db.collection("users")
      .doc(req.user.uid)
      .collection("gmailAccounts")
      .doc(req.params.id)
      .delete();

    res.json({
      success: true,
      message: "Gmail disconnected"
    });

  } catch (error) {
    res.status(500).json({
      success: false,
      message: "Disconnect failed"
    });
  }
});

// Start server
app.listen(PORT, "0.0.0.0", () => {
  console.log("JONY MAIL Backend running on port " + PORT);
});
