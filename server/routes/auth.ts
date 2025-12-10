import { RequestHandler } from "express";
import { verifyFirebaseToken } from "../utils/firebase-admin";

// Session storage - in production, use Redis or persistent DB
const sessionStore: Map<
  string,
  { email: string; uid: string; createdAt: number }
> = new Map();

// Session cookie name and settings
const SESSION_COOKIE_NAME = "auth_session";
const SESSION_DURATION = 24 * 60 * 60 * 1000; // 24 hours

/**
 * Generate a session ID
 */
const generateSessionId = (): string => {
  return Buffer.from(`${Date.now()}-${Math.random()}`).toString("base64");
};

/**
 * Verify Firebase ID token and create session
 * Called during login flow (POST /api/auth/login)
 */
export const handleLogin: RequestHandler = async (req, res) => {
  try {
    const { idToken } = req.body;

    if (!idToken) {
      res.status(400).json({
        error: "Missing ID token",
      });
      return;
    }

    // Verify Firebase token
    const verifiedToken = await verifyFirebaseToken(idToken);

    if (!verifiedToken.isAuthorized) {
      res.status(403).json({
        error: "Email is not authorized to access this resource",
        email: verifiedToken.email,
      });
      return;
    }

    // Create session
    const sessionId = generateSessionId();
    sessionStore.set(sessionId, {
      email: verifiedToken.email!,
      uid: verifiedToken.uid,
      createdAt: Date.now(),
    });

    // Set httpOnly cookie (cannot be accessed by JavaScript, only sent with requests)
    res.cookie(SESSION_COOKIE_NAME, sessionId, {
      httpOnly: true,
      secure: process.env.NODE_ENV === "production", // Only send over HTTPS in production
      sameSite: "strict", // Prevent CSRF attacks
      maxAge: SESSION_DURATION,
      path: "/", // Available for all routes
    });

    console.log(
      `[${new Date().toISOString()}] ✅ Session created for: ${verifiedToken.email}`,
    );

    res.json({
      success: true,
      message: "Login successful",
      email: verifiedToken.email,
    });
  } catch (error) {
    const errorMsg = error instanceof Error ? error.message : String(error);
    console.error(`[${new Date().toISOString()}] Login error: ${errorMsg}`);
    res.status(401).json({
      error: "Login failed",
      details: process.env.NODE_ENV === "development" ? errorMsg : undefined,
    });
  }
};

/**
 * Check authentication status via session cookie
 */
export const handleCheckAuth: RequestHandler = async (req, res) => {
  try {
    const sessionId = req.cookies[SESSION_COOKIE_NAME];

    if (!sessionId) {
      res.status(401).json({
        authenticated: false,
        message: "No valid session",
      });
      return;
    }

    const session = sessionStore.get(sessionId);

    if (!session) {
      res.status(401).json({
        authenticated: false,
        message: "Session not found or expired",
      });
      return;
    }

    // Check if session has expired
    if (Date.now() - session.createdAt > SESSION_DURATION) {
      sessionStore.delete(sessionId);
      res.clearCookie(SESSION_COOKIE_NAME);
      res.status(401).json({
        authenticated: false,
        message: "Session expired",
      });
      return;
    }

    res.json({
      authenticated: true,
      email: session.email,
      uid: session.uid,
    });
  } catch (error) {
    console.error("Auth check error:", error);
    res.status(500).json({ error: "Auth check failed" });
  }
};

/**
 * Logout endpoint - clears session
 */
export const handleLogout: RequestHandler = async (req, res) => {
  try {
    const sessionId = req.cookies[SESSION_COOKIE_NAME];

    if (sessionId) {
      sessionStore.delete(sessionId);
    }

    res.clearCookie(SESSION_COOKIE_NAME);

    res.json({
      success: true,
      message: "Logout successful",
    });
  } catch (error) {
    console.error("Logout error:", error);
    res.status(500).json({ error: "Logout failed" });
  }
};

/**
 * Auth middleware to protect routes
 * Checks session cookie instead of Authorization header
 */
export const authMiddleware: (
  req: any,
  res: any,
  next: any,
) => Promise<void> = async (req, res, next) => {
  try {
    const sessionId = req.cookies[SESSION_COOKIE_NAME];

    if (!sessionId) {
      console.warn(
        `[${new Date().toISOString()}] Auth attempt without valid session for: ${req.method} ${req.path}`,
      );
      res.status(401).json({
        error: "No authentication session provided",
      });
      return;
    }

    const session = sessionStore.get(sessionId);

    if (!session) {
      console.warn(
        `[${new Date().toISOString()}] Invalid or expired session attempted for: ${req.method} ${req.path}`,
      );
      res.status(401).json({
        error: "Invalid or expired session",
      });
      return;
    }

    // Check if session has expired
    if (Date.now() - session.createdAt > SESSION_DURATION) {
      sessionStore.delete(sessionId);
      res.clearCookie(SESSION_COOKIE_NAME);
      console.warn(
        `[${new Date().toISOString()}] Expired session attempted for: ${session.email}`,
      );
      res.status(401).json({
        error: "Session expired",
      });
      return;
    }

    // Attach user info to request for use in route handlers
    req.user = {
      uid: session.uid,
      email: session.email,
    };

    console.log(
      `[${new Date().toISOString()}] ✅ Authorized access: ${session.email} for ${req.method} ${req.path}`,
    );
    next();
  } catch (error) {
    console.error(
      `[${new Date().toISOString()}] Auth middleware error:`,
      error,
    );
    res.status(500).json({ error: "Authentication failed" });
  }
};
