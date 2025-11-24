import { RequestHandler } from "express";
import { randomBytes, createHash, timingSafeEqual } from "crypto";

interface AuthRequest {
  username: string;
  password: string;
}

interface AuthSession {
  token: string;
  createdAt: number;
  expiresAt: number;
  username: string;
}

// In-memory session store with better management
const sessions: Map<string, AuthSession> = new Map();
const failedAttempts: Map<string, { count: number; resetTime: number }> =
  new Map();

// Token validity: 24 hours
const TOKEN_EXPIRY_MS = 24 * 60 * 60 * 1000;
const MAX_FAILED_ATTEMPTS = 5;
const LOCKOUT_DURATION_MS = 15 * 60 * 1000; // 15 minutes

// Hash credentials using SHA-256 for constant-time comparison
const hashCredential = (value: string): string => {
  return createHash("sha256").update(value).digest("hex");
};

// Generate a cryptographically secure random token
const generateToken = (): string => {
  return randomBytes(32).toString("hex");
};

// Validate request body structure and types
const validateAuthRequest = (
  body: any,
): { username: string; password: string } | null => {
  // Ensure body exists and is an object
  if (!body || typeof body !== "object") {
    console.error("Auth request body is not an object:", typeof body);
    return null;
  }

  // Extract and validate username
  const username = body.username;
  if (typeof username !== "string" || !username) {
    console.error("Invalid username in request body:", typeof username);
    return null;
  }

  // Extract and validate password
  const password = body.password;
  if (typeof password !== "string" || !password) {
    console.error("Invalid password in request body:", typeof password);
    return null;
  }

  return { username: username.trim(), password };
};

// Constant-time comparison to prevent timing attacks
const safeCompare = (provided: string, stored: string): boolean => {
  try {
    return timingSafeEqual(Buffer.from(provided), Buffer.from(stored));
  } catch {
    return false;
  }
};

// Check and enforce rate limiting
const checkRateLimit = (identifier: string): boolean => {
  const now = Date.now();
  const attempt = failedAttempts.get(identifier);

  if (!attempt) {
    return true; // No previous attempts
  }

  // Reset counter if lockout period has expired
  if (now >= attempt.resetTime) {
    failedAttempts.delete(identifier);
    return true;
  }

  // Still in lockout period
  return attempt.count < MAX_FAILED_ATTEMPTS;
};

// Record a failed login attempt
const recordFailedAttempt = (identifier: string): void => {
  const now = Date.now();
  const attempt = failedAttempts.get(identifier) || {
    count: 0,
    resetTime: now + LOCKOUT_DURATION_MS,
  };

  attempt.count++;
  failedAttempts.set(identifier, attempt);

  if (attempt.count >= MAX_FAILED_ATTEMPTS) {
    console.warn(`Rate limit exceeded for identifier: ${identifier}`);
  }
};

// Reset rate limit on successful login
const resetRateLimit = (identifier: string): void => {
  failedAttempts.delete(identifier);
};

export const handleLogin: RequestHandler = async (req, res) => {
  const clientIp =
    (req.headers["x-forwarded-for"] as string)?.split(",")[0] ||
    req.socket.remoteAddress ||
    "unknown";

  try {
    // Validate request body
    const credentials = validateAuthRequest(req.body);
    if (!credentials) {
      console.warn(`Invalid request body from ${clientIp}`);
      res.status(400).json({ error: "Invalid request format" });
      return;
    }

    const { username, password } = credentials;

    // Check rate limit
    if (!checkRateLimit(clientIp)) {
      console.warn(`Rate limit exceeded for ${clientIp}`);
      res.status(429).json({
        error: "Too many login attempts. Please try again in 15 minutes.",
      });
      return;
    }

    // Get credentials from environment variables
    const validUsername = process.env.ADMIN_USERNAME;
    const validPassword = process.env.ADMIN_PASSWORD;

    // Validate that credentials are configured
    if (!validUsername || !validPassword) {
      console.error(
        "🔴 CRITICAL: Admin credentials not configured in environment variables!",
      );
      console.error(
        "Please ensure ADMIN_USERNAME and ADMIN_PASSWORD are set in your environment.",
      );
      res.status(500).json({
        error: "Server configuration error. Please contact the administrator.",
      });
      return;
    }

    // Verify credentials using constant-time comparison
    const providedUsernameHash = hashCredential(username);
    const storedUsernameHash = hashCredential(validUsername);
    const providedPasswordHash = hashCredential(password);
    const storedPasswordHash = hashCredential(validPassword);

    const usernameMatch = safeCompare(providedUsernameHash, storedUsernameHash);
    const passwordMatch = safeCompare(providedPasswordHash, storedPasswordHash);

    if (!usernameMatch || !passwordMatch) {
      recordFailedAttempt(clientIp);
      console.warn(
        `Failed login attempt from ${clientIp} with username: ${username}`,
      );
      res.status(401).json({ error: "Invalid username or password" });
      return;
    }

    // Credentials are valid - reset rate limit
    resetRateLimit(clientIp);

    // Generate secure session token
    const token = generateToken();
    const now = Date.now();
    const session: AuthSession = {
      token,
      createdAt: now,
      expiresAt: now + TOKEN_EXPIRY_MS,
      username: validUsername,
    };

    sessions.set(token, session);
    console.info(
      `✓ Successful login from ${clientIp} for user: ${validUsername}`,
    );

    // Clean up expired sessions
    const expiredTokens: string[] = [];
    for (const [key, value] of sessions.entries()) {
      if (value.expiresAt < now) {
        expiredTokens.push(key);
      }
    }
    expiredTokens.forEach((key) => sessions.delete(key));

    res.json({
      success: true,
      message: "Login successful",
      token,
      expiresIn: TOKEN_EXPIRY_MS,
      username: validUsername,
    });
  } catch (error) {
    console.error("🔴 Login error:", error);
    res
      .status(500)
      .json({ error: "An unexpected error occurred. Please try again." });
  }
};

export const handleLogout: RequestHandler = async (req, res) => {
  try {
    const token = req.headers.authorization?.replace("Bearer ", "");

    if (token) {
      const session = sessions.get(token);
      if (session) {
        sessions.delete(token);
        console.info(`✓ Logout successful for user: ${session.username}`);
      }
    }

    res.json({
      success: true,
      message: "Logout successful",
    });
  } catch (error) {
    console.error("Logout error:", error);
    res.status(500).json({ error: "Logout failed" });
  }
};

export const handleCheckAuth: RequestHandler = async (req, res) => {
  try {
    const token = req.headers.authorization?.replace("Bearer ", "");

    if (!token) {
      res
        .status(401)
        .json({ authenticated: false, message: "No token provided" });
      return;
    }

    const session = sessions.get(token);
    const now = Date.now();

    if (!session || session.expiresAt < now) {
      if (session) {
        sessions.delete(token);
      }
      res
        .status(401)
        .json({ authenticated: false, message: "Token expired or invalid" });
      return;
    }

    res.json({
      authenticated: true,
      message: "Token is valid",
      expiresAt: session.expiresAt,
      username: session.username,
    });
  } catch (error) {
    console.error("Auth check error:", error);
    res.status(500).json({ error: "Auth check failed" });
  }
};

// Middleware to verify authentication
export const authMiddleware: (req: any, res: any, next: any) => void = (
  req,
  res,
  next,
) => {
  try {
    const authHeader = req.headers.authorization;
    if (!authHeader || !authHeader.startsWith("Bearer ")) {
      res.status(401).json({ error: "No authentication token provided" });
      return;
    }

    const token = authHeader.substring(7); // Remove "Bearer " prefix
    const session = sessions.get(token);
    const now = Date.now();

    if (!session || session.expiresAt < now) {
      if (session) {
        sessions.delete(token);
      }
      res.status(401).json({ error: "Token expired or invalid" });
      return;
    }

    // Attach user info to request for downstream handlers
    req.user = { username: session.username, token };
    next();
  } catch (error) {
    console.error("Auth middleware error:", error);
    res.status(500).json({ error: "Authentication failed" });
  }
};
