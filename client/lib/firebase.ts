import { initializeApp } from "firebase/app";
import {
  getAuth,
  GoogleAuthProvider,
  signInWithPopup,
  signOut,
  Auth,
  User,
} from "firebase/auth";

// Firebase config from environment variables (Vite client-side)
const firebaseConfig = {
  apiKey: import.meta.env.VITE_FIREBASE_API_KEY,
  authDomain: import.meta.env.VITE_FIREBASE_AUTH_DOMAIN,
  projectId: import.meta.env.VITE_FIREBASE_PROJECT_ID,
  storageBucket: import.meta.env.VITE_FIREBASE_STORAGE_BUCKET,
  messagingSenderId: import.meta.env.VITE_FIREBASE_MESSAGING_SENDER_ID,
  appId: import.meta.env.VITE_FIREBASE_APP_ID,
};

// Check if Firebase config is valid
const isFirebaseConfigValid = Object.values(firebaseConfig).every(
  (val) => val && val !== undefined && val !== "",
);

let auth: Auth | null = null;
let googleProvider: GoogleAuthProvider | null = null;

if (isFirebaseConfigValid) {
  try {
    const app = initializeApp(firebaseConfig);
    auth = getAuth(app);

    googleProvider = new GoogleAuthProvider();
    googleProvider.addScope("profile");
    googleProvider.addScope("email");
  } catch (error) {
    console.error("Firebase initialization error:", error);
    auth = null;
    googleProvider = null;
  }
} else {
  console.warn(
    "Firebase configuration is incomplete. Some features will be disabled. Please set all VITE_FIREBASE_* environment variables.",
  );
}

// Authorized email domains/accounts
const AUTHORIZED_EMAILS = import.meta.env.VITE_AUTHORIZED_EMAILS
  ? import.meta.env.VITE_AUTHORIZED_EMAILS.split(",").map((email) =>
      email.trim().toLowerCase(),
    )
  : [];

/**
 * Sign in with Google and create server session
 * Returns user data if successful, throws error if email is not authorized
 */
export const signInWithGoogle = async (): Promise<User> => {
  if (!auth || !googleProvider) {
    throw new Error(
      "Firebase authentication is not configured. Please set up Firebase environment variables.",
    );
  }

  try {
    const result = await signInWithPopup(auth, googleProvider);
    const user = result.user;

    // Validate that user email is authorized
    if (user.email) {
      const isAuthorized = isEmailAuthorized(user.email);
      if (!isAuthorized) {
        await signOut(auth);
        throw new Error(
          "Your email is not authorized to access the admin panel. Please contact the administrator.",
        );
      }
    } else {
      await signOut(auth);
      throw new Error("Unable to retrieve email from Google account.");
    }

    // Create server session with the ID token
    const idToken = await user.getIdToken();
    await createServerSession(idToken);

    return user;
  } catch (error) {
    console.error("Google sign-in error:", error);
    throw error;
  }
};

/**
 * Create a server session by sending the Firebase ID token to backend
 * Backend will set httpOnly cookie with session ID
 */
export const createServerSession = async (idToken: string): Promise<void> => {
  try {
    const response = await fetch("/api/auth/login", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
      },
      credentials: "include", // Important: Include cookies in request
      body: JSON.stringify({ idToken }),
    });

    if (!response.ok) {
      const data = await response.json();
      throw new Error(data.error || "Failed to create session");
    }

    console.log("✅ Server session created successfully");
  } catch (error) {
    console.error("Failed to create server session:", error);
    throw error;
  }
};

/**
 * Sign out the current user and clear server session
 */
export const signOutUser = async (): Promise<void> => {
  if (!auth) {
    throw new Error("Firebase authentication is not configured.");
  }

  try {
    // Clear server session first
    await fetch("/api/auth/logout", {
      method: "POST",
      credentials: "include",
    }).catch((error) => {
      console.error("Failed to clear server session:", error);
      // Continue with local logout even if server call fails
    });

    // Then sign out from Firebase
    await signOut(auth);
  } catch (error) {
    console.error("Sign out error:", error);
    throw error;
  }
};

/**
 * Check if an email is authorized
 */
export const isEmailAuthorized = (email: string): boolean => {
  const lowerEmail = email.toLowerCase();

  if (AUTHORIZED_EMAILS.length === 0) {
    console.warn("No authorized emails configured");
    return false;
  }

  return AUTHORIZED_EMAILS.some((authorizedEmail) => {
    // Support both specific emails and domain wildcards (e.g., "@company.com")
    if (authorizedEmail.startsWith("@")) {
      return lowerEmail.endsWith(authorizedEmail);
    }
    return lowerEmail === authorizedEmail;
  });
};

/**
 * Get Firebase ID token for backend verification
 */
export const getIdToken = async (): Promise<string | null> => {
  if (!auth) {
    console.warn("Firebase authentication is not configured.");
    return null;
  }

  try {
    const user = auth.currentUser;
    if (!user) return null;
    return await user.getIdToken();
  } catch (error) {
    console.error("Error getting ID token:", error);
    return null;
  }
};

/**
 * Export auth instance (may be null if Firebase is not configured)
 */
export { auth };
