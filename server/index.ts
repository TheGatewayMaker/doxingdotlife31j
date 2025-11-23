import "dotenv/config";
import express from "express";
import cors from "cors";
import multer from "multer";
import { handleDemo } from "./routes/demo";
import { handleUpload } from "./routes/upload";
import { handleGetPosts } from "./routes/posts";
import { handleGetServers } from "./routes/servers";
import { handleMediaProxy } from "./routes/media";

const upload = multer({
  storage: multer.memoryStorage(),
  limits: {
    fileSize: 100 * 1024 * 1024,
  },
});

export function createServer() {
  const app = express();

  // Middleware
  app.use(cors());
  app.use(express.json());
  app.use(express.urlencoded({ extended: true }));

  // Example API routes
  app.get("/api/ping", (_req, res) => {
    const ping = process.env.PING_MESSAGE ?? "ping";
    res.json({ message: ping });
  });

  app.get("/api/demo", handleDemo);

  // Debug endpoint to check environment variables
  app.get("/api/debug/env", (_req, res) => {
    const r2Keys = Object.keys(process.env).filter((k) => k.startsWith("R2_"));
    const r2Values: Record<string, string | undefined> = {};
    r2Keys.forEach((key) => {
      r2Values[key] = process.env[key] ? "SET" : "MISSING";
    });
    res.json({
      r2_configured: r2Keys.length === 4,
      r2_variables: r2Values,
      all_r2_keys: r2Keys,
    });
  });

  // Forum API routes
  app.post(
    "/api/upload",
    upload.fields([
      { name: "media", maxCount: 1 },
      { name: "thumbnail", maxCount: 1 },
    ]),
    handleUpload,
  );
  app.get("/api/posts", handleGetPosts);
  app.get("/api/servers", handleGetServers);
  app.get("/api/media", handleMediaProxy);

  return app;
}
