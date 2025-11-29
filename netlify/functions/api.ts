import serverless from "serverless-http";
import { createServer } from "../../server";

let app: any;
let serverlessHandler: any;

const getApp = () => {
  if (!app) {
    try {
      app = createServer();
    } catch (error) {
      console.error("Failed to create server:", error);
      throw error;
    }
  }
  return app;
};

const getServerlessHandler = () => {
  if (!serverlessHandler) {
    const app = getApp();
    serverlessHandler = serverless(app, {
      basePath: "/.netlify/functions/api",
      binary: [
        "image/*",
        "video/*",
        "application/octet-stream",
        "multipart/form-data",
        "*/*",
      ],
      request: (request: any, event: any, context: any) => {
        // Log request details for debugging
        console.log(`[${new Date().toISOString()}] ${event.httpMethod} ${event.path}`);
      },
    });
  }
  return serverlessHandler;
};

export const handler = async (event: any, context: any) => {
  try {
    // Set a longer timeout for the context
    context.callbackWaitsForEmptyEventLoop = false;

    const handler = getServerlessHandler();
    const result = await handler(event, context);

    return result;
  } catch (error) {
    console.error("Handler error:", error);
    console.error("Error details:", {
      message: error instanceof Error ? error.message : String(error),
      stack: error instanceof Error ? error.stack : undefined,
    });

    return {
      statusCode: 500,
      body: JSON.stringify({
        error: "Internal server error",
        details:
          process.env.NODE_ENV === "development"
            ? error instanceof Error
              ? error.message
              : String(error)
            : undefined,
      }),
      headers: {
        "Content-Type": "application/json",
        "Cache-Control": "no-cache, no-store, must-revalidate",
      },
    };
  }
};
