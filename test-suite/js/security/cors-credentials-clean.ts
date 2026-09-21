import cors from "cors";
import express from "express";

type ResponseLike = {
  setHeader(name: string, value: string | boolean): void;
};

const app = express();
const TRUSTED_ORIGIN = "https://app.example.com";
const allowedOrigins = new Set([TRUSTED_ORIGIN, "https://admin.example.com"]);

app.use(
  cors({
    origin: [TRUSTED_ORIGIN, "https://admin.example.com"],
    credentials: true,
  }),
);

app.use(
  cors({
    origin(origin, callback) {
      if (!origin || allowedOrigins.has(origin)) {
        callback(null, origin);
        return;
      }
      callback(new Error("origin is not allowed"));
    },
    credentials: true,
  }),
);

export function trustedCredentialedResponse(res: ResponseLike): void {
  res.setHeader("Access-Control-Allow-Origin", TRUSTED_ORIGIN);
  res.setHeader("Access-Control-Allow-Credentials", "true");
  res.setHeader("Vary", "Origin");
}
