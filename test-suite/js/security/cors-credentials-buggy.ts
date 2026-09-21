import cors from "cors";
import express from "express";

type ResponseLike = {
  setHeader(name: string, value: string | boolean): void;
  header(name: string, value: string | boolean | undefined): void;
};

type RequestLike = {
  headers: {
    origin?: string;
  };
};

const app = express();

app.use(
  cors({
    origin: "*",
    credentials: true,
  }),
);

app.use(
  cors({
    origin: true,
    credentials: true,
  }),
);

export function allowAllCredentialedResponses(res: ResponseLike): void {
  res.setHeader("Access-Control-Allow-Origin", "*");
  res.setHeader("Access-Control-Allow-Credentials", "true");
}

export function reflectAnyOrigin(req: RequestLike, res: ResponseLike): void {
  res.header("Access-Control-Allow-Origin", req.headers.origin);
  res.header("Access-Control-Allow-Credentials", "true");
}
