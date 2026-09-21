import axios from "axios";
import https from "https";
import tls from "tls";

export const unsafeAgent = new https.Agent({
  rejectUnauthorized: false,
});

export const client = axios.create({
  httpsAgent: new https.Agent({
    rejectUnauthorized: false,
  }),
});

export function connectToInternalService(host: string): tls.TLSSocket {
  return tls.connect({
    host,
    port: 443,
    rejectUnauthorized: false,
  });
}

const rejectUnauthorized = false;

export const indirectUnsafeAgent = new https.Agent({
  rejectUnauthorized,
});

process.env.NODE_TLS_REJECT_UNAUTHORIZED = "0";

export const testEnv = {
  NODE_TLS_REJECT_UNAUTHORIZED: "0",
};

process.env.NODE_TLS_REJECT_UNAUTHORIZED = 0 as any;

export const numericTestEnv = {
  NODE_TLS_REJECT_UNAUTHORIZED: 0,
};

const disabledNodeTls = "0";

export const indirectTestEnv = {
  NODE_TLS_REJECT_UNAUTHORIZED: disabledNodeTls,
};
