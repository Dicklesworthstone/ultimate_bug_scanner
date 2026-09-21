import axios from "axios";
import https from "https";
import tls from "tls";

const privateCa = "-----BEGIN CERTIFICATE-----\\n...\\n-----END CERTIFICATE-----";

export const safeAgent = new https.Agent({
  ca: privateCa,
  rejectUnauthorized: true,
});

export const client = axios.create({
  httpsAgent: safeAgent,
});

export function connectToInternalService(host: string): tls.TLSSocket {
  return tls.connect({
    host,
    port: 443,
    ca: privateCa,
    rejectUnauthorized: true,
  });
}

const rejectUnauthorized = true;

export const indirectSafeAgent = new https.Agent({
  rejectUnauthorized,
});

process.env.NODE_TLS_REJECT_UNAUTHORIZED = "1";

export const testEnv = {
  NODE_TLS_REJECT_UNAUTHORIZED: "1",
};

process.env.NODE_TLS_REJECT_UNAUTHORIZED = "true";

export const numericTestEnv = {
  NODE_TLS_REJECT_UNAUTHORIZED: 1,
};

const enabledNodeTls = "1";

export const indirectTestEnv = {
  NODE_TLS_REJECT_UNAUTHORIZED: enabledNodeTls,
};
