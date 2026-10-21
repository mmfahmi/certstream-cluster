const stream = new WebSocket("ws://127.0.0.1:8081/");

stream.addEventListener("open", () => {
  console.log("Connected. Waiting for certificate updates…");
});

stream.addEventListener("message", ({ data }) => {
  const message = JSON.parse(data);
  if (message.message_type !== "certificate_update") return;

  const cert = message.data ?? {};
  const leaf = cert.leaf_cert ?? {};
  console.log(JSON.stringify({
    id: cert.cert_index,
    issuer: leaf.issuer?.O,
    domains: leaf.all_domains,
    seen: cert.seen,
    source: cert.source?.name,
  }, null, 2));
});

stream.addEventListener("error", () => {
  console.error("Could not connect to the local CertStream server.");
});
