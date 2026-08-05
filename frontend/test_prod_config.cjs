function resolveApiBaseUrl(rawEnvUrl, isProd) {
  if (rawEnvUrl && rawEnvUrl.trim() !== "") {
    return rawEnvUrl.trim().replace(/\/+$/, "");
  }

  if (isProd) {
    throw new Error(
      "[SentinelAI Config Error] VITE_API_BASE_URL is missing or empty in the production build environment! " +
        "You must set VITE_API_BASE_URL in your build environment (e.g., VITE_API_BASE_URL=https://api.sentinelai.com)."
    );
  }

  return "";
}

console.log("1. Testing Dev Mode (empty VITE_API_BASE_URL):");
console.log("   Result:", JSON.stringify(resolveApiBaseUrl("", false)));

console.log("\n2. Testing Production Mode (VITE_API_BASE_URL set):");
console.log("   Result:", JSON.stringify(resolveApiBaseUrl("https://api.sentinelai.com", true)));

console.log("\n3. Testing Production Mode (empty VITE_API_BASE_URL):");
try {
  resolveApiBaseUrl("", true);
  console.error("   FAIL: Did not throw!");
} catch (err) {
  console.log("   SUCCESS: Threw expected error ->", err.message);
}
