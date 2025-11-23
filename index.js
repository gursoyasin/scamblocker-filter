// --- ScamBlocker Network Filter API (Vercel Serverless) ---
// Works with iOS MessageFilterExtension

import fetch from "node-fetch";

// MARK: - GOOGLE SAFE BROWSING
async function checkSafeBrowsing(url) {
  try {
    const key = process.env.SAFE_BROWSING_KEY;
    const endpoint =
      "https://safebrowsing.googleapis.com/v4/threatMatches:find?key=" + key;

    const body = {
      client: { clientId: "scamblocker", clientVersion: "1.0" },
      threatInfo: {
        threatTypes: ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE"],
        platformTypes: ["ANY_PLATFORM"],
        threatEntryTypes: ["URL"],
        threatEntries: [{ url }],
      },
    };

    const res = await fetch(endpoint, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body),
    });

    const data = await res.json();
    return data.matches ? true : false;
  } catch (e) {
    console.error("Google SB error:", e);
    return false;
  }
}

// MARK: - VIRUSTOTAL URL CHECK
async function checkVirusTotal(url) {
  try {
    const key = process.env.VT_KEY;
    const id = Buffer.from(url).toString("base64").replace(/\//g, "_");

    const res = await fetch(
      `https://www.virustotal.com/api/v3/urls/${id}`,
      { headers: { "x-apikey": key } }
    );

    const data = await res.json();
    const stats = data.data?.attributes?.last_analysis_stats;

    if (!stats) return false;

    return stats.malicious > 0 || stats.suspicious > 0;
  } catch (e) {
    console.log("VirusTotal error:", e);
    return false;
  }
}

// MARK: - DOMAIN KEYWORD CHECK
function domainIsRisk(url) {
  const lowered = url.toLowerCase();
  return (
    lowered.includes("bank") ||
    lowered.includes("ziraat") ||
    lowered.includes("vakif") ||
    lowered.includes("isbank") ||
    lowered.includes("kargo") ||
    lowered.includes("edevlet") ||
    lowered.includes("update") ||
    lowered.includes("login")
  );
}

// MARK: - MAIN API HANDLER
export default async function handler(req, res) {
  const { url } = req.body || {};

  if (!url) {
    return res.status(400).json({ error: "URL missing" });
  }

  console.log("Incoming URL:", url);

  const sb = await checkSafeBrowsing(url);
  const vt = await checkVirusTotal(url);
  const keyword = domainIsRisk(url);

  const highRisk = sb || vt || keyword;

  return res.status(200).json({
    success: true,
    url,
    safeBrowsing: sb,
    virusTotal: vt,
    keywordFlag: keyword,
    riskLevel: highRisk ? "high" : "low",
    score: highRisk ? 100 : 0,
  });
}
