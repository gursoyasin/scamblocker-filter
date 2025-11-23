import fetch from "node-fetch";

async function checkGoogle(url) {
  try {
    const key = process.env.SAFE_BROWSING_KEY;
    const endpoint = `https://safebrowsing.googleapis.com/v4/threatMatches:find?key=${key}`;

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
    console.log("Google Safe Browsing error:", e);
    return false;
  }
}

async function checkVirusTotal(url) {
  try {
    const key = process.env.VT_KEY;
    const encoded = Buffer.from(url).toString("base64").replace(/\//g, "_");
    const vtURL = `https://www.virustotal.com/api/v3/urls/${encoded}`;

    const res = await fetch(vtURL, {
      headers: { "x-apikey": key }
    });

    const data = await res.json();
    const stats = data.data?.attributes?.last_analysis_stats;

    return stats.malicious > 0 || stats.suspicious > 0;

  } catch (e) {
    console.log("VirusTotal error:", e);
    return false;
  }
}

function domainRisk(url) {
  const lowered = url.toLowerCase();
  return (
    lowered.includes("bank") ||
    lowered.includes("kargo") ||
    lowered.includes("update") ||
    lowered.includes("e-devlet") ||
    lowered.includes("edevlet")
  );
}

export default async function handler(req, res) {
  try {
    const message = req.body?.message || "";

    // URL çıkar
    const urlRegex = /(https?:\/\/[^\s]+)/g;
    const found = message.match(urlRegex);
    const url = found ? found[0] : null;

    if (!url) {
      return res.status(200).json({ result: "no_url" });
    }

    const google = await checkGoogle(url);
    const vt = await checkVirusTotal(url);
    const domain = domainRisk(url);

    const isDanger = google || vt || domain;

    return res.status(200).json({
      url,
      google,
      vt,
      domain,
      danger: isDanger
    });

  } catch (e) {
    console.error("Handler error:", e);
    return res.status(500).json({ error: "server_error" });
  }
}
