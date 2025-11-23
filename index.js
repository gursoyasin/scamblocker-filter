// --- ScamBlocker Network Filter API (Vercel Serverless) ---
// Works with iOS MessageFilterExtension

import fetch from "node-fetch";

// Google Safe Browsing check
async function checkGoogleSafeBrowsing(url) {
    try {
        const key = process.env.SAFE_BROWSING_KEY;
        const endpoint = `https://safebrowsing.googleapis.com/v4/threatMatches:find?key=${key}`;

        const body = {
            client: { clientId: "scamblocker", clientVersion: "1.0" },
            threatInfo: {
                threatTypes: [
                    "MALWARE",
                    "SOCIAL_ENGINEERING",
                    "UNWANTED_SOFTWARE"
                ],
                platformTypes: ["ANY_PLATFORM"],
                threatEntryTypes: ["URL"],
                threatEntries: [{ url }]
            }
        };

        const res = await fetch(endpoint, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify(body)
        });

        const data = await res.json();
        return data.matches ? true : false;
    } catch (e) {
        console.log("Google SB error:", e);
        return false;
    }
}

// VirusTotal URL check
async function checkVirusTotal(url) {
    try {
        const key = process.env.VT_KEY;
        const id = Buffer.from(url).toString("base64").replace(/=+$/, "");

        const res = await fetch(`https://www.virustotal.com/api/v3/urls/${id}`, {
            headers: { "x-apikey": key }
        });

        const data = await res.json();
        const stats = data.data?.attributes?.last_analysis_stats;

        if (!stats) return false;

        return stats.malicious > 0 || stats.suspicious > 0;
    } catch (e) {
        console.log("VirusTotal error:", e);
        return false;
    }
}

// Domain keyword scan
function domainIsRisky(url) {
    const lowered = url.toLowerCase();

    if (
        lowered.includes("bank") ||
        lowered.includes("ziraat") ||
        lowered.includes("vakif") ||
        lowered.includes("isbank") ||
        lowered.includes("update") ||
        lowered.includes("guvenlik") ||
        lowered.includes("cargo") ||
        lowered.includes("edevlet")
    ) {
        return true;
    }

    return false;
}

export default async function handler(req, res) {
    const { message } = req.body;

    if (!message) {
        return res.status(400).json({ error: "message field required" });
    }

    const urls = [];
    const urlRegex = /(https?:\/\/[^\s]+)/g;
    const found = message.match(urlRegex);
    if (found) urls.push(...found);

    let risky = false;

    for (let u of urls) {
        const g = await checkGoogleSafeBrowsing(u);
        const v = await checkVirusTotal(u);
        const d = domainIsRisky(u);

        if (g || v || d) {
            risky = true;
            break;
        }
    }

    res.json({
        risky,
        urls
    });
}
