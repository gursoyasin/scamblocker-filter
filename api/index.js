// === ScamBlocker Network Filter API (Vercel Serverless) ===
// Works with iOS MessageFilterExtension

import fetch from "node-fetch";

export default async function handler(req, res) {
    try {
        const { message } = req.body;
        if (!message) return res.status(400).json({ error: "No message provided" });

        const foundLink = extractURL(message);
        if (!foundLink) return res.json({ safe: true, reason: "No URL found" });

        const safeBrowsingStatus = await checkSafeBrowsing(foundLink);
        const vtStatus = await checkVirusTotal(foundLink);
        const domainStatus = isSuspiciousDomain(foundLink);

        const isMalicious = safeBrowsingStatus || vtStatus || domainStatus;

        return res.json({
            url: foundLink,
            malicious: isMalicious,
            sources: {
                googleSafeBrowsing: safeBrowsingStatus,
                virusTotal: vtStatus,
                domainCheck: domainStatus
            }
        });
    } catch (e) {
        console.error("SERVER ERROR:", e);
        return res.status(500).json({ error: "Internal server error" });
    }
}

// === Extract URL from message ===
function extractURL(text) {
    const regex = /(https?:\/\/[^\s]+)/g;
    const match = text.match(regex);
    return match ? match[0] : null;
}

// === Google Safe Browsing API ===
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
    } catch {
        return false;
    }
}

// === VirusTotal API ===
async function checkVirusTotal(url) {
    try {
        const key = process.env.VT_KEY;
        const base64 = Buffer.from(url).toString("base64").replace(/=/g, "");
        const endpoint = `https://www.virustotal.com/api/v3/urls/${base64}`;

        const res = await fetch(endpoint, {
            headers: { "x-apikey": key },
        });

        const data = await res.json();
        const stats = data.data.attributes.last_analysis_stats;
        return stats.malicious > 0;
    } catch {
        return false;
    }
}

// === Basic suspicious domain check ===
function isSuspiciousDomain(url) {
    const lower = url.toLowerCase();
    const bad = ["bank", "hesap", "ödeme", "cargo", "update", "edevlet"];
    return bad.some((k) => lower.includes(k));
}
