// --- ScamBlocker Network Filter API (Vercel Serverless) ---
import fetch from "node-fetch";

export default async function handler(req, res) {

    // 1) GET isteği gelirse hata vermesin
    if (req.method === "GET") {
        return res.status(200).json({ status: "API çalışıyor", method: "GET" });
    }

    // 2) Body doğrula
    const body = req.body || {};
    const message = body.message || "";
    const sender = body.sender || "";
    const url = body.url || "";

    if (!message && !url) {
        return res.status(400).json({
            error: "Geçersiz istek. 'message' veya 'url' body içinde olmalı."
        });
    }

    // 3) GOOGLE SAFE BROWSING CHECK
    async function checkGoogle(url) {
        try {
            const key = process.env.SAFE_BROWSING_KEY;
            const endpoint = `https://safebrowsing.googleapis.com/v4/threatMatches:find?key=${key}`;

            const payload = {
                client: { clientId: "scamblocker", clientVersion: "1.0" },
                threatInfo: {
                    threatTypes: ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE"],
                    platformTypes: ["ANY_PLATFORM"],
                    threatEntryTypes: ["URL"],
                    threatEntries: [{ url }]
                }
            };

            const r = await fetch(endpoint, {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify(payload)
            });

            const data = await r.json();
            return data.matches ? true : false;
        } catch (e) {
            console.error("Google Safe Browsing ERROR:", e);
            return false;
        }
    }

    // 4) VIRUSTOTAL CHECK
    async function checkVirusTotal(url) {
        try {
            const key = process.env.VT_KEY;

            const apiUrl = `https://www.virustotal.com/api/v3/urls/${Buffer.from(url).toString("base64").replace(/=/g, "")}`;

            const r = await fetch(apiUrl, {
                headers: { "x-apikey": key }
            });

            const data = await r.json();
            const stats = data?.data?.attributes?.last_analysis_stats;
            if (!stats) return false;

            return stats.malicious > 0 || stats.suspicious > 0;
        } catch (e) {
            console.error("VirusTotal ERROR:", e);
            return false;
        }
    }

    // 5) DOMAIN HEURISTICS
    function domainRisk(url) {
        const lowered = url.toLowerCase();
        return (
            lowered.includes("bank") ||
            lowered.includes("update") ||
            lowered.includes("login") ||
            lowered.includes("cargo") ||
            lowered.includes("edevlet")
        );
    }

    // 6) ANALİZ BAŞLIYOR
    const isGoogleBad = url ? await checkGoogle(url) : false;
    const isVtBad = url ? await checkVirusTotal(url) : false;
    const heuristic = url ? domainRisk(url) : false;

    const risky = isGoogleBad || isVtBad || heuristic;

    return res.status(200).json({
        url,
        risky,
        signals: {
            google: isGoogleBad,
            virustotal: isVtBad,
            heuristic
        }
    });
}
