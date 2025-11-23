// --- ScamBlocker: Phone Number Fraud Checker API ---
// POST /api/phone-check

export default async function handler(req, res) {
  if (req.method !== "POST") {
    return res.status(200).json({ status: "OK", method: "GET" });
  }

  try {
    const { phone } = req.body;

    if (!phone) {
      return res.status(400).json({ error: "Phone parameter is missing" });
    }

    // Normalize phone number
    const cleaned = phone
      .replace(/\s+/g, "")
      .replace(/-/g, "")
      .replace(/\(/g, "")
      .replace(/\)/g, "")
      .replace(/^(\+90)/, "")
      .replace(/^0/, "");

    // --- Fraud Number Database ---
    // Çok yaygın dolandırıcıların raporları (güncellenebilir)
    const fraudDB = {
      "8502555512": {
        reports: 128,
        category: "Fake Bank Call",
        description: "Kendini banka görevlisi olarak tanıtıp kart bilgisi isteyen aramalar.",
        risk: 95
      },
      "8502559966": {
        reports: 93,
        category: "Fake Debt Collection",
        description: "Sahte borç bildirimi ile ödeme isteyen çağrılar.",
        risk: 88
      },
      "5382224411": {
        reports: 64,
        category: "SMS Scam / Confirmation Code",
        description: "Kod isteyen veya ödeme linki içeren SMS dolandırıcılığı.",
        risk: 82
      },
      "5516652319": {
        reports: 31,
        category: "Investment Fraud",
        description: "Sahte yatırım danışmanlığı ile para isteyen çağrılar.",
        risk: 76
      }
    };

    // Check in DB
    if (fraudDB[cleaned]) {
      return res.status(200).json({
        status: "fraud",
        phone: cleaned,
        ...fraudDB[cleaned]
      });
    }

    // Not found → safe
    return res.status(200).json({
      status: "clean",
      phone: cleaned,
      risk: 5,
      description: "Bu numara kayıtlı bilinen dolandırıcılık listelerinde bulunamadı.",
      reports: 0
    });

  } catch (e) {
    console.error("PhoneCheck error:", e);
    return res.status(500).json({ error: "Internal Server Error" });
  }
}
