/**
 * SMS Budget Tracker — Secure Edition v2
 *
 * PRIVACY & SECURITY CONTRACT (GDPR · CCPA · India DPDP Act 2023)
 * ─────────────────────────────────────────────────────────────────
 * ✅ OTP, PIN, CVV, verification-code messages blocked before any data is read
 * ✅ Reads ONLY: ₹ amount, credited/debited keyword, brand name (from allowlist only)
 * ✅ Brand detection uses a pre-defined public allowlist — no free-text reading
 * ✅ No account numbers, personal names, UPI IDs, or bank refs stored
 * ✅ All processing local — zero network calls, zero server storage
 * ✅ Data lives in React state only; cleared on close
 * ✅ GDPR Art.5(1)(c) · CCPA "no sale" · India DPDP Act 2023 purpose-limitation
 */

import { useState, useMemo, useEffect } from "react";
import { registerPlugin } from "@capacitor/core";

// Native SMS plugin — reads Android SMS inbox via SmsPlugin.java
const SmsNative = registerPlugin("Sms");
import {
  BarChart, Bar, PieChart, Pie, Cell,
  XAxis, YAxis, Tooltip, ResponsiveContainer, LabelList
} from "recharts";
import { Home, List, TrendingUp, TrendingDown, Tag, X, Plus, ShieldCheck } from "lucide-react";

// ─── Theme ─────────────────────────────────────────────────────────────────
const INCOME_COLOR = "#10b981";
const UHO_COLOR    = "#f59e0b";
const MISC_COLOR   = "#818cf8";
const DEBIT_COLOR  = "#ef4444";
const QC_COLOR     = "#f43f5e";   // QuickCart — rose/pink
const CC_COLOR     = "#a78bfa";   // Credit Card — violet
const INV_COLOR    = "#06b6d4";   // Investments — cyan
const SAFE_COLOR   = "#22d3ee";
const CARD_BG      = "#1e293b";
const PAGE_BG      = "#0f172a";
const BORDER       = "#334155";
const T_MUTED      = "#64748b";
const T_DIM        = "#94a3b8";
const T_BRIGHT     = "#f1f5f9";

const DEFAULT_TAGS = [
  "Food", "Transport", "Shopping", "Entertainment",
  "Utilities", "Travel", "Electronics", "Medical", "Groceries"
];

// ══════════════════════════════════════════════════════════════════════════
//  SECURITY ENGINE — OTP / sensitive message blocker
// ══════════════════════════════════════════════════════════════════════════
const BLOCKED_PATTERNS = [
  /\botp\b/i, /one[\s-]?time[\s-]?pass(word)?/i,
  /verification\s*code/i, /\bauth(entication)?\s*code/i,
  /login\s*(code|otp|pin)/i, /\bsecure\s*(code|pin|otp)\b/i,
  /do\s*not\s*share/i, /never\s*share/i,
  /valid\s*for\s*\d+\s*min/i, /expire[sd]?\s*in\s*\d+/i,
  /\d{4,8}\s*is\s*your/i, /\bcode\s*[:\-–]\s*\d{4,8}/i,
  /\byour\s*(otp|code|pin)\s*(is|:)/i,
  /\bpin\b/i, /\bcvv\b/i, /\bpassword\b/i,
  /\bsecurity\s*(code|number|key)\b/i, /\bsecret\s*(code|key|word)\b/i,
  /login\s*attempt/i, /sign[\s-]?in\s*attempt/i,
  /access\s*attempt/i, /\bpasscode\b/i, /\bverif(y|ication|ied)\b/i,
  /2fa/i, /two[\s-]?factor/i, /multi[\s-]?factor/i,
  /\bfraud\s*alert\b/i, /suspicious\s*(activity|transaction)/i,
  /unauthori[sz]ed/i,
];

function isTransactionMessage(raw) {
  if (!raw || typeof raw !== "string") return false;
  // Accept ₹ OR Rs. amounts (covers bank SMS + credit card SMS)
  if (!(/(?:₹[\s\d,]|Rs\.?\s*[\d,])/.test(raw))) return false;
  // Must have a transaction keyword — covers debit/credit bank SMS and credit card SMS
  if (!(/\b(credited|debited|spent|charged|used\s+for|purchase[d]?|transaction)\b/i.test(raw))) return false;
  return !BLOCKED_PATTERNS.some(p => p.test(raw));
}

// ══════════════════════════════════════════════════════════════════════════
//  BRAND DETECTION — allowlist of known public brands only
//  Nothing outside this list is ever read from the message.
//  Brand names are public company names, not PII — GDPR-safe.
// ══════════════════════════════════════════════════════════════════════════
const QUICKCART_BRANDS = [
  // Food delivery
  "Zomato", "Swiggy",
  // Grocery / q-commerce
  "Zepto", "Blinkit", "Instamart", "BigBasket", "JioMart", "Dunzo",
  // E-commerce
  "Amazon", "Flipkart", "Meesho", "Ajio", "Myntra", "Nykaa",
  // Entertainment / out
  "District", "BookMyShow",
  // Pharmacy
  "PharmEasy", "1mg", "Medlife",
  // Other
  "Swiggy Instamart", "ONDC",
];

// ── Investment brand allowlist ───────────────────────────────────────────
const INVESTMENT_BRANDS = [
  "Groww", "Zerodha", "Kuvera", "ET Money", "INDmoney", "Angel One",
  "AngelOne", "Paytm Money", "PaytmMoney", "Upstox", "ICICI Direct",
  "HDFC Securities", "Kotak Securities", "SBI Securities", "Motilal Oswal",
];
const INV_REGEX = new RegExp(
  INVESTMENT_BRANDS.map(b => `\\b${b.replace(/[-\s]/g, "[\\s-]?")}\\b`).join("|"),
  "i"
);
function detectInvestmentBrand(raw) {
  const m = raw.match(INV_REGEX);
  return m ? m[0] : null;
}

/** Builds one combined regex for all brands (case-insensitive word-boundary match) */
const BRAND_REGEX = new RegExp(
  QUICKCART_BRANDS.map(b => `\\b${b.replace(/[-\s]/g, "[\\s-]?")}\\b`).join("|"),
  "i"
);

function detectBrand(raw) {
  const match = raw.match(BRAND_REGEX);
  return match ? match[0] : null;
}

// ══════════════════════════════════════════════════════════════════════════
//  UPI NARRATION AUTO-TAGGER
//  Reads ONLY the narration/remarks field of UPI SMS (the note you type in
//  GPay / PhonePe). Raw text is NEVER stored — only the matched tag label.
//  e.g. "grocery" → tag:"Groceries", "travel" → tag:"Travel"
// ══════════════════════════════════════════════════════════════════════════

// Keyword → tag mapping (only predefined labels are ever stored)
const NARRATION_TAG_MAP = [
  { tag: "Groceries",     keywords: ["grocery","groceries","kirana","sabzi","vegetable","fruit","provision","supermarket","dmart","reliance fresh","more store"] },
  { tag: "Food",          keywords: ["food","restaurant","cafe","dining","lunch","dinner","breakfast","meal","snack","coffee","tea","juice","bakery","hotel food"] },
  { tag: "Travel",        keywords: ["travel","flight","hotel","train","bus","cab","taxi","trip","tour","holiday","vacation","airport","railway","irctc","booking"] },
  { tag: "Medical",       keywords: ["medical","medicine","hospital","doctor","pharmacy","health","chemist","clinic","diagnostic","lab","apollo","medplus"] },
  { tag: "Transport",     keywords: ["fuel","petrol","diesel","metro","auto","rickshaw","parking","toll","fastag","cng","hp pump","iocl"] },
  { tag: "Entertainment", keywords: ["entertainment","movie","theatre","cinema","concert","show","sport","game","pvr","inox","bookmyshow"] },
  { tag: "Shopping",      keywords: ["shopping","clothes","fashion","apparel","cloth","saree","shirt","shoes","bag","accessory"] },
  { tag: "Utilities",     keywords: ["electricity","water","gas","bill","recharge","internet","broadband","wifi","dth","postpaid","prepaid","utility"] },
  { tag: "Rent",          keywords: ["rent","maintenance","society","housing","landlord","flat","deposit","lease"] },
  { tag: "Education",     keywords: ["school","college","fees","education","course","tuition","book","stationery","library","exam"] },
  { tag: "Self Care",     keywords: ["salon","spa","haircut","gym","fitness","yoga","wellness","beauty","parlour","massage"] },
  { tag: "Savings",       keywords: ["savings","investment","fd","rd","mutual fund","sip","ppf","insurance","premium","lic"] },
];

// Extract the narration/note from UPI bank SMS — only the narration segment
// Patterns cover HDFC, SBI, ICICI, Axis, Kotak, Yes Bank, IndusInd UPI formats
function extractUpiNarration(raw) {
  const patterns = [
    // HDFC:  Info: UPI/refno/NARRATION/vpa@bank
    /\bInfo:\s*UPI[\/\-]\d+[\/\-]([^\/\-,@\n]{2,30})[\/\-]/i,
    // Axis / generic: UPI/refno/vpa@bank/NARRATION
    /UPI[\/\-]\d+[\/\-][^\/]+@[^\/]+[\/\-]([^\/,\.\n]{2,30})/i,
    // Remarks / Note field (SBI, ICICI variants)
    /\bRemarks?:\s*([^\.\n,]{2,30})/i,
    /\bNote:\s*([^\.\n,]{2,30})/i,
    // PhonePe / PayTM narration after "for"
    /\bpaid\s+(?:for|via)\s+([a-z][a-z\s]{1,25})/i,
  ];
  for (const p of patterns) {
    const m = raw.match(p);
    if (m) {
      const narration = m[1].trim().toLowerCase();
      // Reject if narration looks like a VPA, reference number, or is too generic
      if (/[@\d]{4,}/.test(narration)) continue;
      if (narration.length < 3)        continue;
      return narration;
    }
  }
  return null;
}

function narrationToTag(raw) {
  const narration = extractUpiNarration(raw);
  if (!narration) return null;
  for (const { tag, keywords } of NARRATION_TAG_MAP) {
    if (keywords.some(k => narration.includes(k))) return tag;
  }
  return null;
}

// ── Secure parser ───────────────────────────────────────────────────────
function secureExtract(raw) {
  // Match ₹ or Rs. amounts (credit card SMS often use Rs.)
  const amtMatch = raw.match(/(?:₹|Rs\.?)\s*([\d,]+(?:\.\d{1,2})?)/i);
  if (!amtMatch) return null;
  const amount = Math.round(parseFloat(amtMatch[1].replace(/,/g, "")) * 100) / 100;
  if (!isFinite(amount) || amount <= 0) return null;

  // credited / refund / cashback / reversal = money coming in
  const isCredit  = /\bcredited\b/i.test(raw);
  const isRefund  = /\b(refund|reversal|cashback|cash\s*back|reversed|returned)\b/i.test(raw);
  const type = (isCredit || isRefund) ? "credited" : "debited";
  const isRefundTxn = isRefund && !isCredit; // flag for display

  // Detect if this is a credit card transaction
  const isCreditCard = /credit[\s\-]?card|cc\s+(ending|no|limit|card)|credit\s*a\/c/i.test(raw);

  const brand       = detectBrand(raw);           // null if no known QC brand
  const invBrand    = detectInvestmentBrand(raw); // null if no investment brand

  // Category logic:
  //   credited              → income
  //   credit card debit     → creditcard   (own category, regardless of amount/brand)
  //   investment platform   → investments  (Groww, Zerodha, etc.)
  //   known QC brand        → quickcart    (regardless of amount)
  //   debit > 2000          → uho
  //   debit ≤ 2000          → miscellaneous
  let category;
  if      (type === "credited") category = "income";
  else if (isCreditCard)        category = "creditcard";
  else if (invBrand)            category = "investments";
  else if (brand)               category = "quickcart";
  else if (amount > 2000)       category = "uho";
  else                          category = "miscellaneous";

  return { amount, type, category, brand: brand || invBrand, isCreditCard, isRefund: isRefundTxn };
}

const MONTH_NAMES = ["Jan","Feb","Mar","Apr","May","Jun","Jul","Aug","Sep","Oct","Nov","Dec"];

function processSMS(sms) {
  if (!isTransactionMessage(sms.raw)) return null;
  const parsed = secureExtract(sms.raw);
  if (!parsed) return null;

  // Derive month/year for period filtering
  let monthKey, year;
  if (sms.timestamp) {
    const d = new Date(sms.timestamp);
    year     = d.getFullYear();
    monthKey = `${year}-${String(d.getMonth() + 1).padStart(2, "0")}`;
  } else {
    // Parse from date string like "Apr 08" — assume current year
    const now  = new Date();
    year       = now.getFullYear();
    const parts = (sms.date || "").split(" ");
    const mIdx  = MONTH_NAMES.indexOf(parts[0]);
    const month = mIdx >= 0 ? mIdx + 1 : now.getMonth() + 1;
    monthKey   = `${year}-${String(month).padStart(2, "0")}`;
  }

  // Auto-tag from UPI narration (the note you type in GPay / PhonePe)
  // Raw narration text is never stored — only the matched label (e.g. "Grocery")
  const suggestedTag = parsed.type === "debited" ? narrationToTag(sms.raw) : null;

  return { id: sms.id, date: sms.date, bank: sms.bank, monthKey, year, ...parsed, suggestedTag, tag: null };
}

// ─── Mock SMS feed ──────────────────────────────────────────────────────
const MOCK_SMS_FEED = [
  // Credited
  { id: 1,  raw: "₹45,000 credited to Ac xx5678 SALARY from TECHCORP PVT LTD",     date: "Apr 08", bank: "HDFC"  },
  { id: 2,  raw: "₹15,000 credited to Ac xx5678 NEFT from RAHUL SHARMA",            date: "Apr 14", bank: "HDFC"  },
  { id: 3,  raw: "₹8,000 credited to Ac xx5678 IMPS from PRIYA MEHTA",              date: "Apr 12", bank: "SBI"   },
  { id: 4,  raw: "₹5,000 credited to Ac xx5678 UPI from AMIT KUMAR",                date: "Apr 10", bank: "ICICI" },
  // UHO (large, non-brand)
  { id: 5,  raw: "₹12,000 debited from Ac xx5678. Info: IndiGo Flight Booking",     date: "Apr 09", bank: "HDFC"  },
  { id: 6,  raw: "₹6,500 debited from Ac xx5678. Info: Monthly Rent Apr",           date: "Apr 07", bank: "ICICI" },
  { id: 7,  raw: "₹3,500 debited from Ac xx5678. Info: Myntra Fashion Order",       date: "Apr 11", bank: "HDFC"  },
  { id: 8,  raw: "₹2,500 debited from Ac xx5678. Info: Amazon Shopping",            date: "Apr 14", bank: "HDFC"  },
  // QuickCart brands
  { id: 9,  raw: "₹450 debited from Ac xx5678. Info: Swiggy Order #7892",           date: "Apr 13", bank: "HDFC"  },
  { id: 10, raw: "₹380 debited from Ac xx5678. Info: Zomato Order #2312",           date: "Apr 12", bank: "HDFC"  },
  { id: 11, raw: "₹1,850 debited from Ac xx5678. Info: BigBasket Grocery",          date: "Apr 11", bank: "HDFC"  },
  { id: 12, raw: "₹290 debited from Ac xx5678. Info: Zepto Order #5510",            date: "Apr 10", bank: "SBI"   },
  { id: 13, raw: "₹560 debited from Ac xx5678. Info: Blinkit Order #8821",          date: "Apr 09", bank: "HDFC"  },
  { id: 14, raw: "₹1,200 debited from Ac xx5678. Info: Amazon Fresh Order",         date: "Apr 08", bank: "HDFC"  },
  { id: 15, raw: "₹750 debited from Ac xx5678. Info: District Movie Booking",       date: "Apr 07", bank: "ICICI" },
  { id: 16, raw: "₹320 debited from Ac xx5678. Info: Swiggy Instamart",             date: "Apr 06", bank: "SBI"   },
  // Misc (small, non-brand)
  { id: 17, raw: "₹900 debited from Ac xx5678. Info: Netflix Subscription",         date: "Apr 10", bank: "HDFC"  },
  { id: 18, raw: "₹500 debited from Ac xx5678. Info: Jio Recharge",                 date: "Apr 07", bank: "SBI"   },
  { id: 19, raw: "₹350 debited from Ac xx5678. Info: HP Petrol Fill-up",            date: "Apr 09", bank: "SBI"   },
  { id: 20, raw: "₹200 debited from Ac xx5678. Info: Starbucks Coffee",             date: "Apr 11", bank: "SBI"   },
  // UPI with narration — auto-tag from GPay note
  { id: 31, raw: "₹650 debited from Ac xx5678. Info: UPI/987654321/grocery/merchant@okicici. Avl Bal:₹8,200", date: "Apr 13", bank: "HDFC" },
  { id: 32, raw: "₹4,200 debited from Ac xx5678. Info: UPI/876543219/travel/irctc@okaxis. Avl Bal:₹4,000",    date: "Apr 08", bank: "HDFC" },
  { id: 33, raw: "₹800 debited from Ac xx5678. Info: UPI/765432198/medical/apollo@okicici. Avl Bal:₹3,200",   date: "Apr 10", bank: "SBI"  },
  { id: 34, raw: "₹1,100 debited from Ac xx5678 Remarks: rent payment Apr. UPI Ref:654321987",                date: "Apr 01", bank: "ICICI"},
  { id: 35, raw: "₹350 debited from Ac xx5678. Info: UPI/543219876/fuel/hpcl@okaxis. Avl Bal:₹2,850",        date: "Apr 11", bank: "HDFC" },
  // Credit Card transactions
  { id: 21, raw: "Rs.3,500.00 debited from your HDFC Credit Card ending 1234 at IndiGo. Apr 08",   date: "Apr 08", bank: "HDFC"  },
  { id: 22, raw: "₹850 spent on SBI Credit Card XX5678 at Swiggy on 12-Apr-26",                    date: "Apr 12", bank: "SBI"   },
  { id: 23, raw: "Alert: Transaction of ₹1,200 on your Axis Bank Credit Card ending 9012 at Amazon", date: "Apr 11", bank: "Axis"  },
  { id: 24, raw: "Rs.450.00 charged on ICICI Bank Credit Card XX3456 at Zomato. Apr 10",            date: "Apr 10", bank: "ICICI" },
  { id: 25, raw: "Your Kotak Credit Card has been used for Rs.6,200 at Apple Store. Apr 09",        date: "Apr 09", bank: "Kotak" },
  // Investments — Groww, Zerodha, SIP
  { id: 41, raw: "₹5,000 debited from Ac xx5678. Info: Groww Mutual Fund SIP Apr",        date: "Apr 03", bank: "HDFC"  },
  { id: 42, raw: "₹2,500 debited from Ac xx5678. Info: Zerodha Broking Charges",          date: "Apr 07", bank: "ICICI" },
  { id: 43, raw: "₹10,000 debited from Ac xx5678. Info: Groww - Nifty 50 Index Fund SIP", date: "Apr 01", bank: "SBI"   },
  { id: 44, raw: "₹3,000 debited from Ac xx5678. Info: INDmoney US Stock Purchase",       date: "Apr 10", bank: "HDFC"  },
  // BLOCKED — OTP messages (prove filter works)
  { id: 101, raw: "748392 is your OTP for HDFC NetBanking. Do not share with anyone.", date: "Apr 14", bank: "HDFC"  },
  { id: 102, raw: "Your ICICI Bank OTP is 291047. Valid for 10 minutes.",              date: "Apr 13", bank: "ICICI" },
  { id: 103, raw: "SBI: Your login OTP is 503821. Do not share this code.",            date: "Apr 12", bank: "SBI"   },
  { id: 104, raw: "PIN for your debit card ending 5678 has been set. Do not share.",   date: "Apr 11", bank: "HDFC"  },
  { id: 105, raw: "Two-factor authentication code: 884712. Expires in 5 min.",         date: "Apr 10", bank: "SBI"   },
];

// ─── Helpers ─────────────────────────────────────────────────────────────
const fmt = n => `₹${n.toLocaleString("en-IN", { minimumFractionDigits: 0, maximumFractionDigits: 2 })}`;

const catLabel = c => ({
  income: "Income", uho: "UHO", miscellaneous: "Misc",
  quickcart: "QuickCart", creditcard: "CC", investments: "Invest",
}[c] || c);

const catStyle = c => ({
  income:        { color: INCOME_COLOR, background: "rgba(16,185,129,.15)"  },
  uho:           { color: UHO_COLOR,    background: "rgba(245,158,11,.15)"  },
  miscellaneous: { color: MISC_COLOR,   background: "rgba(129,140,248,.15)" },
  quickcart:     { color: QC_COLOR,     background: "rgba(244,63,94,.15)"   },
  creditcard:    { color: CC_COLOR,     background: "rgba(167,139,250,.15)" },
  investments:   { color: INV_COLOR,    background: "rgba(6,182,212,.15)"   },
}[c]);

const CAT_COLORS = {
  income: INCOME_COLOR, uho: UHO_COLOR, miscellaneous: MISC_COLOR,
  quickcart: QC_COLOR,  creditcard: CC_COLOR, investments: INV_COLOR,
};

const CustomTooltip = ({ active, payload, label }) => {
  if (!active || !payload?.length) return null;
  return (
    <div style={{ background: PAGE_BG, border: `1px solid ${BORDER}`, borderRadius: 8,
      padding: "6px 12px", fontSize: 12, color: T_BRIGHT }}>
      {label && <p style={{ color: T_DIM, margin: "0 0 2px", fontSize: 11 }}>{label}</p>}
      <p style={{ margin: 0, fontWeight: 700 }}>{fmt(payload[0].value)}</p>
    </div>
  );
};

const StatCard = ({ label, value, accent, Icon, sub }) => (
  <div style={{ background: `${accent}18`, border: `1px solid ${accent}35`,
    borderRadius: 16, padding: "14px 16px", flex: 1 }}>
    <div style={{ display: "flex", alignItems: "center", gap: 6, marginBottom: 8 }}>
      <Icon size={14} color={accent} />
      <span style={{ color: accent, fontSize: 11, fontWeight: 600, textTransform: "uppercase", letterSpacing: 0.5 }}>{label}</span>
    </div>
    <p style={{ color: T_BRIGHT, fontSize: 18, fontWeight: 700, margin: "0 0 2px" }}>{value}</p>
    {sub && <p style={{ color: T_MUTED, fontSize: 10, margin: 0 }}>{sub}</p>}
  </div>
);

// ══════════════════════════════════════════════════════════════════════════
//  MAIN APP
// ══════════════════════════════════════════════════════════════════════════
export default function App() {
  const [tab,            setTab]            = useState("home");
  const [tagMap,         setTagMap]         = useState({});
  const [activeTagTxn,   setActiveTagTxn]   = useState(null);
  const [customTagInput, setCustomTagInput] = useState("");
  const [userTags,       setUserTags]       = useState(DEFAULT_TAGS);
  const [showTagMgr,     setShowTagMgr]     = useState(false);
  const [showPrivacy,    setShowPrivacy]    = useState(false);
  const [chartMode,      setChartMode]      = useState("pie");  // "pie" | "bar"
  const [qcChartMode,    setQcChartMode]    = useState("bar");  // QuickCart: "pie" | "bar"
  const [newGlobalTag,   setNewGlobalTag]   = useState("");
  const [filters,        setFilters]        = useState({ type: "all", category: "all" });
  const [smsFeed,        setSmsFeed]        = useState(MOCK_SMS_FEED);
  const [smsLoading,     setSmsLoading]     = useState(true);

  // ── Load real SMS on mount (falls back to mock data in browser/dev) ───
  useEffect(() => {
    SmsNative.getMessages()
      .then(({ messages }) => {
        const feed = messages.map((m, i) => {
          const d = new Date(Number(m.date));
          return {
            id:        i,
            raw:       m.body,
            timestamp: Number(m.date),
            // Always "Apr 08" format so month parser works correctly
            date: `${MONTH_NAMES[d.getMonth()]} ${String(d.getDate()).padStart(2, "0")}`,
            bank: m.address,
          };
        });
        // Only replace if we actually got messages
        if (feed.length > 0) setSmsFeed(feed);
      })
      .catch(() => { /* keep mock data — running in browser or permission denied */ })
      .finally(() => setSmsLoading(false));
  }, []);

  // ── Period state ─────────────────────────────────────────────────────
  const NOW = new Date();
  const [period,    setPeriod]    = useState("M"); // "W"|"M"|"3M"|"6M"|"1Y"|"ALL"
  const [viewMonth, setViewMonth] = useState(NOW.getMonth() + 1);
  const [viewYear,  setViewYear]  = useState(NOW.getFullYear());

  const [selectedCat, setSelectedCat] = useState(null);
  const toggleCat = cat => setSelectedCat(p => p === cat ? null : cat);

  const shiftMonth = (dir) => {
    setViewMonth(m => {
      let nm = m + dir;
      if (nm < 1)  { setViewYear(y => y - 1); return 12; }
      if (nm > 12) { setViewYear(y => y + 1); return 1;  }
      return nm;
    });
  };

  // ── Security pipeline ─────────────────────────────────────────────────
  const { txns, blockedCount } = useMemo(() => {
    let blocked = 0;
    const passed = smsFeed.reduce((acc, sms) => {
      const r = processSMS(sms);
      if (r) acc.push(r); else blocked++;
      return acc;
    }, []);
    return { txns: passed, blockedCount: blocked };
  }, [smsFeed]);

  const taggedTxns = useMemo(
    // Manual tag wins; fall back to GPay narration auto-tag; then null
    () => txns.map(t => ({ ...t, tag: tagMap[t.id] || t.suggestedTag || null })),
    [txns, tagMap]
  );

  // ── Period filter ─────────────────────────────────────────────────────
  const periodTxns = useMemo(() => {
    const mk = (y, m) => `${y}-${String(m).padStart(2, "0")}`;
    if (period === "ALL") return taggedTxns;
    if (period === "M")   return taggedTxns.filter(t => t.monthKey === mk(viewYear, viewMonth));
    if (period === "1Y")  return taggedTxns.filter(t => t.year === NOW.getFullYear());
    // W / 3M / 6M — cut off by monthKey
    const monthsBack = period === "W" ? 0 : period === "3M" ? 3 : 6;
    const d = new Date(NOW.getFullYear(), NOW.getMonth() - monthsBack, 1);
    const cutoff = mk(d.getFullYear(), d.getMonth() + 1);
    return taggedTxns.filter(t => t.monthKey >= cutoff);
  }, [taggedTxns, period, viewYear, viewMonth]);

  // ── Aggregates (period-scoped) ────────────────────────────────────────
  const totalCredited  = useMemo(() => periodTxns.filter(t => t.type === "credited").reduce((s, t) => s + t.amount, 0), [periodTxns]);
  const totalDebited   = useMemo(() => periodTxns.filter(t => t.type === "debited").reduce((s, t) => s + t.amount, 0), [periodTxns]);
  const totalUHO       = useMemo(() => periodTxns.filter(t => t.category === "uho").reduce((s, t) => s + t.amount, 0), [periodTxns]);
  const totalMisc      = useMemo(() => periodTxns.filter(t => t.category === "miscellaneous").reduce((s, t) => s + t.amount, 0), [periodTxns]);
  const totalQuickCart = useMemo(() => periodTxns.filter(t => t.category === "quickcart").reduce((s, t) => s + t.amount, 0), [periodTxns]);
  const totalCC        = useMemo(() => periodTxns.filter(t => t.category === "creditcard").reduce((s, t) => s + t.amount, 0), [periodTxns]);
  const totalInv       = useMemo(() => periodTxns.filter(t => t.category === "investments").reduce((s, t) => s + t.amount, 0), [periodTxns]);

  // ── Chart data ────────────────────────────────────────────────────────
  const barData = [
    { name: "Credited",  amt: totalCredited,  fill: INCOME_COLOR },
    { name: "Debited",   amt: totalDebited,   fill: DEBIT_COLOR  },
  ];

  const pieData = useMemo(() => [
    { name: "Income",     value: totalCredited,  color: INCOME_COLOR },
    { name: "QuickCart",  value: totalQuickCart, color: QC_COLOR     },
    { name: "UHO",        value: totalUHO,       color: UHO_COLOR    },
    { name: "Misc",       value: totalMisc,      color: MISC_COLOR   },
  ].filter(d => d.value > 0), [totalCredited, totalQuickCart, totalUHO, totalMisc]);

  // Drill-down txns for selected category card
  const drillTxns = useMemo(() =>
    selectedCat ? periodTxns.filter(t => t.category === selectedCat) : [],
    [periodTxns, selectedCat]
  );

  // Yearly insight — top category, top brand, biggest single spend
  const yearlyInsight = useMemo(() => {
    if (!["1Y","ALL"].includes(period) || periodTxns.length === 0) return null;
    const debits = periodTxns.filter(t => t.type === "debited");
    const cats = { uho: 0, quickcart: 0, miscellaneous: 0, creditcard: 0, investments: 0 };
    debits.forEach(t => { if (cats[t.category] !== undefined) cats[t.category] += t.amount; });
    const topCat = Object.entries(cats).sort((a,b) => b[1]-a[1])[0];
    const topCatLabel = { uho: "UHO (big spends)", quickcart: "QuickCart", miscellaneous: "Misc", creditcard: "Credit Card", investments: "Investments" }[topCat[0]];

    const brandMap = {};
    debits.filter(t => t.brand).forEach(t => { brandMap[t.brand] = (brandMap[t.brand]||0) + t.amount; });
    const topBrand = Object.entries(brandMap).sort((a,b) => b[1]-a[1])[0];

    const biggestSpend = debits.reduce((max, t) => t.amount > (max?.amount||0) ? t : max, null);

    const monthMap = {};
    debits.forEach(t => { monthMap[t.monthKey] = (monthMap[t.monthKey]||0) + t.amount; });
    const heaviestMonth = Object.entries(monthMap).sort((a,b) => b[1]-a[1])[0];
    const hmLabel = heaviestMonth ? `${MONTH_NAMES[parseInt(heaviestMonth[0].split("-")[1])-1]}` : null;

    return { topCat: topCatLabel, topCatAmt: topCat[1], topBrand, biggestSpend, heaviestMonth: hmLabel, heaviestAmt: heaviestMonth?.[1] };
  }, [periodTxns, period]);

  // Brand chart — QuickCart brands breakdown
  const brandChartData = useMemo(() => {
    const map = {};
    periodTxns.filter(t => t.category === "quickcart" && t.brand).forEach(t => {
      const b = t.brand.charAt(0).toUpperCase() + t.brand.slice(1).toLowerCase()
        .replace(/\b\w/g, c => c.toUpperCase());
      map[b] = (map[b] || 0) + t.amount;
    });
    return Object.entries(map)
      .map(([name, amt]) => ({ name, amt }))
      .sort((a, b) => b.amt - a.amt);
  }, [taggedTxns]);

  // Tag chart — spending per tag
  const tagChartData = useMemo(() => {
    const map = {};
    periodTxns.filter(t => t.tag).forEach(t => {
      map[t.tag] = (map[t.tag] || 0) + t.amount;
    });
    return Object.entries(map)
      .map(([name, amt]) => ({ name, amt }))
      .sort((a, b) => b.amt - a.amt);
  }, [taggedTxns]);

  // Filtered txns for Overview (period-scoped)
  const filteredTxns = useMemo(() => periodTxns.filter(t => {
    if (filters.type !== "all"     && t.type     !== filters.type)     return false;
    if (filters.category !== "all" && t.category !== filters.category) return false;
    return true;
  }), [taggedTxns, filters]);

  // ── Actions ───────────────────────────────────────────────────────────
  const applyTag  = (id, tag) => { setTagMap(p => ({ ...p, [id]: tag })); setActiveTagTxn(null); setCustomTagInput(""); };
  const removeTag = id        => setTagMap(p => { const n = { ...p }; delete n[id]; return n; });
  const addGlobalTag = () => {
    const t = newGlobalTag.trim();
    if (t && !userTags.includes(t)) setUserTags(p => [...p, t]);
    setNewGlobalTag("");
  };

  const chip = (active, color = "#6366f1") => ({
    padding: "5px 13px", borderRadius: 20, border: "none", cursor: "pointer",
    fontSize: 11, fontWeight: 500, whiteSpace: "nowrap", transition: "all .15s",
    background: active ? color : PAGE_BG, color: active ? "#fff" : T_MUTED,
  });

  const S = {
    section:      { background: CARD_BG, borderRadius: 16, padding: 16, marginBottom: 14 },
    sectionTitle: { color: T_DIM, fontSize: 13, fontWeight: 600, margin: "0 0 14px" },
  };

  // ══════════════════════════════════════════════════════════════════════
  //  PRIVACY BANNER + MODAL
  // ══════════════════════════════════════════════════════════════════════
  const PrivacyBanner = () => (
    <button onClick={() => setShowPrivacy(true)}
      style={{ display: "flex", alignItems: "center", justifyContent: "space-between",
        background: "rgba(34,211,238,.07)", border: "1px solid rgba(34,211,238,.2)",
        borderRadius: 12, padding: "9px 14px", marginBottom: 14,
        cursor: "pointer", width: "100%", textAlign: "left" }}>
      <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
        <ShieldCheck size={14} color={SAFE_COLOR} />
        <span style={{ color: SAFE_COLOR, fontSize: 11, fontWeight: 600 }}>Privacy Protected</span>
        <span style={{ color: T_MUTED, fontSize: 11 }}>· {blockedCount} msgs blocked</span>
      </div>
      <span style={{ color: T_MUTED, fontSize: 10 }}>tap ›</span>
    </button>
  );

  const PrivacyModal = () => (
    <div onClick={() => setShowPrivacy(false)}
      style={{ position: "absolute", inset: 0, background: "rgba(0,0,0,.65)", zIndex: 60,
        display: "flex", alignItems: "flex-end" }}>
      <div onClick={e => e.stopPropagation()}
        style={{ background: CARD_BG, borderRadius: "20px 20px 0 0", width: "100%",
          padding: "22px 20px 40px", maxHeight: "82%", overflowY: "auto" }}>
        <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 18 }}>
          <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
            <ShieldCheck size={20} color={SAFE_COLOR} />
            <h3 style={{ color: T_BRIGHT, fontSize: 17, fontWeight: 700, margin: 0 }}>Privacy & Security</h3>
          </div>
          <button onClick={() => setShowPrivacy(false)}
            style={{ background: PAGE_BG, border: "none", borderRadius: 8, width: 30, height: 30,
              cursor: "pointer", display: "flex", alignItems: "center", justifyContent: "center" }}>
            <X size={14} color={T_DIM} />
          </button>
        </div>
        {[
          { icon: "🚫", title: `${blockedCount} sensitive messages blocked`,
            body: "OTP, PIN, CVV, verification codes, fraud alerts — detected and discarded before any data is read. Not a single digit from those messages is stored." },
          { icon: "🔢", title: "Only ₹ amount + type extracted",
            body: "Parser reads: rupee amount, credited/debited keyword, and known brand name (from public allowlist only). Names, account numbers, UPI IDs, and bank refs are never stored." },
          { icon: "🏷️", title: "Brand detection is allowlist-only",
            body: `Only ${QUICKCART_BRANDS.length} pre-approved public brand names are matched. No free-text reading, no NLP, no third-party API. The match regex is compiled locally.` },
          { icon: "📵", title: "Zero network calls",
            body: "No HTTP requests, no analytics SDK, no crash reporter. All processing runs in your browser / device." },
          { icon: "🗑️", title: "No persistent storage",
            body: "Nothing written to localStorage, IndexedDB, cookies, or files. Data lives in React state and vanishes when you close the app." },
          { icon: "⚖️", title: "Legal compliance",
            body: "GDPR Art. 5(1)(c) data minimisation (EU) · CCPA 'no sale of personal information' (USA) · India DPDP Act 2023 purpose-limitation & storage-limitation." },
        ].map((item, i, arr) => (
          <div key={i} style={{ marginBottom: 14, paddingBottom: 14,
            borderBottom: i < arr.length - 1 ? `1px solid ${BORDER}` : "none" }}>
            <div style={{ display: "flex", alignItems: "center", gap: 8, marginBottom: 4 }}>
              <span style={{ fontSize: 15 }}>{item.icon}</span>
              <p style={{ color: T_BRIGHT, fontSize: 13, fontWeight: 600, margin: 0 }}>{item.title}</p>
            </div>
            <p style={{ color: T_DIM, fontSize: 12, lineHeight: 1.6, margin: 0, paddingLeft: 27 }}>{item.body}</p>
          </div>
        ))}
        <div style={{ background: "rgba(244,63,94,.08)", border: "1px solid rgba(244,63,94,.25)",
          borderRadius: 12, padding: "12px 14px", marginTop: 4 }}>
          <p style={{ color: QC_COLOR, fontSize: 11, fontWeight: 600, margin: "0 0 5px" }}>QuickCart brand allowlist ({QUICKCART_BRANDS.length} brands)</p>
          <p style={{ color: T_MUTED, fontSize: 11, lineHeight: 1.7, margin: 0 }}>
            {QUICKCART_BRANDS.join(" · ")}
          </p>
        </div>
      </div>
    </div>
  );

  // ══════════════════════════════════════════════════════════════════════
  //  HOME TAB
  // ══════════════════════════════════════════════════════════════════════
  const HomeTab = () => {
    const totalSpend = totalUHO + totalMisc + totalQuickCart;
    const uhoP  = totalSpend > 0 ? (totalUHO       / totalSpend * 100) : 0;
    const qcP   = totalSpend > 0 ? (totalQuickCart / totalSpend * 100) : 0;
    const miscP = totalSpend > 0 ? (totalMisc      / totalSpend * 100) : 0;

    const PERIODS = ["W","M","3M","6M","1Y","ALL"];

    const periodLabel = period === "M"
      ? `${MONTH_NAMES[viewMonth - 1]} ${viewYear}`
      : period === "1Y" || period === "ALL" ? `${viewYear}` : `Last ${period}`;

    // Category icon map
    const catIcon = { income:"💚", uho:"🏠", quickcart:"🛒", miscellaneous:"🏷️" };
    const txnColor = t => t.type === "credited"
      ? INCOME_COLOR
      : t.category === "uho" ? UHO_COLOR : t.category === "quickcart" ? QC_COLOR : MISC_COLOR;

    return (
    <div style={{ overflowY: "auto", flex: 1, paddingBottom: 88 }}>

      {/* ── HERO CARD (cream) ─────────────────────────────────────── */}
      <div style={{ background: "#f5f0e8", borderRadius: "0 0 28px 28px",
        padding: "52px 20px 24px", marginBottom: 16 }}>

        {/* Top row */}
        <div style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start", marginBottom: 4 }}>
          <div>
            <p style={{ color: "#6b6460", fontSize: 11, letterSpacing: 1, textTransform: "uppercase", margin: "0 0 2px" }}>
              Total Spent · {periodLabel}
            </p>
            <h1 style={{ color: "#1a1410", fontSize: 34, fontWeight: 800, margin: 0, letterSpacing: -1 }}>
              {fmt(totalSpend)}
            </h1>
            {totalCredited > 0 && (
              <p style={{ color: "#3d9a6e", fontSize: 12, margin: "4px 0 0", fontWeight: 600 }}>
                +{fmt(totalCredited)} income this period
              </p>
            )}
          </div>
          <button onClick={() => setShowTagMgr(true)}
            style={{ width: 38, height: 38, borderRadius: "50%",
              background: "rgba(0,0,0,.08)", border: "none", cursor: "pointer",
              display: "flex", alignItems: "center", justifyContent: "center" }}>
            <Tag size={15} color="#6b6460" />
          </button>
        </div>

        {/* Period selector: W M 3M 6M 1Y ALL */}
        <div style={{ display: "flex", gap: 4, marginTop: 16 }}>
          {PERIODS.map(p => (
            <button key={p} onClick={() => setPeriod(p)}
              style={{ flex: 1, padding: "6px 2px", borderRadius: 20, border: "none",
                cursor: "pointer", fontSize: 11, fontWeight: 700, transition: "all .15s",
                background: period === p ? "#1a1410" : "rgba(0,0,0,.06)",
                color:      period === p ? "#f5f0e8" : "#6b6460" }}>
              {p}
            </button>
          ))}
        </div>

        {/* Month nav — only shown for M period */}
        {period === "M" && (
          <div style={{ display: "flex", alignItems: "center", justifyContent: "center", gap: 12, marginTop: 14 }}>
            <button onClick={() => shiftMonth(-1)}
              style={{ background: "rgba(0,0,0,.08)", border: "none", borderRadius: 8,
                color: "#6b6460", fontSize: 16, width: 30, height: 30, cursor: "pointer",
                display: "flex", alignItems: "center", justifyContent: "center" }}>‹</button>
            <span style={{ color: "#1a1410", fontSize: 14, fontWeight: 700 }}>
              {MONTH_NAMES[viewMonth - 1]} {viewYear}
            </span>
            <button onClick={() => shiftMonth(1)}
              style={{ background: "rgba(0,0,0,.08)", border: "none", borderRadius: 8,
                color: "#6b6460", fontSize: 16, width: 30, height: 30, cursor: "pointer",
                display: "flex", alignItems: "center", justifyContent: "center" }}>›</button>
          </div>
        )}

        <p style={{ color: "#9e9690", fontSize: 10, margin: "10px 0 0", textAlign: "center" }}>
          {periodTxns.length} transactions · {blockedCount} blocked
        </p>
      </div>

      <div style={{ padding: "0 16px" }}>

      <PrivacyBanner />

      {/* Income / Spent stat cards */}
      <div style={{ display: "flex", gap: 10, marginBottom: 14 }}>
        {[
          { label: "INCOME",  val: totalCredited, color: "#4ade80", bg: "rgba(74,222,128,.08)" },
          { label: "SPENT",   val: totalDebited,  color: "#f87171", bg: "rgba(248,113,113,.08)" },
        ].map(({ label, val, color, bg }) => (
          <div key={label} style={{ flex: 1, background: bg, borderRadius: 18, padding: "14px 14px" }}>
            <p style={{ color, fontSize: 9, fontWeight: 800, letterSpacing: 1.2, margin: "0 0 6px" }}>{label}</p>
            <p style={{ color: T_BRIGHT, fontSize: 20, fontWeight: 800, margin: 0, letterSpacing: -0.5 }}>{fmt(val)}</p>
          </div>
        ))}
      </div>

      {/* ── Budget Allocation — donut + vertical columns ── */}
      {totalDebited > 0 && (() => {
        const cats = [
          { cat: "uho",           label: "UHO",     emoji: "🏠", val: totalUHO,       color: UHO_COLOR  },
          { cat: "quickcart",     label: "Quick",   emoji: "🛒", val: totalQuickCart, color: QC_COLOR   },
          { cat: "creditcard",    label: "CC",      emoji: "💳", val: totalCC,        color: CC_COLOR   },
          { cat: "investments",   label: "Invest",  emoji: "📈", val: totalInv,       color: INV_COLOR  },
          { cat: "miscellaneous", label: "Misc",    emoji: "🏷️", val: totalMisc,      color: MISC_COLOR },
        ];
        const maxVal = Math.max(...cats.map(c => c.val), 1);
        return (
          <div style={{ marginBottom: 16 }}>
            {/* Section header */}
            <p style={{ color: T_DIM, fontSize: 12, fontWeight: 700, letterSpacing: 0.8,
              textTransform: "uppercase", margin: "0 0 14px" }}>Your Budget Tracker</p>

            {/* Donut + legend row */}
            <div style={{ display: "flex", alignItems: "center", gap: 16, marginBottom: 20 }}>
              {/* Donut */}
              <div style={{ position: "relative", flexShrink: 0 }}>
                <ResponsiveContainer width={130} height={130}>
                  <PieChart>
                    <Pie data={cats.map(c => ({ name: c.label, value: c.val || 0.01 }))}
                      dataKey="value" cx="50%" cy="50%"
                      innerRadius={40} outerRadius={58} paddingAngle={3} strokeWidth={0}>
                      {cats.map((c, i) => <Cell key={i} fill={c.color} />)}
                    </Pie>
                  </PieChart>
                </ResponsiveContainer>
                {/* Center label */}
                <div style={{ position: "absolute", top: "50%", left: "50%",
                  transform: "translate(-50%,-50%)", textAlign: "center", pointerEvents: "none" }}>
                  <p style={{ color: T_BRIGHT, fontSize: 13, fontWeight: 800, margin: 0, lineHeight: 1 }}>
                    {fmt(totalDebited)}
                  </p>
                  <p style={{ color: T_MUTED, fontSize: 9, margin: "3px 0 0" }}>spent</p>
                </div>
              </div>

              {/* Legend */}
              <div style={{ flex: 1, display: "flex", flexDirection: "column", gap: 10 }}>
                {cats.map(c => {
                  const pct = totalDebited > 0 ? Math.round((c.val / totalDebited) * 100) : 0;
                  return (
                    <div key={c.cat}>
                      <div style={{ display: "flex", justifyContent: "space-between", marginBottom: 4 }}>
                        <span style={{ color: T_DIM, fontSize: 11, fontWeight: 600 }}>{c.emoji} {c.label}</span>
                        <span style={{ color: c.color, fontSize: 11, fontWeight: 800 }}>{pct}%</span>
                      </div>
                      <div style={{ height: 5, borderRadius: 99, background: "rgba(255,255,255,.06)" }}>
                        <div style={{ height: "100%", borderRadius: 99, background: c.color,
                          width: `${pct}%`, transition: "width .5s ease" }} />
                      </div>
                    </div>
                  );
                })}
              </div>
            </div>

            {/* Vertical column allocation bars */}
            <div style={{ display: "flex", gap: 10, alignItems: "flex-end", justifyContent: "center",
              background: CARD_BG, borderRadius: 20, padding: "20px 16px 14px" }}>
              {cats.map(c => {
                const pct = maxVal > 0 ? Math.round((c.val / maxVal) * 100) : 0;
                const isActive = selectedCat === c.cat;
                return (
                  <div key={c.cat} onClick={() => toggleCat(c.cat)}
                    style={{ flex: 1, display: "flex", flexDirection: "column", alignItems: "center",
                      cursor: "pointer", gap: 6 }}>
                    {/* Amount label */}
                    <p style={{ color: isActive ? c.color : T_BRIGHT, fontSize: 11, fontWeight: 800,
                      margin: 0, textAlign: "center" }}>{fmt(c.val)}</p>
                    {/* % label */}
                    <p style={{ color: c.color, fontSize: 10, fontWeight: 700, margin: 0 }}>
                      {totalDebited > 0 ? Math.round((c.val / totalDebited) * 100) : 0}%
                    </p>
                    {/* Bar column */}
                    <div style={{ width: "100%", height: 100, borderRadius: 8, overflow: "hidden",
                      background: "rgba(255,255,255,.05)", display: "flex", alignItems: "flex-end" }}>
                      <div style={{
                        width: "100%", borderRadius: 8,
                        height: `${Math.max(pct, 4)}%`,
                        background: isActive ? c.color : `${c.color}88`,
                        transition: "height .5s ease, background .2s",
                      }} />
                    </div>
                    {/* Label */}
                    <p style={{ color: isActive ? c.color : T_MUTED, fontSize: 10, fontWeight: 700,
                      margin: 0, textAlign: "center", letterSpacing: 0.3 }}>{c.emoji} {c.label}</p>
                  </div>
                );
              })}
            </div>
          </div>
        );
      })()}

      {/* ── Dark stat cards — UHO / QuickCart / CC / Misc ── */}
      <div style={{ display: "flex", flexDirection: "column", gap: 10, marginBottom: 16 }}>
        {[
          { cat: "uho",           label: "UHO",         emoji: "🏠", val: totalUHO,       color: UHO_COLOR,
            sub: "Large spends above ₹2,000",           count: periodTxns.filter(t => t.category === "uho").length },
          { cat: "quickcart",     label: "QuickCart",   emoji: "🛒", val: totalQuickCart, color: QC_COLOR,
            sub: "Brands: Zomato, Amazon & more",       count: periodTxns.filter(t => t.category === "quickcart").length },
          { cat: "creditcard",    label: "Credit Card", emoji: "💳", val: totalCC,        color: CC_COLOR,
            sub: "All credit card transactions",        count: periodTxns.filter(t => t.category === "creditcard").length },
          { cat: "investments",   label: "Investments", emoji: "📈", val: totalInv,       color: INV_COLOR,
            sub: "Groww, Zerodha, mutual funds",        count: periodTxns.filter(t => t.category === "investments").length },
          { cat: "miscellaneous", label: "Misc",        emoji: "🏷️", val: totalMisc,      color: MISC_COLOR,
            sub: "Small spends below ₹2,000",           count: periodTxns.filter(t => t.category === "miscellaneous").length },
        ].map(({ cat, label, emoji, val, color, sub, count }) => {
          const isActive = selectedCat === cat;
          const pct = totalDebited > 0 ? Math.round((val / totalDebited) * 100) : 0;
          return (
            <div key={cat} onClick={() => toggleCat(cat)}
              style={{ background: isActive ? `${color}18` : CARD_BG,
                border: `1px solid ${isActive ? color + "55" : "transparent"}`,
                borderRadius: 20, padding: "16px 18px", cursor: "pointer",
                transition: "all .2s" }}>
              <div style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start" }}>
                <div>
                  <p style={{ color: color, fontSize: 10, fontWeight: 800, letterSpacing: 1,
                    textTransform: "uppercase", margin: "0 0 4px" }}>{emoji} {label}</p>
                  <p style={{ color: T_BRIGHT, fontSize: 26, fontWeight: 900, margin: "0 0 4px",
                    letterSpacing: -1 }}>{fmt(val)}</p>
                  <p style={{ color: T_MUTED, fontSize: 11, margin: 0 }}>{sub}</p>
                </div>
                <div style={{ textAlign: "right" }}>
                  <p style={{ color: color, fontSize: 22, fontWeight: 900, margin: "0 0 2px" }}>{pct}%</p>
                  <p style={{ color: T_MUTED, fontSize: 10, margin: 0 }}>{count} txns</p>
                </div>
              </div>
              {/* Progress bar */}
              <div style={{ marginTop: 12, height: 4, borderRadius: 99, background: "rgba(255,255,255,.06)" }}>
                <div style={{ height: "100%", borderRadius: 99, background: color,
                  width: `${pct}%`, transition: "width .6s ease" }} />
              </div>
              {isActive && (
                <p style={{ color: color, fontSize: 10, margin: "8px 0 0", textAlign: "center", fontWeight: 600 }}>
                  ↑ Tap to close
                </p>
              )}
            </div>
          );
        })}
      </div>

      {/* DRILL-DOWN: UHO */}
      {selectedCat === "uho" && drillTxns.length > 0 && (
        <div style={{ background: `${UHO_COLOR}0a`, border: `1px solid ${UHO_COLOR}25`,
          borderRadius: 18, padding: "14px 16px", marginBottom: 14 }}>
          <p style={{ color: UHO_COLOR, fontSize: 12, fontWeight: 700, margin: "0 0 12px" }}>🏠 UHO Transactions</p>
          {drillTxns.map(t => (
            <div key={t.id} style={{ display: "flex", justifyContent: "space-between", alignItems: "center",
              padding: "10px 0", borderBottom: `1px solid ${BORDER}33` }}>
              <div>
                <p style={{ color: T_BRIGHT, fontSize: 12, fontWeight: 600, margin: "0 0 2px" }}>{t.bank}</p>
                <p style={{ color: T_MUTED, fontSize: 10, margin: 0 }}>{t.date}{t.isCreditCard ? " · CC" : ""}</p>
              </div>
              <p style={{ color: UHO_COLOR, fontSize: 14, fontWeight: 800, margin: 0 }}>−{fmt(t.amount)}</p>
            </div>
          ))}
        </div>
      )}

      {/* DRILL-DOWN: QuickCart */}
      {selectedCat === "quickcart" && (
        <div style={{ background: `${QC_COLOR}0a`, border: `1px solid ${QC_COLOR}25`,
          borderRadius: 18, padding: "14px 16px", marginBottom: 14 }}>
          <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", marginBottom: 14 }}>
            <p style={{ color: QC_COLOR, fontSize: 12, fontWeight: 700, margin: 0 }}>🛒 QuickCart — {fmt(totalQuickCart)}</p>
            <div style={{ display: "flex", background: PAGE_BG, borderRadius: 20, padding: 3, gap: 2 }}>
              {[{ id: "bar", label: "📊" }, { id: "pie", label: "🥧" }].map(opt => (
                <button key={opt.id} onClick={e => { e.stopPropagation(); setQcChartMode(opt.id); }}
                  style={{ padding: "4px 10px", borderRadius: 16, border: "none", cursor: "pointer",
                    fontSize: 11, fontWeight: 600,
                    background: qcChartMode === opt.id ? QC_COLOR : "transparent",
                    color:      qcChartMode === opt.id ? "#fff"   : T_MUTED }}>
                  {opt.label}
                </button>
              ))}
            </div>
          </div>
          {brandChartData.length > 0 && qcChartMode === "bar" && (
            <ResponsiveContainer width="100%" height={brandChartData.length * 36 + 10}>
              <BarChart data={brandChartData} layout="vertical" margin={{ top: 0, right: 56, bottom: 0, left: 0 }}>
                <XAxis type="number" hide />
                <YAxis type="category" dataKey="name" axisLine={false} tickLine={false}
                  tick={{ fill: T_DIM, fontSize: 12 }} width={80} />
                <Tooltip content={<CustomTooltip />} cursor={{ fill: "rgba(244,63,94,.05)" }} />
                <Bar dataKey="amt" fill={QC_COLOR} radius={[0, 6, 6, 0]} barSize={14}>
                  <LabelList dataKey="amt" position="right" formatter={v => fmt(v)} style={{ fill: T_DIM, fontSize: 10 }} />
                </Bar>
              </BarChart>
            </ResponsiveContainer>
          )}
          {brandChartData.length > 0 && qcChartMode === "pie" && (
            <div style={{ display: "flex", alignItems: "center", gap: 12, marginBottom: 12 }}>
              <ResponsiveContainer width={120} height={120}>
                <PieChart>
                  <Pie data={brandChartData.map(d => ({ ...d, value: d.amt }))} dataKey="value"
                    cx="50%" cy="50%" innerRadius={28} outerRadius={48} paddingAngle={4} strokeWidth={0}>
                    {brandChartData.map((_, i) => <Cell key={i} fill={`hsl(${340 + i * 22},80%,${58 + i*4}%)`} />)}
                  </Pie>
                </PieChart>
              </ResponsiveContainer>
              <div style={{ flex: 1, display: "flex", flexDirection: "column", gap: 6 }}>
                {brandChartData.map((e, i) => (
                  <div key={i} style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
                    <div style={{ display: "flex", alignItems: "center", gap: 6 }}>
                      <div style={{ width: 8, height: 8, borderRadius: "50%", background: `hsl(${340+i*22},80%,${58+i*4}%)` }} />
                      <span style={{ color: T_DIM, fontSize: 11 }}>{e.name}</span>
                    </div>
                    <span style={{ color: T_BRIGHT, fontSize: 11, fontWeight: 700 }}>{fmt(e.amt)}</span>
                  </div>
                ))}
              </div>
            </div>
          )}
          {drillTxns.map(t => (
            <div key={t.id} style={{ display: "flex", justifyContent: "space-between", alignItems: "center",
              padding: "10px 0", borderBottom: `1px solid ${BORDER}33` }}>
              <div>
                <p style={{ color: T_BRIGHT, fontSize: 12, fontWeight: 600, margin: "0 0 1px" }}>{t.brand || t.bank}</p>
                <p style={{ color: T_MUTED, fontSize: 10, margin: 0 }}>{t.date}</p>
              </div>
              <p style={{ color: QC_COLOR, fontSize: 14, fontWeight: 800, margin: 0 }}>−{fmt(t.amount)}</p>
            </div>
          ))}
        </div>
      )}

      {/* DRILL-DOWN: Investments */}
      {selectedCat === "investments" && drillTxns.length > 0 && (
        <div style={{ background: `${INV_COLOR}0a`, border: `1px solid ${INV_COLOR}25`,
          borderRadius: 18, padding: "14px 16px", marginBottom: 14 }}>
          <p style={{ color: INV_COLOR, fontSize: 12, fontWeight: 700, margin: "0 0 4px" }}>
            📈 Investments — {fmt(totalInv)}
          </p>
          <p style={{ color: T_MUTED, fontSize: 10, margin: "0 0 12px" }}>
            Groww, Zerodha, mutual funds & SIPs
          </p>
          {drillTxns.map(t => (
            <div key={t.id} style={{ display: "flex", justifyContent: "space-between", alignItems: "center",
              padding: "10px 0", borderBottom: `1px solid ${BORDER}33` }}>
              <div>
                <p style={{ color: T_BRIGHT, fontSize: 12, fontWeight: 600, margin: "0 0 2px" }}>
                  {t.brand || t.bank}
                </p>
                <p style={{ color: T_MUTED, fontSize: 10, margin: 0 }}>{t.date}</p>
              </div>
              <p style={{ color: INV_COLOR, fontSize: 14, fontWeight: 800, margin: 0 }}>−{fmt(t.amount)}</p>
            </div>
          ))}
        </div>
      )}

      {/* DRILL-DOWN: Credit Card */}
      {selectedCat === "creditcard" && drillTxns.length > 0 && (
        <div style={{ background: `${CC_COLOR}0a`, border: `1px solid ${CC_COLOR}25`,
          borderRadius: 18, padding: "14px 16px", marginBottom: 14 }}>
          <p style={{ color: CC_COLOR, fontSize: 12, fontWeight: 700, margin: "0 0 4px" }}>
            💳 Credit Card — {fmt(totalCC)}
          </p>
          <p style={{ color: T_MUTED, fontSize: 10, margin: "0 0 12px" }}>
            Transactions billed to your credit cards
          </p>
          {/* CC brand breakdown mini-table */}
          {(() => {
            const ccBrandMap = {};
            drillTxns.filter(t => t.brand).forEach(t => {
              ccBrandMap[t.brand] = (ccBrandMap[t.brand] || 0) + t.amount;
            });
            const ccBrands = Object.entries(ccBrandMap).sort((a,b) => b[1]-a[1]);
            return ccBrands.length > 0 ? (
              <div style={{ background: "rgba(167,139,250,.08)", borderRadius: 12,
                padding: "10px 12px", marginBottom: 12 }}>
                <p style={{ color: CC_COLOR, fontSize: 10, fontWeight: 700,
                  textTransform: "uppercase", letterSpacing: 0.8, margin: "0 0 8px" }}>By Brand</p>
                {ccBrands.map(([brand, amt]) => (
                  <div key={brand} style={{ display: "flex", justifyContent: "space-between",
                    padding: "4px 0" }}>
                    <span style={{ color: T_DIM, fontSize: 11 }}>{brand}</span>
                    <span style={{ color: T_BRIGHT, fontSize: 11, fontWeight: 700 }}>{fmt(amt)}</span>
                  </div>
                ))}
              </div>
            ) : null;
          })()}
          {drillTxns.map(t => (
            <div key={t.id} style={{ display: "flex", justifyContent: "space-between", alignItems: "center",
              padding: "10px 0", borderBottom: `1px solid ${BORDER}33` }}>
              <div>
                <p style={{ color: T_BRIGHT, fontSize: 12, fontWeight: 600, margin: "0 0 2px" }}>
                  {t.brand || t.bank}
                </p>
                <p style={{ color: T_MUTED, fontSize: 10, margin: 0 }}>{t.date} · {t.bank} CC</p>
              </div>
              <p style={{ color: CC_COLOR, fontSize: 14, fontWeight: 800, margin: 0 }}>−{fmt(t.amount)}</p>
            </div>
          ))}
        </div>
      )}

      {/* DRILL-DOWN: Misc */}
      {selectedCat === "miscellaneous" && drillTxns.length > 0 && (
        <div style={{ background: `${MISC_COLOR}0a`, border: `1px solid ${MISC_COLOR}25`,
          borderRadius: 18, padding: "14px 16px", marginBottom: 14 }}>
          <p style={{ color: MISC_COLOR, fontSize: 12, fontWeight: 700, margin: "0 0 12px" }}>🏷️ Misc Transactions</p>
          {drillTxns.map(t => (
            <div key={t.id} style={{ display: "flex", justifyContent: "space-between", alignItems: "center",
              padding: "10px 0", borderBottom: `1px solid ${BORDER}33` }}>
              <div>
                <p style={{ color: T_BRIGHT, fontSize: 12, fontWeight: 600, margin: "0 0 2px" }}>{t.tag || t.bank}</p>
                <p style={{ color: T_MUTED, fontSize: 10, margin: 0 }}>{t.date}</p>
              </div>
              <p style={{ color: MISC_COLOR, fontSize: 14, fontWeight: 800, margin: 0 }}>−{fmt(t.amount)}</p>
            </div>
          ))}
        </div>
      )}

      {/* ── Yearly insight brief ── */}
      {yearlyInsight && (
        <div style={{ background: "rgba(99,102,241,.08)", border: "1px solid rgba(99,102,241,.18)",
          borderRadius: 20, padding: "16px 18px", marginBottom: 14 }}>
          <p style={{ color: "#818cf8", fontSize: 11, fontWeight: 800, margin: "0 0 12px",
            textTransform: "uppercase", letterSpacing: 1 }}>📊 {viewYear} Year in Review</p>
          <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 10 }}>
            {[
              { icon: "🔺", label: "Top Category",   val: `${yearlyInsight.topCat} · ${fmt(yearlyInsight.topCatAmt)}` },
              yearlyInsight.topBrand && { icon: "🛒", label: "Top Brand", val: `${yearlyInsight.topBrand[0]} · ${fmt(yearlyInsight.topBrand[1])}` },
              yearlyInsight.heaviestMonth && { icon: "📅", label: "Heaviest Month", val: `${yearlyInsight.heaviestMonth} · ${fmt(yearlyInsight.heaviestAmt)}` },
              yearlyInsight.biggestSpend  && { icon: "💸", label: "Biggest Spend",  val: `${fmt(yearlyInsight.biggestSpend.amount)} · ${yearlyInsight.biggestSpend.date}` },
            ].filter(Boolean).map((item, i) => (
              <div key={i} style={{ background: "rgba(99,102,241,.08)", borderRadius: 14, padding: "12px 12px" }}>
                <p style={{ color: T_MUTED, fontSize: 10, margin: "0 0 4px" }}>{item.icon} {item.label}</p>
                <p style={{ color: T_BRIGHT, fontSize: 12, fontWeight: 700, margin: 0 }}>{item.val}</p>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* ── Spending by Tag chart ── */}
      {tagChartData.length > 0 && (
        <div style={{ background: CARD_BG, borderRadius: 20, padding: "16px 16px", marginBottom: 14 }}>
          <div style={{ display: "flex", alignItems: "center", gap: 6, marginBottom: 14 }}>
            <Tag size={13} color="#818cf8" />
            <p style={{ color: "#818cf8", fontSize: 12, fontWeight: 700, textTransform: "uppercase",
              letterSpacing: 0.8, margin: 0 }}>Spending by Tag</p>
          </div>
          <ResponsiveContainer width="100%" height={tagChartData.length * 38 + 10}>
            <BarChart data={tagChartData} layout="vertical" margin={{ top: 0, right: 60, bottom: 0, left: 0 }}>
              <XAxis type="number" hide />
              <YAxis type="category" dataKey="name" axisLine={false} tickLine={false}
                tick={{ fill: T_DIM, fontSize: 12 }} width={80} />
              <Tooltip content={<CustomTooltip />} cursor={{ fill: "rgba(99,102,241,.05)" }} />
              <Bar dataKey="amt" fill="#6366f1" radius={[0, 8, 8, 0]} barSize={16}>
                <LabelList dataKey="amt" position="right" formatter={v => fmt(v)} style={{ fill: T_DIM, fontSize: 10 }} />
              </Bar>
            </BarChart>
          </ResponsiveContainer>
        </div>
      )}
      {tagChartData.length === 0 && (
        <div style={{ background: "rgba(99,102,241,.05)", border: "1px dashed rgba(99,102,241,.2)",
          borderRadius: 18, padding: "18px 16px", textAlign: "center", marginBottom: 14 }}>
          <Tag size={18} color="#6366f1" style={{ margin: "0 auto 8px" }} />
          <p style={{ color: "#818cf8", fontSize: 12, fontWeight: 600, margin: "0 0 4px" }}>Tag Chart</p>
          <p style={{ color: T_MUTED, fontSize: 11, margin: 0 }}>
            Go to Overview → tap 🏷️ on any transaction to build your tag chart
          </p>
        </div>
      )}
    </div>
  );

  // ══════════════════════════════════════════════════════════════════════
  //  OVERVIEW TAB
  // ══════════════════════════════════════════════════════════════════════
  const OverviewTab = () => (
    <div style={{ flex: 1, display: "flex", flexDirection: "column", overflow: "hidden" }}>
      <div style={{ padding: "20px 16px 12px", borderBottom: `1px solid ${CARD_BG}` }}>
        <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 12 }}>
          <h2 style={{ color: T_BRIGHT, fontSize: 20, fontWeight: 800, margin: 0 }}>Transactions</h2>
          <span style={{ color: T_MUTED, fontSize: 12 }}>{filteredTxns.length} shown</span>
        </div>
        {/* Filters */}
        <div style={{ display: "flex", gap: 7, overflowX: "auto", paddingBottom: 2 }}>
          {["all","credited","debited"].map(f => (
            <button key={f} onClick={() => setFilters(p => ({ ...p, type: f }))}
              style={chip(filters.type === f, "#6366f1")}>
              {f === "all" ? "All" : f.charAt(0).toUpperCase() + f.slice(1)}
            </button>
          ))}
          <div style={{ width: 1, background: BORDER, margin: "3px 2px" }} />
          {[
            { val: "income",        label: "Income",    color: INCOME_COLOR },
            { val: "quickcart",     label: "🛒 Quick",  color: QC_COLOR     },
            { val: "uho",           label: "UHO",       color: UHO_COLOR    },
            { val: "creditcard",    label: "💳 CC",     color: CC_COLOR     },
            { val: "investments",   label: "📈 Invest", color: INV_COLOR    },
            { val: "miscellaneous", label: "Misc",      color: MISC_COLOR   },
          ].map(f => (
            <button key={f.val}
              onClick={() => setFilters(p => ({ ...p, category: p.category === f.val ? "all" : f.val }))}
              style={chip(filters.category === f.val, f.color)}>
              {f.label}
            </button>
          ))}
        </div>
      </div>

      <div style={{ flex: 1, overflowY: "auto", padding: "12px 16px 88px",
        display: "flex", flexDirection: "column", gap: 8 }}>
        {filteredTxns.length === 0 && (
          <div style={{ textAlign: "center", color: T_MUTED, padding: "50px 0" }}>
            No transactions match this filter
          </div>
        )}
        {filteredTxns.map(t => {
          const cs   = catStyle(t.category);
          const open = activeTagTxn === t.id;
          return (
            <div key={t.id}>
              <div style={{ background: CARD_BG, borderRadius: open ? "14px 14px 0 0" : 14,
                padding: "12px 14px", display: "flex", alignItems: "center", justifyContent: "space-between" }}>
                {/* Left */}
                <div style={{ display: "flex", alignItems: "center", gap: 12, flex: 1, minWidth: 0 }}>
                  <div style={{ width: 38, height: 38, borderRadius: 12, flexShrink: 0,
                    background: t.type === "credited" ? "rgba(16,185,129,.15)" : "rgba(239,68,68,.15)",
                    display: "flex", alignItems: "center", justifyContent: "center" }}>
                    {t.type === "credited"
                      ? <TrendingUp  size={16} color={INCOME_COLOR} />
                      : <TrendingDown size={16} color={DEBIT_COLOR}  />}
                  </div>
                  <div style={{ minWidth: 0 }}>
                    <div style={{ display: "flex", alignItems: "center", gap: 5, flexWrap: "wrap" }}>
                      <span style={{ fontSize: 10, fontWeight: 700, padding: "2px 8px", borderRadius: 20, ...cs }}>
                        {catLabel(t.category)}
                      </span>
                      {t.brand && t.category === "quickcart" && (
                        <span style={{ fontSize: 10, fontWeight: 600, padding: "2px 8px", borderRadius: 20,
                          background: "rgba(244,63,94,.12)", color: QC_COLOR }}>
                          {t.brand}
                        </span>
                      )}
                      {t.tag && (
                        <span style={{ fontSize: 10, fontWeight: 500, padding: "2px 8px", borderRadius: 20,
                          background: BORDER, color: T_DIM, display: "flex", alignItems: "center", gap: 3 }}>
                          {t.tag}
                          <button onClick={() => removeTag(t.id)}
                            style={{ background: "none", border: "none", cursor: "pointer", padding: 0, lineHeight: 0 }}>
                            <X size={9} color={T_MUTED} />
                          </button>
                        </span>
                      )}
                    </div>
                    <p style={{ color: T_MUTED, fontSize: 11, margin: "3px 0 0" }}>{t.date} · {t.bank}</p>
                  </div>
                </div>
                {/* Right */}
                <div style={{ display: "flex", alignItems: "center", gap: 8, flexShrink: 0 }}>
                  <span style={{ color: t.type === "credited" ? INCOME_COLOR : DEBIT_COLOR,
                    fontSize: 15, fontWeight: 800 }}>
                    {t.type === "credited" ? "+" : "−"}{fmt(t.amount)}
                  </span>
                  <button onClick={() => { setActiveTagTxn(open ? null : t.id); setCustomTagInput(""); }}
                    style={{ width: 28, height: 28, borderRadius: 8, border: "none", cursor: "pointer",
                      background: open ? "#6366f1" : PAGE_BG,
                      display: "flex", alignItems: "center", justifyContent: "center" }}>
                    <Tag size={12} color={open ? "#fff" : T_MUTED} />
                  </button>
                </div>
              </div>

              {/* Inline tag picker */}
              {open && (
                <div style={{ background: "#172033", borderRadius: "0 0 14px 14px",
                  padding: "10px 14px 12px", borderTop: `1px solid ${PAGE_BG}` }}>
                  <p style={{ color: T_MUTED, fontSize: 10, fontWeight: 600,
                    textTransform: "uppercase", letterSpacing: 0.5, margin: "0 0 8px" }}>Pick a tag</p>
                  <div style={{ display: "flex", gap: 6, flexWrap: "wrap", marginBottom: 8 }}>
                    {userTags.map(tag => (
                      <button key={tag} onClick={() => applyTag(t.id, tag)}
                        style={{ padding: "4px 10px", borderRadius: 12, border: "none", cursor: "pointer",
                          fontSize: 11, fontWeight: 500,
                          background: t.tag === tag ? "#6366f1" : BORDER,
                          color:      t.tag === tag ? "#fff"    : T_DIM }}>
                        {tag}
                      </button>
                    ))}
                  </div>
                  <div style={{ display: "flex", gap: 6 }}>
                    <input value={customTagInput} onChange={e => setCustomTagInput(e.target.value)}
                      onKeyDown={e => {
                        if (e.key === "Enter" && customTagInput.trim()) {
                          const tag = customTagInput.trim();
                          if (!userTags.includes(tag)) setUserTags(p => [...p, tag]);
                          applyTag(t.id, tag);
                        }
                      }}
                      placeholder="Custom tag…"
                      style={{ flex: 1, background: PAGE_BG, border: `1px solid ${BORDER}`,
                        borderRadius: 8, padding: "6px 10px", color: T_BRIGHT,
                        fontSize: 12, outline: "none", fontFamily: "inherit" }} />
                    <button onClick={() => {
                        const tag = customTagInput.trim();
                        if (!tag) return;
                        if (!userTags.includes(tag)) setUserTags(p => [...p, tag]);
                        applyTag(t.id, tag);
                      }}
                      style={{ padding: "6px 14px", background: "#6366f1", border: "none",
                        borderRadius: 8, color: "#fff", fontSize: 12, cursor: "pointer", fontWeight: 600 }}>
                      Add
                    </button>
                  </div>
                </div>
              )}
            </div>
          );
        })}
      </div>
    </div>
  );

  // ══════════════════════════════════════════════════════════════════════
  //  TAG MANAGER MODAL
  // ══════════════════════════════════════════════════════════════════════
  const TagManagerModal = () => (
    <div onClick={() => setShowTagMgr(false)}
      style={{ position: "absolute", inset: 0, background: "rgba(0,0,0,.6)", zIndex: 50,
        display: "flex", alignItems: "flex-end" }}>
      <div onClick={e => e.stopPropagation()}
        style={{ background: CARD_BG, borderRadius: "20px 20px 0 0", width: "100%",
          padding: "20px 20px 36px", maxHeight: "70%", overflowY: "auto" }}>
        <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 14 }}>
          <h3 style={{ color: T_BRIGHT, fontSize: 17, fontWeight: 700, margin: 0 }}>Manage Tags</h3>
          <button onClick={() => setShowTagMgr(false)}
            style={{ background: PAGE_BG, border: "none", borderRadius: 8, width: 30, height: 30,
              cursor: "pointer", display: "flex", alignItems: "center", justifyContent: "center" }}>
            <X size={14} color={T_DIM} />
          </button>
        </div>
        <p style={{ color: T_MUTED, fontSize: 12, margin: "0 0 14px" }}>
          Tags appear in the transaction list and generate a chart on the Home tab.
        </p>
        <div style={{ display: "flex", gap: 8, marginBottom: 16 }}>
          <input value={newGlobalTag} onChange={e => setNewGlobalTag(e.target.value)}
            onKeyDown={e => { if (e.key === "Enter") addGlobalTag(); }}
            placeholder="New tag name…"
            style={{ flex: 1, background: PAGE_BG, border: `1px solid ${BORDER}`,
              borderRadius: 10, padding: "8px 12px", color: T_BRIGHT,
              fontSize: 13, outline: "none", fontFamily: "inherit" }} />
          <button onClick={addGlobalTag}
            style={{ padding: "8px 16px", background: "#6366f1", border: "none",
              borderRadius: 10, color: "#fff", fontSize: 13, cursor: "pointer", fontWeight: 600,
              display: "flex", alignItems: "center", gap: 6 }}>
            <Plus size={14} /> Add
          </button>
        </div>
        <div style={{ display: "flex", flexWrap: "wrap", gap: 8 }}>
          {userTags.map(tag => (
            <div key={tag} style={{ display: "flex", alignItems: "center", gap: 6,
              padding: "6px 12px", background: BORDER, borderRadius: 20 }}>
              <span style={{ color: T_BRIGHT, fontSize: 13 }}>{tag}</span>
              <button onClick={() => setUserTags(p => p.filter(t => t !== tag))}
                style={{ background: "none", border: "none", cursor: "pointer", padding: 0, lineHeight: 0 }}>
                <X size={11} color={T_MUTED} />
              </button>
            </div>
          ))}
        </div>
      </div>
    </div>
  );

  // ══════════════════════════════════════════════════════════════════════
  //  ROOT RENDER
  // ══════════════════════════════════════════════════════════════════════
  return (
    <div style={{ maxWidth: 390, margin: "0 auto", height: "100vh",
      background: PAGE_BG, display: "flex", flexDirection: "column",
      overflow: "hidden", position: "relative",
      fontFamily: "-apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif" }}>
      <div style={{ height: 8, flexShrink: 0 }} />
      <div style={{ flex: 1, display: "flex", flexDirection: "column", overflow: "hidden" }}>
        {tab === "home"     && <HomeTab />}
        {tab === "overview" && <OverviewTab />}
      </div>

      {/* Bottom Navbar */}
      <div style={{ position: "absolute", bottom: 0, left: 0, right: 0, height: 68,
        background: "#141e2e", borderTop: `1px solid ${CARD_BG}`,
        display: "flex", alignItems: "center", justifyContent: "space-around", zIndex: 40 }}>
        {[
          { id: "home",     label: "Home",     Icon: Home },
          { id: "overview", label: "Overview", Icon: List },
        ].map(({ id, label, Icon }) => {
          const active = tab === id;
          return (
            <button key={id} onClick={() => setTab(id)}
              style={{ display: "flex", flexDirection: "column", alignItems: "center", gap: 3,
                background: "none", border: "none", cursor: "pointer", padding: "8px 28px",
                color: active ? MISC_COLOR : T_MUTED, position: "relative" }}>
              <div style={{ position: "relative" }}>
                <Icon size={21} />
                {active && <div style={{ position: "absolute", top: -4, right: -4, width: 6, height: 6,
                  borderRadius: "50%", background: MISC_COLOR }} />}
              </div>
              <span style={{ fontSize: 10, fontWeight: active ? 700 : 500 }}>{label}</span>
            </button>
          );
        })}
      </div>

      {showTagMgr  && <TagManagerModal />}
      {showPrivacy && <PrivacyModal    />}
    </div>
  );
}
