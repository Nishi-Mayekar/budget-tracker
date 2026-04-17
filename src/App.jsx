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

import { useState, useMemo } from "react";
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
  if (!(/₹[\s\d,]/.test(raw))) return false;
  if (!(/\b(credited|debited)\b/i.test(raw))) return false;
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

/** Builds one combined regex for all brands (case-insensitive word-boundary match) */
const BRAND_REGEX = new RegExp(
  QUICKCART_BRANDS.map(b => `\\b${b.replace(/[-\s]/g, "[\\s-]?")}\\b`).join("|"),
  "i"
);

function detectBrand(raw) {
  const match = raw.match(BRAND_REGEX);
  return match ? match[0] : null;
}

// ── Secure parser ───────────────────────────────────────────────────────
function secureExtract(raw) {
  const amtMatch = raw.match(/₹\s*([\d,]+(?:\.\d{1,2})?)/);
  if (!amtMatch) return null;
  const amount = Math.round(parseFloat(amtMatch[1].replace(/,/g, "")) * 100) / 100;
  if (!isFinite(amount) || amount <= 0) return null;

  const type   = /\bcredited\b/i.test(raw) ? "credited" : "debited";
  const brand  = detectBrand(raw);  // null if no known brand found

  // Category logic:
  //   credited           → income
  //   known QC brand     → quickcart  (regardless of amount)
  //   debit > 2000       → uho
  //   debit ≤ 2000       → miscellaneous
  let category;
  if      (type === "credited") category = "income";
  else if (brand)               category = "quickcart";
  else if (amount > 2000)       category = "uho";
  else                          category = "miscellaneous";

  return { amount, type, category, brand };
}

function processSMS(sms) {
  if (!isTransactionMessage(sms.raw)) return null;
  const parsed = secureExtract(sms.raw);
  if (!parsed) return null;
  return { id: sms.id, date: sms.date, bank: sms.bank, ...parsed, tag: null };
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
  income: "Income", uho: "UHO", miscellaneous: "Misc", quickcart: "QuickCart"
}[c] || c);

const catStyle = c => ({
  income:        { color: INCOME_COLOR, background: "rgba(16,185,129,.15)"  },
  uho:           { color: UHO_COLOR,    background: "rgba(245,158,11,.15)"  },
  miscellaneous: { color: MISC_COLOR,   background: "rgba(129,140,248,.15)" },
  quickcart:     { color: QC_COLOR,     background: "rgba(244,63,94,.15)"   },
}[c]);

const CAT_COLORS = {
  income: INCOME_COLOR, uho: UHO_COLOR, miscellaneous: MISC_COLOR, quickcart: QC_COLOR
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

  // ── Security pipeline ─────────────────────────────────────────────────
  const { txns, blockedCount } = useMemo(() => {
    let blocked = 0;
    const passed = MOCK_SMS_FEED.reduce((acc, sms) => {
      const r = processSMS(sms);
      if (r) acc.push(r); else blocked++;
      return acc;
    }, []);
    return { txns: passed, blockedCount: blocked };
  }, []);

  const taggedTxns = useMemo(
    () => txns.map(t => ({ ...t, tag: tagMap[t.id] || null })),
    [txns, tagMap]
  );

  // ── Aggregates ────────────────────────────────────────────────────────
  const totalCredited  = useMemo(() => taggedTxns.filter(t => t.type === "credited").reduce((s, t) => s + t.amount, 0), [taggedTxns]);
  const totalDebited   = useMemo(() => taggedTxns.filter(t => t.type === "debited").reduce((s, t) => s + t.amount, 0), [taggedTxns]);
  const totalUHO       = useMemo(() => taggedTxns.filter(t => t.category === "uho").reduce((s, t) => s + t.amount, 0), [taggedTxns]);
  const totalMisc      = useMemo(() => taggedTxns.filter(t => t.category === "miscellaneous").reduce((s, t) => s + t.amount, 0), [taggedTxns]);
  const totalQuickCart = useMemo(() => taggedTxns.filter(t => t.category === "quickcart").reduce((s, t) => s + t.amount, 0), [taggedTxns]);

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

  // Brand chart — QuickCart brands breakdown
  const brandChartData = useMemo(() => {
    const map = {};
    taggedTxns.filter(t => t.category === "quickcart" && t.brand).forEach(t => {
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
    taggedTxns.filter(t => t.tag).forEach(t => {
      map[t.tag] = (map[t.tag] || 0) + t.amount;
    });
    return Object.entries(map)
      .map(([name, amt]) => ({ name, amt }))
      .sort((a, b) => b.amt - a.amt);
  }, [taggedTxns]);

  // Filtered txns for Overview
  const filteredTxns = useMemo(() => taggedTxns.filter(t => {
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
  const HomeTab = () => (
    <div style={{ overflowY: "auto", flex: 1, padding: "20px 16px 88px" }}>
      {/* Header */}
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start", marginBottom: 16 }}>
        <div>
          <p style={{ color: T_MUTED, fontSize: 11, letterSpacing: 1, textTransform: "uppercase", margin: "0 0 3px" }}>April 2026</p>
          <h1 style={{ color: T_BRIGHT, fontSize: 22, fontWeight: 800, margin: 0 }}>Budget Tracker</h1>
          <p style={{ color: T_MUTED, fontSize: 11, margin: "4px 0 0" }}>{taggedTxns.length} transactions parsed</p>
        </div>
        <button onClick={() => setShowTagMgr(true)}
          style={{ width: 40, height: 40, borderRadius: "50%",
            background: "linear-gradient(135deg,#6366f1,#8b5cf6)",
            display: "flex", alignItems: "center", justifyContent: "center",
            border: "none", cursor: "pointer" }}>
          <Tag size={16} color="#fff" />
        </button>
      </div>

      <PrivacyBanner />

      {/* Summary cards */}
      <div style={{ display: "flex", gap: 12, marginBottom: 14 }}>
        <StatCard label="Credited" value={fmt(totalCredited)} accent={INCOME_COLOR} Icon={TrendingUp}   />
        <StatCard label="Debited"  value={fmt(totalDebited)}  accent={DEBIT_COLOR}  Icon={TrendingDown} />
      </div>

      {/* Bar: Credit vs Debit */}
      <div style={S.section}>
        <p style={S.sectionTitle}>Credit vs Debit</p>
        <ResponsiveContainer width="100%" height={150}>
          <BarChart data={barData} barSize={52} margin={{ top: 4, right: 4, bottom: 0, left: 0 }}>
            <XAxis dataKey="name" axisLine={false} tickLine={false}
              tick={{ fill: T_MUTED, fontSize: 12, fontWeight: 500 }} />
            <YAxis hide />
            <Tooltip content={<CustomTooltip />} cursor={{ fill: "rgba(255,255,255,.03)" }} />
            <Bar dataKey="amt" radius={[8, 8, 0, 0]}>
              {barData.map((e, i) => <Cell key={i} fill={e.fill} />)}
            </Bar>
          </BarChart>
        </ResponsiveContainer>
      </div>

      {/* Spending Breakdown — Pie / Bar toggle */}
      <div style={S.section}>
        {/* Header row with toggle */}
        <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", marginBottom: 14 }}>
          <p style={{ color: T_DIM, fontSize: 13, fontWeight: 600, margin: 0 }}>Spending Breakdown</p>
          {/* Toggle pill */}
          <div style={{ display: "flex", background: PAGE_BG, borderRadius: 20, padding: 3, gap: 2 }}>
            {[
              { id: "pie", label: "🥧 Pie"  },
              { id: "bar", label: "📊 Bar"  },
            ].map(opt => (
              <button key={opt.id} onClick={() => setChartMode(opt.id)}
                style={{
                  padding: "4px 12px", borderRadius: 16, border: "none", cursor: "pointer",
                  fontSize: 11, fontWeight: 600, transition: "all .2s",
                  background: chartMode === opt.id ? "#6366f1" : "transparent",
                  color:      chartMode === opt.id ? "#fff"    : T_MUTED,
                }}>
                {opt.label}
              </button>
            ))}
          </div>
        </div>

        {/* PIE VIEW */}
        {chartMode === "pie" && (
          <div style={{ display: "flex", alignItems: "center", gap: 12 }}>
            <div style={{ flexShrink: 0 }}>
              <ResponsiveContainer width={145} height={145}>
                <PieChart>
                  <Pie data={pieData} dataKey="value" cx="50%" cy="50%"
                    innerRadius={38} outerRadius={58} paddingAngle={4} strokeWidth={0}>
                    {pieData.map((e, i) => <Cell key={i} fill={e.color} />)}
                  </Pie>
                  <Tooltip content={<CustomTooltip />} />
                </PieChart>
              </ResponsiveContainer>
            </div>
            <div style={{ display: "flex", flexDirection: "column", gap: 8, flex: 1 }}>
              {pieData.map((e, i) => (
                <div key={i} style={{ display: "flex", alignItems: "center", gap: 10 }}>
                  <div style={{ width: 9, height: 9, borderRadius: "50%", background: e.color, flexShrink: 0 }} />
                  <div>
                    <p style={{ color: T_DIM,    fontSize: 11, margin: 0 }}>{e.name}</p>
                    <p style={{ color: T_BRIGHT, fontSize: 13, fontWeight: 700, margin: 0 }}>{fmt(e.value)}</p>
                  </div>
                </div>
              ))}
            </div>
          </div>
        )}

        {/* BAR VIEW */}
        {chartMode === "bar" && (
          <ResponsiveContainer width="100%" height={pieData.length * 42 + 10}>
            <BarChart data={pieData.map(d => ({ name: d.name, amt: d.value, fill: d.color }))}
              layout="vertical" margin={{ top: 0, right: 60, bottom: 0, left: 0 }}>
              <XAxis type="number" hide />
              <YAxis type="category" dataKey="name" axisLine={false} tickLine={false}
                tick={{ fill: T_DIM, fontSize: 12 }} width={70} />
              <Tooltip content={<CustomTooltip />} cursor={{ fill: "rgba(255,255,255,.03)" }} />
              <Bar dataKey="amt" radius={[0, 8, 8, 0]} barSize={18}>
                {pieData.map((e, i) => <Cell key={i} fill={e.color} />)}
                <LabelList dataKey="amt" position="right"
                  formatter={v => fmt(v)}
                  style={{ fill: T_DIM, fontSize: 10 }} />
              </Bar>
            </BarChart>
          </ResponsiveContainer>
        )}
      </div>

      {/* Category summary row — UHO / QuickCart / Misc */}
      <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr 1fr", gap: 10, marginBottom: 14 }}>
        {[
          { label: "UHO",       val: totalUHO,       color: UHO_COLOR,  sub: "> ₹2k"  },
          { label: "QuickCart", val: totalQuickCart, color: QC_COLOR,   sub: "brands" },
          { label: "Misc",      val: totalMisc,      color: MISC_COLOR, sub: "≤ ₹2k"  },
        ].map(({ label, val, color, sub }) => (
          <div key={label} style={{ background: `${color}10`, border: `1px solid ${color}28`,
            borderRadius: 14, padding: "12px 10px" }}>
            <p style={{ color, fontSize: 9, fontWeight: 700, textTransform: "uppercase", letterSpacing: 0.5, margin: "0 0 4px" }}>{label}</p>
            <p style={{ color: T_BRIGHT, fontSize: 14, fontWeight: 800, margin: "0 0 2px" }}>{fmt(val)}</p>
            <p style={{ color: T_MUTED, fontSize: 9, margin: 0 }}>{sub}</p>
          </div>
        ))}
      </div>

      {/* QuickCart 🛒 brands breakdown — with Pie / Bar toggle */}
      {brandChartData.length > 0 && (
        <div style={S.section}>
          {/* Header + toggle */}
          <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", marginBottom: 14 }}>
            <div style={{ display: "flex", alignItems: "center", gap: 6 }}>
              <span style={{ fontSize: 14 }}>🛒</span>
              <p style={{ color: QC_COLOR, fontSize: 13, fontWeight: 700, margin: 0 }}>QuickCart Breakdown</p>
            </div>
            <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
              <span style={{ color: T_MUTED, fontSize: 11 }}>{fmt(totalQuickCart)}</span>
              {/* Toggle pill */}
              <div style={{ display: "flex", background: PAGE_BG, borderRadius: 20, padding: 3, gap: 2 }}>
                {[{ id: "bar", label: "📊" }, { id: "pie", label: "🥧" }].map(opt => (
                  <button key={opt.id} onClick={() => setQcChartMode(opt.id)}
                    style={{ padding: "4px 10px", borderRadius: 16, border: "none", cursor: "pointer",
                      fontSize: 11, fontWeight: 600, transition: "all .2s",
                      background: qcChartMode === opt.id ? QC_COLOR : "transparent",
                      color:      qcChartMode === opt.id ? "#fff"   : T_MUTED }}>
                    {opt.label}
                  </button>
                ))}
              </div>
            </div>
          </div>

          {/* BAR VIEW (default) */}
          {qcChartMode === "bar" && (
            <ResponsiveContainer width="100%" height={brandChartData.length * 36 + 10}>
              <BarChart data={brandChartData} layout="vertical"
                margin={{ top: 0, right: 56, bottom: 0, left: 0 }}>
                <XAxis type="number" hide />
                <YAxis type="category" dataKey="name" axisLine={false} tickLine={false}
                  tick={{ fill: T_DIM, fontSize: 12 }} width={80} />
                <Tooltip content={<CustomTooltip />} cursor={{ fill: "rgba(244,63,94,.05)" }} />
                <Bar dataKey="amt" fill={QC_COLOR} radius={[0, 6, 6, 0]} barSize={14}>
                  <LabelList dataKey="amt" position="right"
                    formatter={v => fmt(v)} style={{ fill: T_DIM, fontSize: 10 }} />
                </Bar>
              </BarChart>
            </ResponsiveContainer>
          )}

          {/* PIE VIEW */}
          {qcChartMode === "pie" && (
            <div style={{ display: "flex", alignItems: "center", gap: 12 }}>
              <div style={{ flexShrink: 0 }}>
                <ResponsiveContainer width={140} height={140}>
                  <PieChart>
                    <Pie data={brandChartData.map(d => ({ ...d, value: d.amt }))}
                      dataKey="value" cx="50%" cy="50%"
                      innerRadius={36} outerRadius={56} paddingAngle={4} strokeWidth={0}>
                      {brandChartData.map((_, i) => (
                        <Cell key={i} fill={`hsl(${340 + i * 22},80%,${58 + i * 4}%)`} />
                      ))}
                    </Pie>
                    <Tooltip content={<CustomTooltip />} />
                  </PieChart>
                </ResponsiveContainer>
              </div>
              <div style={{ display: "flex", flexDirection: "column", gap: 7, flex: 1 }}>
                {brandChartData.map((e, i) => (
                  <div key={i} style={{ display: "flex", alignItems: "center", gap: 8 }}>
                    <div style={{ width: 8, height: 8, borderRadius: "50%", flexShrink: 0,
                      background: `hsl(${340 + i * 22},80%,${58 + i * 4}%)` }} />
                    <div style={{ flex: 1, minWidth: 0 }}>
                      <p style={{ color: T_DIM, fontSize: 11, margin: 0, overflow: "hidden",
                        textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{e.name}</p>
                    </div>
                    <p style={{ color: T_BRIGHT, fontSize: 11, fontWeight: 700, margin: 0, flexShrink: 0 }}>
                      {fmt(e.amt)}
                    </p>
                  </div>
                ))}
              </div>
            </div>
          )}
        </div>
      )}

      {/* Tag chart — only when tags exist */}
      {tagChartData.length > 0 && (
        <div style={S.section}>
          <div style={{ display: "flex", alignItems: "center", gap: 6, marginBottom: 14 }}>
            <Tag size={13} color="#6366f1" />
            <p style={{ color: "#818cf8", fontSize: 13, fontWeight: 700, margin: 0 }}>Spending by Tag</p>
          </div>
          <ResponsiveContainer width="100%" height={tagChartData.length * 36 + 10}>
            <BarChart data={tagChartData} layout="vertical"
              margin={{ top: 0, right: 60, bottom: 0, left: 0 }}>
              <XAxis type="number" hide />
              <YAxis type="category" dataKey="name" axisLine={false} tickLine={false}
                tick={{ fill: T_DIM, fontSize: 12 }} width={80} />
              <Tooltip content={<CustomTooltip />} cursor={{ fill: "rgba(99,102,241,.05)" }} />
              <Bar dataKey="amt" fill="#6366f1" radius={[0, 6, 6, 0]} barSize={14}>
                <LabelList dataKey="amt" position="right"
                  formatter={v => fmt(v)}
                  style={{ fill: T_DIM, fontSize: 10 }} />
              </Bar>
            </BarChart>
          </ResponsiveContainer>
          <p style={{ color: T_MUTED, fontSize: 10, margin: "10px 0 0", textAlign: "center" }}>
            Tag transactions in Overview → chart updates here
          </p>
        </div>
      )}

      {/* Tag chart empty state */}
      {tagChartData.length === 0 && (
        <div style={{ background: "rgba(99,102,241,.06)", border: "1px dashed rgba(99,102,241,.25)",
          borderRadius: 16, padding: "18px 16px", textAlign: "center" }}>
          <Tag size={20} color="#6366f1" style={{ margin: "0 auto 8px" }} />
          <p style={{ color: "#818cf8", fontSize: 13, fontWeight: 600, margin: "0 0 4px" }}>Tag Chart</p>
          <p style={{ color: T_MUTED, fontSize: 11, margin: 0 }}>
            Go to Overview → tap 🏷️ on any transaction → a spending-by-tag chart appears here
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
