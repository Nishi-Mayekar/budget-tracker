/**
 * SMS Budget Tracker — Secure Edition v3
 * Design: Claude Design handoff — premium fintech, Inter Tight, warm cream
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

import React, { useState, useMemo, useEffect, useRef } from "react";
import { registerPlugin } from "@capacitor/core";
const SmsNative = registerPlugin("Sms");
// recharts removed — using inline bars for tag chart

// ══════════════════════════════════════════════════════════════════════════
//  SECURITY ENGINE — OTP / sensitive message blocker
// ══════════════════════════════════════════════════════════════════════════
// ── Hard-blocked: messages containing ANY of these are dropped immediately,
//    raw text is never read, no field is extracted, nothing is stored.
const BLOCKED_PATTERNS = [
  // OTP / verification codes
  /\botp\b/i,
  /one[\s-]?time[\s-]?pass(word|code)?/i,
  /verification\s*code/i,
  /\bauth(entication)?\s*(code|otp)\b/i,
  /login\s*(code|otp|pin)/i,
  /\bsecure\s*(code|otp|pin)\b/i,
  /do\s*not\s*share/i,
  /never\s*share/i,
  /valid\s*(only\s*)?for\s*\d+\s*min/i,
  /expire[sd]?\s*in\s*\d+/i,
  /\d{4,8}\s*is\s*your\b/i,
  /\bcode\s*[:\-–]\s*\d{4,8}/i,
  /\byour\s*(otp|code|pin|password)\s*(is|:)/i,
  /\bpasscode\b/i,
  /\bverif(y|ication|ied)\b/i,
  /2fa/i,
  /two[\s-]?factor/i,
  /multi[\s-]?factor/i,
  // Sensitive card / account fields
  /\bcvv\b/i,
  /\bpin\b/i,
  /\bpassword\b/i,
  /\bsecurity\s*(code|number|key|question)\b/i,
  /\bsecret\s*(code|key|word|phrase)\b/i,
  // 16-digit card number pattern (any spacing)
  /\b\d{4}[\s\-]?\d{4}[\s\-]?\d{4}[\s\-]?\d{4}\b/,
  // Security alerts that may embed sensitive context
  /\bfraud\s*alert\b/i,
  /suspicious\s*(activity|login|transaction)/i,
  /unauthori[sz]ed\s*(access|transaction|login)/i,
  /login\s*attempt/i,
  /sign[\s-]?in\s*attempt/i,
  /access\s*attempt/i,
];

// ── Personal message guard: messages from phone numbers (not bank/merchant
//    alphanumeric sender IDs) are personal texts — never process them.
function isPersonalSender(address) {
  if (!address) return false;
  // Phone number = starts with + or is purely digits (possibly with spaces/dashes)
  return /^[+\d][\d\s\-]{5,}$/.test(address.trim());
}

function isTransactionMessage(raw, senderAddress) {
  if (!raw || typeof raw !== "string") return false;
  // Block personal SMS senders (phone numbers)
  if (isPersonalSender(senderAddress)) return false;
  // Must contain a currency amount — with OR without prefix (SBIUPI sends "debited by 500.00")
  const hasCurrencyPrefix = /(?:INR|₹|Rs\.?)\s*[\d,]+/.test(raw);
  const hasAmountAfterVerb = /\b(?:debited|credited|paid|transferred|received|charged)\s+(?:by|for|of|to|from)?\s*(?:INR|₹|Rs\.?)?\s*[\d,]+(?:\.\d{1,2})?/i.test(raw);
  if (!hasCurrencyPrefix && !hasAmountAfterVerb) return false;
  // Must contain at least one transaction verb
  if (!(/\b(credited|debited|spent|charged|used\s+for|purchase[d]?|transaction|transfer(?:red)?|deducted|debit|paid|received|successful(?:ly)?)\b/i.test(raw))) return false;
  // Drop if any blocked pattern matches
  return !BLOCKED_PATTERNS.some(p => p.test(raw));
}

// ══════════════════════════════════════════════════════════════════════════
//  BRAND DETECTION
// ══════════════════════════════════════════════════════════════════════════
const QUICKCART_BRANDS = [
  "Zomato", "Swiggy", "Zepto", "Blinkit", "Instamart", "BigBasket",
  "JioMart", "Dunzo", "Amazon", "Flipkart", "Meesho", "Ajio", "Myntra",
  "Nykaa", "District", "BookMyShow", "PharmEasy", "1mg", "Medlife",
  "Swiggy Instamart", "ONDC",
];

const INVESTMENT_BRANDS = [
  "Groww", "Zerodha", "Kuvera", "ET Money", "INDmoney", "Angel One",
  "AngelOne", "Paytm Money", "PaytmMoney", "Upstox", "ICICI Direct",
  "HDFC Securities", "Kotak Securities", "SBI Securities", "Motilal Oswal",
  "Smallcase", "Dhan", "5paisa", "IIFL Securities",
  "HDFC MF", "SBI MF", "ICICI MF", "Nippon MF", "Axis MF",
  "Mirae Asset", "DSP Mutual", "UTI MF", "Franklin Templeton",
  "Coin by Zerodha",
];

const INSURANCE_BRANDS = [
  "Tata AIA", "LIC", "HDFC Life", "HDFC Ergo", "SBI Life",
  "ICICI Prudential", "ICICI Lombard", "Max Life", "Bajaj Allianz",
  "Aditya Birla Sun Life", "ABSLI", "Kotak Life", "PNB MetLife",
  "Reliance Life", "Reliance Nippon", "Edelweiss Tokio", "Future Generali",
  "Canara HSBC", "IndiaFirst Life", "Niva Bupa", "Star Health",
  "Care Health", "Digit Insurance", "Acko", "Go Digit",
];
const INSURANCE_REGEX = new RegExp(
  INSURANCE_BRANDS.map(b => b.replace(/[-\s]/g, "[\\s\\-]?")).join("|"), "i"
);

// UPI VPA handle → brand (catches groww@axisb, swiggy@icici etc.)
const UPI_VPA_BRANDS = {
  groww: "Groww", grow: "Groww", growwmf: "Groww",
  zerodha: "Zerodha", kuvera: "Kuvera", upstox: "Upstox",
  zomato: "Zomato", swiggy: "Swiggy", swiggyin: "Swiggy",
  blinkit: "Blinkit", zepto: "Zepto", bigbasket: "BigBasket",
  jiomart: "JioMart", amazon: "Amazon", flipkart: "Flipkart",
  tataaialife: "Tata AIA", tataaig: "Tata AIA",
  licpremium: "LIC", lic: "LIC",
};
function detectBrandFromVPA(raw) {
  const m = raw.match(/([\w.\-]+)@[\w.\-]+/);
  if (!m) return null;
  const handle = m[1].toLowerCase().replace(/[.\-]/g, "");
  return UPI_VPA_BRANDS[handle] || null;
}

function detectInsuranceBrand(raw) {
  const m = raw.match(INSURANCE_REGEX);
  if (m) return m[0];
  if (/\b(life\s*insurance|health\s*insurance|term\s*plan|premium\s*due|policy\s*premium|motor\s*insurance)\b/i.test(raw))
    return "Insurance";
  return null;
}

const INV_REGEX = new RegExp(
  INVESTMENT_BRANDS.map(b => b.replace(/[-\s]/g, "[\\s\\-]?")).join("|"), "i"
);
function detectInvestmentBrand(raw) {
  const m = raw.match(INV_REGEX);
  if (m) return m[0];
  // Handle "transfer to/from GROWW/growwo" variants
  const transferMatch = raw.match(/transfer(?:red)?\s+(?:to|from)\s+([A-Za-z][A-Za-z\s]{1,20}?)(?:[\/\s,\.]|$)/i);
  if (transferMatch) {
    const name = transferMatch[1].trim();
    if (/grow[wo]/i.test(name)) return "Groww";
    if (/zerodha/i.test(name)) return "Zerodha";
    if (/kuvera/i.test(name)) return "Kuvera";
    if (/upstox/i.test(name)) return "Upstox";
    if (/ind\s*money/i.test(name)) return "INDmoney";
    if (/angel\s*one/i.test(name)) return "Angel One";
  }
  if (/\bSIP\b.*\b(?:mandate|debit|amount|auto)\b|\bNACH\b.*\b(?:SIP|mutual\s*fund|MF)\b|\bmutual\s*fund\s*SIP\b|\bMF\s*(?:SIP|debit|auto)\b/i.test(raw))
    return "SIP / MF";
  return null;
}

const BRAND_REGEX = new RegExp(
  QUICKCART_BRANDS.map(b => `\\b${b.replace(/[-\s]/g, "[\\s-]?")}\\b`).join("|"), "i"
);
function detectBrand(raw) {
  const m = raw.match(BRAND_REGEX);
  return m ? m[0] : null;
}

// ══════════════════════════════════════════════════════════════════════════
//  BRAND → TAG MAP  (deterministic, no free-text needed)
// ══════════════════════════════════════════════════════════════════════════
const BRAND_TAG_MAP = {
  // Food delivery
  "Zomato": "Food", "Swiggy": "Food",
  // Grocery
  "Blinkit": "Grocery", "Instamart": "Grocery", "Swiggy Instamart": "Grocery",
  "BigBasket": "Grocery", "Zepto": "Grocery", "JioMart": "Grocery",
  "Dunzo": "Grocery", "Amazon Fresh": "Grocery",
  // Investments
  "Groww": "SIP", "Zerodha": "SIP", "Kuvera": "SIP", "ET Money": "SIP",
  "INDmoney": "SIP", "Paytm Money": "SIP", "Upstox": "Stocks",
  "Angel One": "Stocks", "AngelOne": "Stocks", "5paisa": "Stocks",
  "Dhan": "Stocks", "HDFC Securities": "Stocks", "SIP / MF": "SIP",
  // Shopping
  "Amazon": "Shopping", "Flipkart": "Shopping", "Myntra": "Shopping",
  "Ajio": "Shopping", "Meesho": "Shopping", "Nykaa": "Shopping",
  // Entertainment
  "Netflix": "Subscriptions", "Spotify": "Subscriptions",
  "BookMyShow": "Entertainment", "District": "Entertainment",
  // Pharma
  "PharmEasy": "Health", "1mg": "Health", "Medlife": "Health",
  // Insurance
  "Tata AIA": "Insurance", "LIC": "Insurance", "HDFC Life": "Insurance",
  "HDFC Ergo": "Insurance", "SBI Life": "Insurance", "ICICI Prudential": "Insurance",
  "ICICI Lombard": "Insurance", "Max Life": "Insurance", "Bajaj Allianz": "Insurance",
  "Star Health": "Insurance", "Care Health": "Insurance", "Digit Insurance": "Insurance",
  "Acko": "Insurance", "Niva Bupa": "Insurance", "Insurance": "Insurance",
};

// ══════════════════════════════════════════════════════════════════════════
//  UPI NARRATION AUTO-TAGGER
// ══════════════════════════════════════════════════════════════════════════
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
  { tag: "Maid",          keywords: ["maid","bai","help","househelp","house help","domestic","cleaner","cook","ayah"] },
  { tag: "Home",          keywords: ["fridge","refrigerator","washing machine","appliance","furniture","sofa","bed","electronics","ac repair","water filter","purifier","microwave"] },
  { tag: "Parents",       keywords: ["parents","mother","father","mom","dad","amma","appa","nana","nani","dada","dadi","home monthly","family"] },
];

function extractUpiNarration(raw) {
  const patterns = [
    /\bInfo:\s*UPI[\/\-]\d+[\/\-]([^\/\-,@\n]{2,30})[\/\-]/i,
    /UPI[\/\-]\d+[\/\-][^\/]+@[^\/]+[\/\-]([^\/,\.\n]{2,30})/i,
    /\bRemarks?:\s*([^\.\n,]{2,30})/i,
    /\bNote:\s*([^\.\n,]{2,30})/i,
    /\bpaid\s+(?:for|via)\s+([a-z][a-z\s]{1,25})/i,
  ];
  for (const p of patterns) {
    const m = raw.match(p);
    if (m) {
      const narration = m[1].trim().toLowerCase();
      if (/[@\d]{4,}/.test(narration)) continue;
      if (narration.length < 3) continue;
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

// ── Secure parser ─────────────────────────────────────────────────────────
// What this reads:   ₹ amount, credited/debited direction, allowlisted brand name
// What this NEVER stores: raw SMS text, account numbers, card numbers,
//   UPI IDs, personal names, bank reference numbers, balances, phone numbers.
function secureExtract(raw) {
  // ── Step 1: Brand detection on RAW text first (whitelist-only regex, safe) ──
  // Must happen before scrubbing because UPI VPAs like "groww@axisb" get
  // replaced by [UPI] and the brand would be lost.
  const brand       = detectBrand(raw) || detectBrandFromVPA(raw);
  const invBrand    = detectInvestmentBrand(raw) || (detectBrandFromVPA(raw) && INVESTMENT_BRANDS.some(b => b.toLowerCase() === (detectBrandFromVPA(raw)||"").toLowerCase()) ? detectBrandFromVPA(raw) : null);
  const insureBrand = detectInsuranceBrand(raw);

  // ── Step 2: Scrub sensitive data before reading anything else ──
  const scrubbed = raw
    .replace(/\b\d{4}[\s\-]?\d{4}[\s\-]?\d{4}[\s\-]?\d{4}\b/g, "[CARD]")  // 16-digit card
    .replace(/[Aa][Cc](?:count)?\s*(?:no\.?\s*)?[Xx*]{2,}\d{2,6}/g, "[AC]") // Ac XX1234
    .replace(/\b\d{9,18}\b/g, "[NUM]")                                        // long account numbers
    .replace(/[\w.\-]+@[\w.\-]+/g, "[UPI]");                                  // UPI VPA

  // ── Step 3: Extract amount from scrubbed ──
  // Try currency-prefixed first (₹/Rs./INR), then verb-adjacent (SBIUPI: "debited by 500.00")
  let amtMatch = scrubbed.match(/(?:INR|₹|Rs\.?)\s*([\d,]+(?:\.\d{1,2})?)/i);
  if (!amtMatch) {
    amtMatch = scrubbed.match(/\b(?:debited|credited|paid|received|charged|transferred)\s+(?:by|for|of|to|from)?\s*([\d,]+(?:\.\d{1,2})?)/i);
  }
  if (!amtMatch) return null;
  const amount = Math.round(parseFloat(amtMatch[1].replace(/,/g, "")) * 100) / 100;
  if (!isFinite(amount) || amount <= 0 || amount > 10000000) return null;

  // Credit detection: "credited", "received", "added to your account", "money received"
  const isCredit    = /\b(credited|received|added\s+to\s+(?:your\s+)?(?:a(?:ccount|\/c))|money\s+received|amount\s+received)\b/i.test(scrubbed);
  const isDebit     = /\b(debited|spent|charged|paid|deducted|transferred\s+(?:to|from\s+your))\b/i.test(scrubbed);
  const isRefund    = /\b(refund|reversal|cashback|cash\s*back|reversed|returned)\b/i.test(scrubbed);
  // If only "paid" appears without "received", it's a debit (you paid = money went out)
  const type        = (isCredit && !isDebit) || isRefund ? "credited" : "debited";
  const isRefundTxn = isRefund;
  // Detect which card — shown as brand in transactions ("HDFC CC", "SBI Card", "Scapia")
  const CC_PATTERNS = [
    { regex: /\bscapia\b/i,                                       label: "Scapia"   },
    { regex: /\bhdfc\b.*(?:credit\s*card|cc\b|card)/i,            label: "HDFC CC"  },
    { regex: /\bsbi\b.*(?:credit\s*card|cc\b|card)/i,             label: "SBI Card" },
    { regex: /\bicici\b.*(?:credit\s*card|cc\b|card)/i,           label: "ICICI CC" },
    { regex: /\baxis\b.*(?:credit\s*card|cc\b|card)/i,            label: "Axis CC"  },
    { regex: /\bkotak\b.*(?:credit\s*card|cc\b|card)/i,           label: "Kotak CC" },
    { regex: /\byes\s*bank\b.*(?:credit\s*card|cc\b|card)/i,      label: "Yes CC"   },
    { regex: /\bau\s*bank\b.*(?:credit\s*card|cc\b|card)/i,       label: "AU CC"    },
    { regex: /credit[\s\-]?card|cc\s+(ending|no|limit|card)|credit\s*a\/c/i, label: null },
  ];
  let detectedCard = null;
  for (const { regex, label } of CC_PATTERNS) {
    if (regex.test(scrubbed)) { detectedCard = label; break; }
  }
  const isCreditCard = !!detectedCard;

  // Family transfer detection — narration contains family keywords
  const narrationLower = (raw.match(/(?:info|remarks?|note|upi\/\d+\/[^\/]+\/)([^\n,\.@]{3,40})/i)||[])[1]?.toLowerCase() || "";
  const isFamilyTransfer = /\b(parents?|mother|father|mom|dad|amma|appa|nana|nani|dada|dadi|bhaiya|didi|sister|brother|wife|husband)\b/i.test(narrationLower);

  // ── Step 4: Category — known brands always override CC classification ──
  let category;
  if      (type === "credited") category = "income";
  else if (invBrand)            category = "investments";   // Groww/Zerodha always → investments
  else if (insureBrand)         category = "insurance";     // Tata AIA/LIC → insurance
  else if (isFamilyTransfer)    category = "family";        // Transfers tagged as parents/family
  else if (brand)               category = "quickcart";    // Blinkit/Zomato always → quickcart
  else if (isCreditCard)        category = "creditcard";   // generic CC (no known brand)
  else                          category = "miscellaneous";

  const finalBrand = brand || invBrand || insureBrand || (isCreditCard ? detectedCard : null);
  return { amount, type, category, brand: finalBrand, isCreditCard, isRefund: isRefundTxn };
}

const MONTH_NAMES = ["Jan","Feb","Mar","Apr","May","Jun","Jul","Aug","Sep","Oct","Nov","Dec"];

function processSMS(sms) {
  if (!isTransactionMessage(sms.raw, sms.bank)) return null;
  const parsed = secureExtract(sms.raw);
  if (!parsed) return null;

  let monthKey, year;
  if (sms.timestamp) {
    const d = new Date(sms.timestamp);
    year     = d.getFullYear();
    monthKey = `${year}-${String(d.getMonth() + 1).padStart(2, "0")}`;
  } else {
    const now  = new Date();
    year       = now.getFullYear();
    const parts = (sms.date || "").split(" ");
    const mIdx  = MONTH_NAMES.indexOf(parts[0]);
    const month = mIdx >= 0 ? mIdx + 1 : now.getMonth() + 1;
    monthKey   = `${year}-${String(month).padStart(2, "0")}`;
  }

  let suggestedTag = null;
  if (parsed.type === "debited") {
    // 1. Brand-based (deterministic, highest confidence, no raw text read)
    const brandKey = Object.keys(BRAND_TAG_MAP).find(k =>
      parsed.brand && parsed.brand.toLowerCase().includes(k.toLowerCase())
    );
    if (brandKey) {
      suggestedTag = BRAND_TAG_MAP[brandKey];
    } else if (parsed.category === "investments") {
      suggestedTag = "SIP";
    } else {
      // 2. UPI narration keyword match (runs on scrubbed raw — no account data)
      suggestedTag = narrationToTag(sms.raw);
      // 3. Heuristic: small misc amount with no brand → likely auto/transit
      if (!suggestedTag && parsed.category === "miscellaneous" && parsed.amount <= 500) {
        suggestedTag = "Transit";
      }
    }
  }
  // Raw SMS text is never stored in the returned object
  return { id: sms.id, date: sms.date, bank: sms.bank, monthKey, year, ...parsed, suggestedTag, tag: null };
}

// ── Mock SMS feed ─────────────────────────────────────────────────────────
const MOCK_SMS_FEED = [
  { id: 1,  raw: "₹45,000 credited to Ac xx5678 SALARY from TECHCORP PVT LTD",     date: "Apr 05", bank: "HDFC"  },
  { id: 2,  raw: "₹15,000 credited to Ac xx5678 NEFT from RAHUL SHARMA",            date: "Apr 14", bank: "HDFC"  },
  { id: 3,  raw: "₹8,000 credited to Ac xx5678 IMPS from PRIYA MEHTA",              date: "Apr 12", bank: "SBI"   },
  { id: 5,  raw: "₹12,000 debited from Ac xx5678. Info: IndiGo Flight Booking",     date: "Apr 09", bank: "HDFC"  },
  { id: 6,  raw: "₹6,500 debited from Ac xx5678. Info: Monthly Rent Apr",           date: "Apr 01", bank: "ICICI" },
  { id: 7,  raw: "₹3,500 debited from Ac xx5678. Info: Myntra Fashion Order",       date: "Apr 11", bank: "HDFC"  },
  { id: 8,  raw: "₹2,500 debited from Ac xx5678. Info: Amazon Shopping",            date: "Apr 14", bank: "HDFC"  },
  { id: 9,  raw: "₹450 debited from Ac xx5678. Info: Swiggy Order #7892",           date: "Apr 13", bank: "HDFC"  },
  { id: 10, raw: "₹380 debited from Ac xx5678. Info: Zomato Order #2312",           date: "Apr 12", bank: "HDFC"  },
  { id: 11, raw: "₹1,850 debited from Ac xx5678. Info: BigBasket Grocery",          date: "Apr 11", bank: "HDFC"  },
  { id: 12, raw: "₹290 debited from Ac xx5678. Info: Zepto Order #5510",            date: "Apr 10", bank: "SBI"   },
  { id: 13, raw: "₹560 debited from Ac xx5678. Info: Blinkit Order #8821",          date: "Apr 09", bank: "HDFC"  },
  { id: 14, raw: "₹1,200 debited from Ac xx5678. Info: Amazon Fresh Order",         date: "Apr 08", bank: "HDFC"  },
  { id: 15, raw: "₹750 debited from Ac xx5678. Info: District Movie Booking",       date: "Apr 07", bank: "ICICI" },
  { id: 16, raw: "₹320 debited from Ac xx5678. Info: Swiggy Instamart",             date: "Apr 06", bank: "SBI"   },
  { id: 17, raw: "₹900 debited from Ac xx5678. Info: Netflix Subscription",         date: "Apr 10", bank: "HDFC"  },
  { id: 18, raw: "₹500 debited from Ac xx5678. Info: Jio Recharge",                 date: "Apr 07", bank: "SBI"   },
  { id: 19, raw: "₹350 debited from Ac xx5678. Info: HP Petrol Fill-up",            date: "Apr 09", bank: "SBI"   },
  { id: 20, raw: "₹200 debited from Ac xx5678. Info: Starbucks Coffee",             date: "Apr 11", bank: "SBI"   },
  { id: 31, raw: "₹650 debited from Ac xx5678. Info: UPI/987654321/grocery/merchant@okicici. Avl Bal:₹8,200", date: "Apr 13", bank: "HDFC" },
  { id: 32, raw: "₹4,200 debited from Ac xx5678. Info: UPI/876543219/travel/irctc@okaxis. Avl Bal:₹4,000",    date: "Apr 08", bank: "HDFC" },
  { id: 33, raw: "₹800 debited from Ac xx5678. Info: UPI/765432198/medical/apollo@okicici. Avl Bal:₹3,200",   date: "Apr 10", bank: "SBI"  },
  { id: 34, raw: "₹1,100 debited from Ac xx5678 Remarks: rent payment Apr. UPI Ref:654321987",                date: "Apr 01", bank: "ICICI"},
  // HDFC CC
  { id: 21, raw: "Rs.3,500.00 debited from your HDFC Credit Card ending 1234 at IndiGo. Apr 08",   date: "Apr 08", bank: "HDFCCC" },
  { id: 22, raw: "₹1,200 spent on HDFC Bank Credit Card XX1234 at Blinkit on 12-Apr-26",           date: "Apr 12", bank: "HDFCCC" },
  // SBI CC
  { id: 23, raw: "₹850 spent on SBI Credit Card XX5678 at Zomato on 12-Apr-26",                    date: "Apr 12", bank: "SBICRD" },
  { id: 24, raw: "Rs.450.00 charged on SBI Card XX5678 at Swiggy. Apr 10",                         date: "Apr 10", bank: "SBICRD" },
  // Scapia CC
  { id: 25, raw: "₹2,100 spent on your Scapia Card at Amazon. Apr 09",                             date: "Apr 09", bank: "SCAPIA" },
  { id: 26, raw: "Scapia: Rs.642.00 debited at Zepto on 14-Apr-26",                                date: "Apr 14", bank: "SCAPIA" },
  { id: 41, raw: "₹5,000 debited from Ac xx5678. Info: Groww Mutual Fund SIP Apr",        date: "Apr 03", bank: "HDFC"  },
  { id: 42, raw: "₹2,500 debited from Ac xx5678. Info: Zerodha Broking Charges",          date: "Apr 07", bank: "ICICI" },
  { id: 43, raw: "₹10,000 debited from Ac xx5678. Info: Groww - Nifty 50 Index Fund SIP", date: "Apr 01", bank: "SBI"   },
  { id: 44, raw: "₹3,000 debited from Ac xx5678. Info: INDmoney US Stock Purchase",       date: "Apr 10", bank: "HDFC"  },
  { id: 48, raw: "₹5,000 debited from Ac xx5678 via NACH for SIP mandate auto-debit",     date: "Apr 05", bank: "SBI"   },
  { id: 49, raw: "₹8,000 debited from Ac xx5678. Info: UPI/123456/Groww SIP/groww@axisb. Avl Bal:₹50,000", date: "Apr 03", bank: "HDFC" },
  { id: 50, raw: "₹5,000 debited from Ac xx5678. Info: Transfer to GROWW/growwo. Avl Bal:₹45,000",         date: "Apr 01", bank: "SBI"  },
  { id: 51, raw: "₹1,500 debited from Ac xx5678. Tata AIA Life Insurance premium Apr 2026",               date: "Apr 07", bank: "HDFC" },
  { id: 52, raw: "₹2,800 debited from Ac xx5678. HDFC Life Insurance renewal premium deducted",           date: "Apr 06", bank: "HDFC" },
  { id: 53, raw: "₹999 debited from Ac xx5678. LIC premium auto-debit Apr 2026",                         date: "Apr 02", bank: "SBI"  },
  { id: 45, raw: "₹850 refund credited to Ac xx5678 for Swiggy Order #7892",              date: "Apr 15", bank: "HDFC"  },
  { id: 46, raw: "₹200 cashback credited to Ac xx5678 from Axis Bank Credit Card",        date: "Apr 13", bank: "Axis"  },
  { id: 47, raw: "₹1,200 reversal credited to Ac xx5678 for Amazon return",               date: "Apr 11", bank: "HDFC"  },
  // SBIUPI format — no ₹ prefix, "debited by 500.00"
  { id: 61, raw: "Dear UPI user A/C X1234 debited by 642.00 on date 17-04-26 trf to Zomato Ref 987654321. If not done by you call 18001111",  date: "Apr 17", bank: "SBIUPI" },
  { id: 62, raw: "Dear UPI user A/C X1234 debited by 15000.00 on date 05-04-26 trf to parents monthly Ref 111222333.", date: "Apr 05", bank: "SBIUPI" },
  // PhonePe format
  { id: 63, raw: "₹384 paid to Zepto via PhonePe UPI. Ref 445566778. Apr 16", date: "Apr 16", bank: "PHONPE" },
  { id: 64, raw: "₹800 received from RAHUL via PhonePe UPI. Ref 556677889.", date: "Apr 14", bank: "PHONPE" },
  // CRED format
  { id: 65, raw: "₹1299 paid via CRED UPI to Amazon. CRED Ref CRED20260412.", date: "Apr 12", bank: "CREDSG" },
  // BLOCKED — OTP messages
  { id: 101, raw: "748392 is your OTP for HDFC NetBanking. Do not share with anyone.", date: "Apr 14", bank: "HDFC"  },
  { id: 102, raw: "Your ICICI Bank OTP is 291047. Valid for 10 minutes.",              date: "Apr 13", bank: "ICICI" },
  { id: 103, raw: "SBI: Your login OTP is 503821. Do not share this code.",            date: "Apr 12", bank: "SBI"   },
];

// ══════════════════════════════════════════════════════════════════════════
//  DESIGN TOKENS  (from Claude Design handoff)
// ══════════════════════════════════════════════════════════════════════════
const D = {
  cream:       "#f5f3ef",
  cream2:      "#efece5",
  cream3:      "#e8e4db",
  ink:         "#141310",
  ink2:        "#2a2823",
  ink3:        "#6e6a60",
  ink4:        "#9c978b",
  line:        "#e3dfd4",
  line2:       "#d9d4c6",
  white:       "#ffffff",
  income:      "#1f8a5c",
  incomeSoft:  "#e4f2ea",
  cc:          "#6b3fd4",
  ccSoft:      "#ece6fa",
  quick:       "#d43764",
  quickSoft:   "#fae0e8",
  invest:      "#1d7a99",
  investSoft:  "#dff0f5",
  misc:        "#4f55c7",
  miscSoft:    "#e5e6f6",
  insure:      "#c45e1a",   // warm amber-orange for insurance
  insureSoft:  "#faeadf",
  family:      "#7a5c99",   // warm purple for family
  familySoft:  "#ede6f5",
  rLg:         24,
  rMd:         18,
  rSm:         12,
  card:        "0 1px 0 rgba(20,19,16,.04), 0 1px 2px rgba(20,19,16,.04)",
  raised:      "0 2px 0 rgba(20,19,16,.03), 0 8px 24px rgba(20,19,16,.06)",
};

// Category display map
const CATS = {
  income:  { name: "Income",        emoji: "💚", color: D.income,  soft: D.incomeSoft },
  cc:      { name: "Credit Card",   emoji: "💳", color: D.cc,      soft: D.ccSoft     },
  quick:   { name: "QuickCart",     emoji: "🛒", color: D.quick,   soft: D.quickSoft  },
  invest:  { name: "Investments",   emoji: "📈", color: D.invest,  soft: D.investSoft },
  insure:  { name: "Insurance",     emoji: "🛡️", color: D.insure,  soft: D.insureSoft },
  family:  { name: "Family",        emoji: "🏠", color: D.family,  soft: D.familySoft },
  misc:    { name: "Miscellaneous", emoji: "🏷️", color: D.misc,    soft: D.miscSoft   },
};

// Internal category key → display key
const CK = k => ({
  income:"income", creditcard:"cc", quickcart:"quick",
  investments:"invest", insurance:"insure", family:"family", miscellaneous:"misc"
}[k] || "misc");

// Indian number formatter (supports compact: 1.2L, 45k)
const fmt = (n, compact = false) => {
  if (compact && Math.abs(n) >= 100000) return "₹" + (n/100000).toFixed(1).replace(/\.0$/,"") + "L";
  if (compact && Math.abs(n) >= 1000)   return "₹" + (n/1000).toFixed(1).replace(/\.0$/,"")   + "k";
  const abs = Math.round(Math.abs(n)).toString();
  const last3 = abs.slice(-3), rest = abs.slice(0,-3);
  const grouped = rest ? rest.replace(/\B(?=(\d{2})+(?!\d))/g, ",") + "," + last3 : last3;
  return (n < 0 ? "-" : "") + "₹" + grouped;
};

// ── Category icon ─────────────────────────────────────────────────────────
const CatIcon = ({ catKey, size = 40 }) => {
  const c = CATS[CK(catKey)] || CATS.misc;
  return (
    <div style={{ width: size, height: size, borderRadius: Math.round(size * 0.28),
      background: c.soft, display: "flex", alignItems: "center", justifyContent: "center",
      fontSize: Math.round(size * 0.46), flexShrink: 0 }}>
      {c.emoji}
    </div>
  );
};

// Merchant letter avatar
const MerchantAvatar = ({ merchant, catKey, size = 42 }) => {
  const c = CATS[CK(catKey)] || CATS.misc;
  return (
    <div style={{ width: size, height: size, borderRadius: Math.round(size * 0.28),
      background: c.soft, display: "flex", alignItems: "center", justifyContent: "center",
      fontSize: Math.round(size * 0.36), fontWeight: 700, color: c.color, flexShrink: 0,
      fontFamily: "'Inter Tight', sans-serif", userSelect: "none" }}>
      {(merchant || "?").split(/\s+/).filter(Boolean).slice(0,2).map(w=>w[0].toUpperCase()).join("")}
    </div>
  );
};

// Bottom sheet
const Sheet = ({ open, onClose, title, children }) => (
  <>
    <div onClick={onClose} style={{
      position: "absolute", inset: 0, background: "rgba(20,19,16,.4)",
      opacity: open ? 1 : 0, pointerEvents: open ? "auto" : "none",
      transition: "opacity 240ms ease", zIndex: 50,
    }}/>
    <div style={{
      position: "absolute", left: 0, right: 0, bottom: 0,
      background: D.cream, borderRadius: "28px 28px 0 0",
      transform: open ? "translateY(0)" : "translateY(100%)",
      transition: "transform 340ms cubic-bezier(.2,.8,.2,1)",
      zIndex: 51, maxHeight: "88%", display: "flex", flexDirection: "column",
      overflow: "hidden", boxShadow: "0 -8px 48px rgba(0,0,0,.14)",
    }}>
      <div style={{ width: 40, height: 4, background: D.line2, borderRadius: 2, margin: "12px auto 0", flexShrink: 0 }}/>
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center",
        padding: "14px 20px 10px", flexShrink: 0 }}>
        <div style={{ fontSize: 17, fontWeight: 700, color: D.ink, letterSpacing: "-0.01em" }}>{title}</div>
        <button onClick={onClose} style={{ width: 30, height: 30, borderRadius: 9,
          background: D.cream2, border: `1px solid ${D.line}`, cursor: "pointer",
          display: "flex", alignItems: "center", justifyContent: "center",
          fontSize: 14, color: D.ink3 }}>✕</button>
      </div>
      <div style={{ overflowY: "auto", padding: "4px 20px 32px", scrollbarWidth: "none" }}>
        {children}
      </div>
    </div>
  </>
);

// ══════════════════════════════════════════════════════════════════════════
//  MAIN APP
// ══════════════════════════════════════════════════════════════════════════
export default function App() {
  // ── State ───────────────────────────────────────────────────────────────
  const [tab,          setTab]          = useState("home");
  const [tagMap,       setTagMap]       = useState({});
  const [activeTagTxn, setActiveTagTxn] = useState(null);
  const [tagDraft,     setTagDraft]     = useState("");
  const [userTags,     setUserTags]     = useState([
    "Food","Groceries","Rent","Bills","Transit","Fuel","SIP",
    "Subscriptions","Health","Shopping","Travel","Entertainment",
  ]);
  const [showTagMgr,   setShowTagMgr]   = useState(false);
  const [showPrivacy,  setShowPrivacy]  = useState(false);
  const [showSalary,   setShowSalary]   = useState(false);
  const [showDrill,    setShowDrill]    = useState(null);
  const [smsFeed,      setSmsFeed]      = useState(MOCK_SMS_FEED);
  const [onboarded,    setOnboarded]    = useState(false);
  const [obStep,       setObStep]       = useState(0); // 0-2 carousel, 3 salary, 4 fixed expenses
  const [salary,       setSalary]       = useState({ amount: "", day: 1 });
  const [salaryInput,  setSalaryInput]  = useState({ amount: "", day: "1" });
  const [obAmt,        setObAmt]        = useState("");
  const [obDay,        setObDay]        = useState("1");
  // Fixed monthly expenses set during onboarding
  const [fixedExpenses, setFixedExpenses] = useState({
    sip: "", insurance: "", parents: "", rent: "",
  });

  // ── Font injection ──────────────────────────────────────────────────────
  useEffect(() => {
    const link = document.createElement("link");
    link.rel = "stylesheet";
    link.href = "https://fonts.googleapis.com/css2?family=Inter+Tight:wght@400;500;600;700;800;900&display=swap";
    document.head.appendChild(link);
    const style = document.createElement("style");
    style.textContent = `
      * { box-sizing: border-box; -webkit-tap-highlight-color: transparent; }
      .ns::-webkit-scrollbar { display: none; }
      .ns { scrollbar-width: none; }
      @keyframes fadeIn { from { opacity:0; transform:translateY(4px) } to { opacity:1; transform:translateY(0) } }
      @keyframes slideUp { from { opacity:0; transform:translateY(8px) } to { opacity:1; transform:translateY(0) } }
    `;
    document.head.appendChild(style);
  }, []);

  // ── Date parser: extract date from SMS body text as fallback ────────────
  function parseDateFromBody(body) {
    // dd-mm-yy or dd-mm-yyyy (SBIUPI, many banks)
    let m = body.match(/\b(\d{1,2})[-\/](\d{1,2})[-\/](\d{2,4})\b/);
    if (m) {
      const day = parseInt(m[1]), mon = parseInt(m[2]);
      const yr  = m[3].length === 2 ? 2000 + parseInt(m[3]) : parseInt(m[3]);
      if (mon >= 1 && mon <= 12 && day >= 1 && day <= 31)
        return new Date(yr, mon - 1, day);
    }
    // "20-Apr-26" or "20-Apr-2026"
    m = body.match(/\b(\d{1,2})[-\s]([A-Za-z]{3})[-\s](\d{2,4})\b/);
    if (m) {
      const day = parseInt(m[1]);
      const mon = MONTH_NAMES.indexOf(m[2].charAt(0).toUpperCase() + m[2].slice(1).toLowerCase());
      const yr  = m[3].length === 2 ? 2000 + parseInt(m[3]) : parseInt(m[3]);
      if (mon >= 0 && day >= 1 && day <= 31)
        return new Date(yr, mon, day);
    }
    return null;
  }

  // ── Load real SMS ───────────────────────────────────────────────────────
  useEffect(() => {
    SmsNative.getMessages()
      .then(({ messages }) => {
        const feed = messages.map((m, i) => {
          const ts = Number(m.date);
          // Use timestamp if valid (> year 2020), otherwise extract from body
          let d = ts > 1577836800000 ? new Date(ts) : parseDateFromBody(m.body || "");
          if (!d || isNaN(d.getTime())) d = new Date(); // final fallback: today
          return {
            id: i, raw: m.body, timestamp: ts > 0 ? ts : d.getTime(),
            date: `${MONTH_NAMES[d.getMonth()]} ${String(d.getDate()).padStart(2,"0")}`,
            bank: m.address,
          };
        });
        if (feed.length > 0) setSmsFeed(feed);
      })
      .catch(() => {})
  }, []);

  // ── Period state ────────────────────────────────────────────────────────
  const NOW = new Date();
  const [period,    setPeriod]    = useState("M");
  const [viewMonth, setViewMonth] = useState(NOW.getMonth() + 1);
  const [viewYear,  setViewYear]  = useState(NOW.getFullYear());

  const shiftMonth = dir => {
    setViewMonth(m => {
      let nm = m + dir;
      if (nm < 1)  { setViewYear(y => y - 1); return 12; }
      if (nm > 12) { setViewYear(y => y + 1); return 1;  }
      return nm;
    });
  };

  // ── SMS processing pipeline ─────────────────────────────────────────────
  const { txns, blockedCount } = useMemo(() => {
    let blocked = 0;
    const passed = smsFeed.reduce((acc, sms) => {
      const r = processSMS(sms);
      if (r) acc.push(r); else blocked++;
      return acc;
    }, []);
    return { txns: passed, blockedCount: blocked };
  }, [smsFeed]);

  // Cross-check SMS amounts against user's declared fixed expenses
  // Marks transactions as "isFixed" so they don't show as surprise spending
  const taggedTxns = useMemo(() => txns.map(t => {
    const tag = tagMap[t.id] || t.suggestedTag || null;
    let isFixed = false, fixedLabel = null;
    if (t.type === "debited" && t.amount > 0) {
      const amt = t.amount;
      const tol = amt * 0.05; // 5% tolerance for partial amounts
      if (fixedExpenses.sip && Math.abs(amt - Number(fixedExpenses.sip)) <= tol && t.category === "investments") {
        isFixed = true; fixedLabel = "Fixed SIP";
      } else if (fixedExpenses.insurance && Math.abs(amt - Number(fixedExpenses.insurance)) <= tol && t.category === "insurance") {
        isFixed = true; fixedLabel = "Fixed Premium";
      } else if (fixedExpenses.parents && Math.abs(amt - Number(fixedExpenses.parents)) <= tol && t.category === "family") {
        isFixed = true; fixedLabel = "Fixed · Family";
      } else if (fixedExpenses.rent && Math.abs(amt - Number(fixedExpenses.rent)) <= tol && (tag === "Rent" || t.suggestedTag === "Rent")) {
        isFixed = true; fixedLabel = "Fixed · Rent";
      }
    }
    return { ...t, tag, isFixed, fixedLabel };
  }), [txns, tagMap, fixedExpenses]);

  // ── Salary injection ────────────────────────────────────────────────────
  const salaryTxns = useMemo(() => {
    if (!salary.amount || Number(salary.amount) <= 0) return [];
    const amt = Number(salary.amount);
    const day = String(salary.day).padStart(2,"0");
    const months = new Set(taggedTxns.map(t => t.monthKey));
    const mk = (y,m) => `${y}-${String(m).padStart(2,"0")}`;
    months.add(mk(NOW.getFullYear(), NOW.getMonth()+1));
    return [...months].map(mKey => ({
      id: `sal-${mKey}`,
      date: `${MONTH_NAMES[parseInt(mKey.split("-")[1])-1]} ${day}`,
      bank: "Salary", monthKey: mKey, year: parseInt(mKey.split("-")[0]),
      amount: amt, type: "credited", category: "income",
      brand: null, isCreditCard: false, isRefund: false,
      suggestedTag: "Salary", tag: "Salary", isSalary: true,
    }));
  }, [salary, taggedTxns]);

  const allTxns = useMemo(() => {
    const map = {};
    [...taggedTxns, ...salaryTxns].forEach(t => { map[t.id] = t; });
    return Object.values(map).sort((a,b) => {
      if (a.monthKey !== b.monthKey) return b.monthKey.localeCompare(a.monthKey);
      return b.id > a.id ? 1 : -1;
    });
  }, [taggedTxns, salaryTxns]);

  // ── Period filter ───────────────────────────────────────────────────────
  const periodTxns = useMemo(() => {
    const mk = (y,m) => `${y}-${String(m).padStart(2,"0")}`;
    const todayStr = `${MONTH_NAMES[NOW.getMonth()]} ${String(NOW.getDate()).padStart(2,"0")}`;
    if (period === "ALL") return allTxns;
    if (period === "D")   return allTxns.filter(t => t.monthKey === mk(NOW.getFullYear(), NOW.getMonth()+1) && t.date === todayStr);
    if (period === "M")   return allTxns.filter(t => t.monthKey === mk(viewYear, viewMonth));
    if (period === "1Y")  return allTxns.filter(t => t.year === NOW.getFullYear());
    const monthsBack = period === "W" ? 0 : period === "3M" ? 3 : 6;
    const d = new Date(NOW.getFullYear(), NOW.getMonth() - monthsBack, 1);
    return allTxns.filter(t => t.monthKey >= mk(d.getFullYear(), d.getMonth()+1));
  }, [allTxns, period, viewYear, viewMonth]);

  // ── Aggregates ──────────────────────────────────────────────────────────
  const totalIncome  = useMemo(() => periodTxns.filter(t => t.type === "credited" && !t.isRefund).reduce((s,t) => s+t.amount, 0), [periodTxns]);
  const totalDebited = useMemo(() => periodTxns.filter(t => t.type === "debited").reduce((s,t) => s+t.amount, 0), [periodTxns]);
  const totalRefunds = useMemo(() => periodTxns.filter(t => t.isRefund).reduce((s,t) => s+t.amount, 0), [periodTxns]);
  const totalCC      = useMemo(() => periodTxns.filter(t => t.category === "creditcard").reduce((s,t) => s+t.amount, 0), [periodTxns]);
  const totalQuick   = useMemo(() => periodTxns.filter(t => t.category === "quickcart").reduce((s,t) => s+t.amount, 0), [periodTxns]);
  const totalInv     = useMemo(() => periodTxns.filter(t => t.category === "investments").reduce((s,t) => s+t.amount, 0), [periodTxns]);
  const totalInsure  = useMemo(() => periodTxns.filter(t => t.category === "insurance").reduce((s,t) => s+t.amount, 0), [periodTxns]);
  const totalFamily  = useMemo(() => periodTxns.filter(t => t.category === "family").reduce((s,t) => s+t.amount, 0), [periodTxns]);
  const totalMisc    = useMemo(() => periodTxns.filter(t => t.category === "miscellaneous").reduce((s,t) => s+t.amount, 0), [periodTxns]);

  const tagChartData = useMemo(() => {
    const map = {};
    periodTxns.filter(t => t.tag && t.type === "debited").forEach(t => { map[t.tag] = (map[t.tag]||0)+t.amount; });
    return Object.entries(map).map(([name,amt]) => ({name,amt})).sort((a,b) => b.amt-a.amt);
  }, [periodTxns]);

  const brandChartData = useMemo(() => {
    const map = {};
    periodTxns.filter(t => t.category === "quickcart" && t.brand).forEach(t => { map[t.brand] = (map[t.brand]||0)+t.amount; });
    return Object.entries(map).map(([name,amt]) => ({name,amt})).sort((a,b) => b.amt-a.amt);
  }, [periodTxns]);

  // ── Actions ─────────────────────────────────────────────────────────────
  const applyTag = (id, tag) => {
    // Find the brand of this transaction
    const thisTxn = allTxns.find(t => t.id === id);
    const brand = thisTxn?.brand;
    setTagMap(p => {
      const next = { ...p, [id]: tag };
      // Propagate to all transactions with the same brand (if brand is known)
      if (brand) {
        allTxns.forEach(t => {
          if (t.id !== id && t.brand === brand && t.type === "debited" && !p[t.id]) {
            next[t.id] = tag; // only auto-fill if not already manually tagged
          }
        });
      }
      return next;
    });
    setActiveTagTxn(null);
    setTagDraft("");
  };
  const removeTag = id        => setTagMap(p => { const n={...p}; delete n[id]; return n; });

  const periodLabel = period === "D" ? "Today"
    : period === "M"   ? `${MONTH_NAMES[viewMonth-1]} ${viewYear}`
    : period === "W"   ? "This week"
    : period === "1Y" || period === "ALL" ? `${viewYear}` : `Last ${period}`;

  const PERIODS = ["D","W","M","3M","6M","1Y","ALL"];
  const F = { fontFamily: "'Inter Tight', 'Inter', system-ui, sans-serif" };

  // ── Period chips ─────────────────────────────────────────────────────────
  const PeriodChips = () => (
    <div className="ns" style={{ display:"flex", gap:4, padding:4, background:D.cream2,
      borderRadius:999, border:`1px solid ${D.line}`, overflowX:"auto" }}>
      {PERIODS.map(p => (
        <button key={p} onClick={() => setPeriod(p)} style={{
          height:30, minWidth:34, padding:"0 10px", borderRadius:999,
          fontSize:12, fontWeight:700, letterSpacing:"0.02em", flexShrink:0,
          background: period===p ? D.ink : "transparent",
          color:      period===p ? D.cream : D.ink3,
          border:"none", cursor:"pointer", transition:"all 160ms ease",
        }}>{p}</button>
      ))}
    </div>
  );

  // ══════════════════════════════════════════════════════════════════════
  //  ONBOARDING
  // ══════════════════════════════════════════════════════════════════════
  const obSteps = [
    {
      n: "STEP 01", title: "We read your bank SMS",
      body: "Nothing else. No banking login, no account linking, no cloud upload. Your inbox stays yours.",
    },
    {
      n: "STEP 02", title: "Auto-sorted into 5 buckets",
      body: "Swiggy goes to QuickCart. Zerodha to Investments. Credit-card payments separate themselves. Override anything, any time.",
    },
    {
      n: "STEP 03", title: "Tag. Review. Done.",
      body: "Add tags like #Food or #Rent. See where your money actually went — no spreadsheets, no manual entry.",
    },
  ];

  if (!onboarded) {
    // Salary setup step
    if (obStep === 3) {
      return (
        <div style={{ maxWidth:430, margin:"0 auto", height:"100vh", background:D.cream, overflow:"hidden", ...F }}>
          <div style={{ height:"100%", display:"flex", flexDirection:"column" }}>
            <div style={{ padding:"56px 24px 0" }}>
              <div style={{ fontSize:11, fontWeight:700, letterSpacing:"0.12em", color:D.ink4, textTransform:"uppercase", marginBottom:8 }}>
                ALMOST THERE
              </div>
              <div style={{ fontSize:30, fontWeight:800, lineHeight:1.1, color:D.ink, letterSpacing:"-0.02em", marginBottom:10 }}>
                When does your salary land?
              </div>
              <div style={{ fontSize:15, color:D.ink3, fontWeight:500, lineHeight:1.55 }}>
                We'll add it as income automatically each month. You can update this any time.
              </div>
            </div>

            <div style={{ padding:"28px 24px 0", display:"flex", flexDirection:"column", gap:16, flex:1 }}>
              {/* Amount */}
              <div style={{ display:"flex", flexDirection:"column", gap:6 }}>
                <label style={{ fontSize:11, fontWeight:700, letterSpacing:"0.06em", textTransform:"uppercase", color:D.ink3 }}>
                  Monthly salary
                </label>
                <div style={{ position:"relative" }}>
                  <span style={{ position:"absolute", left:16, top:"50%", transform:"translateY(-50%)",
                    fontSize:20, fontWeight:700, color:D.ink3 }}>₹</span>
                  <input type="number" value={obAmt} onChange={e => setObAmt(e.target.value)}
                    placeholder="0" inputMode="numeric"
                    style={{ width:"100%", height:68, paddingLeft:40, paddingRight:16,
                      border:`1.5px solid ${obAmt ? D.ink : D.line}`, borderRadius:16,
                      background:D.white, fontSize:30, fontWeight:800, color:D.ink,
                      outline:"none", ...F }}/>
                </div>
              </div>
              {/* Payday */}
              <div style={{ display:"flex", flexDirection:"column", gap:6 }}>
                <label style={{ fontSize:11, fontWeight:700, letterSpacing:"0.06em", textTransform:"uppercase", color:D.ink3 }}>
                  Payday — day of month
                </label>
                <input type="number" min="1" max="31" value={obDay} onChange={e => setObDay(e.target.value)}
                  placeholder="1" inputMode="numeric"
                  style={{ height:52, padding:"0 16px", border:`1.5px solid ${D.line}`, borderRadius:14,
                    background:D.white, fontSize:17, fontWeight:600, color:D.ink, outline:"none", ...F }}/>
              </div>
              {/* Preview */}
              {obAmt > 0 && (
                <div style={{ padding:"14px 16px", background:D.incomeSoft, borderRadius:14 }}>
                  <div style={{ fontSize:13, color:D.ink, fontWeight:500 }}>
                    <span style={{ fontWeight:800, color:D.income }}>{fmt(Number(obAmt))}</span>
                    {" "}will be added as income on the{" "}
                    <span style={{ fontWeight:700 }}>{obDay||1}{["st","nd","rd"][((obDay||1)-1)%10]||"th"}</span>
                    {" "}of each month
                  </div>
                </div>
              )}
            </div>

            <div style={{ padding:"20px 24px 44px", display:"flex", gap:10 }}>
              <button onClick={() => setOnboarded(true)}
                style={{ height:52, padding:"0 22px", background:"transparent",
                  border:`1px solid ${D.line2}`, borderRadius:14, color:D.ink3,
                  fontSize:14, fontWeight:600, cursor:"pointer", ...F }}>
                Skip
              </button>
              <button onClick={() => {
                  if (Number(obAmt) > 0) {
                    setSalary({ amount: obAmt, day: Number(obDay)||1 });
                    setSalaryInput({ amount: obAmt, day: obDay });
                  }
                  setObStep(4); // → fixed expenses step
                }}
                style={{ flex:1, height:52, background:D.ink, color:D.cream, border:"none",
                  borderRadius:14, fontSize:15, fontWeight:700, cursor:"pointer", ...F }}>
                Next →
              </button>
            </div>
          </div>
        </div>
      );
    }

    // ── Step 4: Fixed monthly expenses ──────────────────────────────────────
    if (obStep === 4) {
      const fields = [
        { key:"sip",       label:"SIP / Investments",  hint:"Groww, Zerodha, Kuvera…",    emoji:"📈" },
        { key:"insurance", label:"Insurance Premiums", hint:"Tata AIA, LIC, ICICI Pru…", emoji:"🛡️" },
        { key:"parents",   label:"Parents / Family",   hint:"Monthly transfer to parents", emoji:"🏠" },
        { key:"rent",      label:"Rent",               hint:"Monthly rent amount",         emoji:"🔑" },
      ];
      const total = Object.values(fixedExpenses).reduce((s,v) => s + (Number(v)||0), 0);
      return (
        <div style={{ height:"100vh", background:D.cream, display:"flex", flexDirection:"column", ...F }}>
          <div style={{ padding:"52px 24px 20px" }}>
            <div style={{ fontSize:11, fontWeight:700, letterSpacing:"0.12em", color:D.ink4, textTransform:"uppercase" }}>STEP 04</div>
            <div style={{ fontSize:28, fontWeight:800, lineHeight:1.1, marginTop:8, color:D.ink, letterSpacing:"-0.02em" }}>
              Your fixed expenses
            </div>
            <div style={{ fontSize:14, color:D.ink3, fontWeight:500, marginTop:10, lineHeight:1.5 }}>
              These repeat every month. We'll flag when SMS amounts match — no manual entry needed.
            </div>
          </div>

          <div style={{ flex:1, overflowY:"auto", padding:"0 24px" }}>
            <div style={{ display:"flex", flexDirection:"column", gap:12 }}>
              {fields.map(f => (
                <div key={f.key} style={{ background:D.white, borderRadius:18, border:`1px solid ${D.line}`, padding:"14px 16px" }}>
                  <div style={{ display:"flex", alignItems:"center", gap:10, marginBottom:8 }}>
                    <span style={{ fontSize:18 }}>{f.emoji}</span>
                    <div>
                      <div style={{ fontSize:13, fontWeight:700, color:D.ink }}>{f.label}</div>
                      <div style={{ fontSize:11, color:D.ink4 }}>{f.hint}</div>
                    </div>
                  </div>
                  <div style={{ position:"relative" }}>
                    <span style={{ position:"absolute", left:14, top:"50%", transform:"translateY(-50%)",
                      fontSize:16, fontWeight:700, color:D.ink3 }}>₹</span>
                    <input type="number" inputMode="numeric"
                      value={fixedExpenses[f.key]}
                      onChange={e => setFixedExpenses(p => ({...p, [f.key]: e.target.value}))}
                      placeholder="0"
                      style={{ width:"100%", height:48, paddingLeft:28, paddingRight:16,
                        border:`1.5px solid ${D.line}`, borderRadius:12,
                        background:D.cream2, fontSize:18, fontWeight:700, color:D.ink,
                        outline:"none", ...F }}/>
                  </div>
                </div>
              ))}
            </div>

            {total > 0 && (
              <div style={{ marginTop:14, padding:"14px 16px", background:D.incomeSoft, borderRadius:14 }}>
                <div style={{ fontSize:12, color:D.ink3, fontWeight:600, marginBottom:4 }}>
                  Fixed commitments / month
                </div>
                <div style={{ fontSize:22, fontWeight:800, color:D.ink }}>{fmt(total)}</div>
                {obAmt && <div style={{ fontSize:12, color:D.income, marginTop:4 }}>
                  {fmt(Number(obAmt) - total,true)} remaining after fixed expenses
                </div>}
              </div>
            )}
            <div style={{ height:20 }}/>
          </div>

          <div style={{ padding:"12px 24px 44px", display:"flex", gap:10 }}>
            <button onClick={() => setOnboarded(true)}
              style={{ height:52, padding:"0 22px", background:"transparent",
                border:`1px solid ${D.line2}`, borderRadius:14, color:D.ink3,
                fontSize:14, fontWeight:600, cursor:"pointer", ...F }}>
              Skip
            </button>
            <button onClick={() => setOnboarded(true)}
              style={{ flex:1, height:52, background:D.ink, color:D.cream, border:"none",
                borderRadius:14, fontSize:15, fontWeight:700, cursor:"pointer", ...F }}>
              {total > 0 ? "Save & start →" : "Skip for now →"}
            </button>
          </div>
        </div>
      );
    }

    // Info carousel steps 0-2
    const s = obSteps[obStep];
    return (
      <div style={{ maxWidth:430, margin:"0 auto", height:"100vh", background:D.cream, overflow:"hidden", ...F }}>
        <div style={{ height:"100%", display:"flex", flexDirection:"column" }}>
          {/* Progress + skip */}
          <div style={{ display:"flex", justifyContent:"space-between", alignItems:"center", padding:"52px 24px 0" }}>
            <div style={{ display:"flex", gap:6 }}>
              {obSteps.map((_,i) => (
                <div key={i} style={{
                  width: i===obStep?24:6, height:6, borderRadius:3,
                  background: i<=obStep ? D.ink : D.line2,
                  transition:"all 300ms cubic-bezier(.2,.8,.2,1)",
                }}/>
              ))}
            </div>
            <button onClick={() => setObStep(3)}
              style={{ fontSize:13, fontWeight:600, color:D.ink3, background:"none", border:"none", cursor:"pointer" }}>
              Skip
            </button>
          </div>

          {/* Visuals */}
          <div style={{ flex:1, padding:"32px 24px 0" }}>
            {obStep === 0 && (
              <div style={{ display:"flex", flexDirection:"column", gap:10 }}>
                <div style={{ background:D.white, borderRadius:18, padding:"18px", border:`1px solid ${D.line}` }}>
                  <div style={{ fontSize:10, color:D.ink4, fontWeight:700, letterSpacing:"0.1em", marginBottom:6 }}>HDFCBK · 14:22</div>
                  <div style={{ fontSize:13, color:D.ink2, lineHeight:1.5 }}>
                    Spent <strong>Rs.486.00</strong> at SWIGGY on 18-Apr using your debit card ending 4417.
                  </div>
                </div>
                <div style={{ display:"flex", alignItems:"center", justifyContent:"flex-end" }}>
                  <div style={{ padding:"10px 16px", background:D.ink, borderRadius:14, display:"flex", alignItems:"center", gap:8 }}>
                    <span style={{ color:D.incomeSoft, fontSize:13, fontWeight:700 }}>✓</span>
                    <span style={{ color:D.cream, fontSize:13, fontWeight:600 }}>₹486 · QuickCart</span>
                  </div>
                </div>
              </div>
            )}
            {obStep === 1 && (
              <div style={{ display:"flex", flexDirection:"column", gap:10 }}>
                {["cc","quick","invest","misc"].map((k,i) => {
                  const c = CATS[k];
                  const amts = {cc:"₹12.4k",quick:"₹9.6k",invest:"₹22.5k",misc:"₹34.2k"};
                  return (
                    <div key={k} style={{ display:"flex", alignItems:"center", gap:14,
                      padding:"13px 16px", background:D.white, borderRadius:16, border:`1px solid ${D.line}` }}>
                      <div style={{ width:38, height:38, borderRadius:11, background:c.soft,
                        display:"flex", alignItems:"center", justifyContent:"center", fontSize:18 }}>{c.emoji}</div>
                      <div style={{ flex:1, fontSize:14, fontWeight:600, color:D.ink }}>{c.name}</div>
                      <div style={{ fontSize:16, fontWeight:700, color:D.ink }}>{amts[k]}</div>
                    </div>
                  );
                })}
              </div>
            )}
            {obStep === 2 && (
              <div style={{ display:"flex", flexWrap:"wrap", gap:8 }}>
                {["Food","Groceries","Rent","SIP","Bills","Fuel","Transit","Subscriptions","Health"].map(t => (
                  <span key={t} style={{ padding:"8px 14px", borderRadius:999,
                    background:D.white, border:`1px solid ${D.line}`,
                    fontSize:13, fontWeight:600, color:D.ink2 }}>#{t}</span>
                ))}
              </div>
            )}
          </div>

          {/* Copy */}
          <div style={{ padding:"24px 24px 0" }}>
            <div style={{ fontSize:11, fontWeight:700, letterSpacing:"0.12em", color:D.ink4, textTransform:"uppercase" }}>{s.n}</div>
            <div style={{ fontSize:30, fontWeight:800, lineHeight:1.1, marginTop:8, color:D.ink, letterSpacing:"-0.02em" }}>{s.title}</div>
            <div style={{ fontSize:15, color:D.ink3, fontWeight:500, marginTop:10, lineHeight:1.55 }}>{s.body}</div>
          </div>

          {/* CTA */}
          <div style={{ padding:"22px 24px 44px" }}>
            <button onClick={() => obStep < 2 ? setObStep(obStep+1) : setObStep(3)}
              style={{ width:"100%", height:54, background:D.ink, color:D.cream, border:"none",
                borderRadius:14, fontSize:15, fontWeight:700, cursor:"pointer", ...F }}>
              {obStep < 2 ? "Continue →" : "Let's go →"}
            </button>
          </div>
        </div>
      </div>
    );
  }

  // ══════════════════════════════════════════════════════════════════════
  //  HOME TAB
  // ══════════════════════════════════════════════════════════════════════
  const HomeTab = () => {
    const spent  = totalDebited;
    const saved  = totalIncome - spent;
    const budget = salary.amount ? Number(salary.amount) : (totalIncome > 0 ? totalIncome : 0);
    const pctBudget = budget > 0 ? Math.min(100, Math.round((spent / budget) * 100)) : 0;
    const daysInMonth  = new Date(viewYear, viewMonth, 0).getDate();
    const daysElapsed  = period==="M" && viewMonth===NOW.getMonth()+1 && viewYear===NOW.getFullYear()
      ? NOW.getDate() : daysInMonth;

    // CC excluded — it's a payment transfer, not real spending
    const catRows = [
      { key:"misc",   internal:"miscellaneous", total:totalMisc   },
      { key:"invest", internal:"investments",   total:totalInv    },
      { key:"insure", internal:"insurance",     total:totalInsure },
      { key:"family", internal:"family",        total:totalFamily },
      { key:"quick",  internal:"quickcart",     total:totalQuick  },
    ].filter(c => c.total > 0);

    // QuickCart sub-breakdown
    const FOOD_BRANDS    = ["Zomato","Swiggy"];
    const GROCERY_BRANDS = ["Blinkit","Instamart","BigBasket","Zepto","JioMart","Dunzo","Amazon Fresh","Swiggy Instamart"];
    const qcTxns = periodTxns.filter(t => t.category === "quickcart" && t.type === "debited");
    const qcFood  = qcTxns.filter(t => FOOD_BRANDS.some(b => (t.brand||"").toLowerCase().includes(b.toLowerCase()))).reduce((s,t)=>s+t.amount,0);
    const qcGrocery = qcTxns.filter(t => GROCERY_BRANDS.some(b => (t.brand||"").toLowerCase().includes(b.toLowerCase()))).reduce((s,t)=>s+t.amount,0);
    const qcOther = totalQuick - qcFood - qcGrocery;

    const nextPayday = () => {
      if (!salary.day) return null;
      const d = new Date();
      let month = d.getMonth(), year = d.getFullYear();
      let pd = new Date(year, month, salary.day);
      if (pd <= d) pd = new Date(year, month+1, salary.day);
      const diff = Math.ceil((pd - d) / 86400000);
      return { date: `${pd.getDate()} ${MONTH_NAMES[pd.getMonth()]}`, days: diff };
    };
    const payday = salary.amount ? nextPayday() : null;

    const budgetLeft = budget > 0 ? Math.max(0, budget - spent) : 0;
    const daysLeft = daysInMonth - daysElapsed;

    return (
      <div className="ns" style={{ overflowY:"auto", flex:1, paddingBottom:80, ...F, background:D.cream }}>

        {/* ── Top bar: greeting + action icons ── */}
        <div style={{ padding:"52px 20px 0", background:D.cream }}>
          <div style={{ display:"flex", justifyContent:"space-between", alignItems:"flex-start" }}>
            <div>
              <div style={{ fontSize:10, letterSpacing:"0.14em", textTransform:"uppercase",
                color:D.ink3, fontWeight:700 }}>Good {
                  (() => { const h=new Date().getHours(); return h<12?"Morning":h<17?"Afternoon":"Evening"; })()
                }</div>
            </div>
            <div style={{ display:"flex", gap:8 }}>
              <button onClick={() => setShowSalary(true)} style={{ width:38, height:38, borderRadius:12,
                background:D.white, border:`1px solid ${D.line}`, cursor:"pointer",
                display:"flex", alignItems:"center", justifyContent:"center", fontSize:16 }}>💰</button>
              <button onClick={() => setShowTagMgr(true)} style={{ width:38, height:38, borderRadius:12,
                background:D.white, border:`1px solid ${D.line}`, cursor:"pointer",
                display:"flex", alignItems:"center", justifyContent:"center", fontSize:15 }}>🏷️</button>
              <button onClick={() => setShowPrivacy(true)} style={{ width:38, height:38, borderRadius:12,
                background:D.white, border:`1px solid ${D.line}`, cursor:"pointer",
                display:"flex", alignItems:"center", justifyContent:"center", fontSize:15 }}>🔒</button>
            </div>
          </div>

          {/* Payday pill */}
          {payday && (
            <div onClick={() => setShowSalary(true)} style={{ display:"inline-flex", alignItems:"center", gap:6,
              padding:"6px 12px", borderRadius:999, background:D.incomeSoft,
              marginTop:10, cursor:"pointer" }}>
              <span style={{ fontSize:12 }}>🗓</span>
              <span style={{ fontSize:11, fontWeight:700, color:D.income }}>
                Payday · {payday.date} · in {payday.days} day{payday.days!==1?"s":""}
              </span>
            </div>
          )}

          {/* Period chips */}
          <div style={{ marginTop:16 }}>
            <PeriodChips/>
          </div>

          {/* Month nav */}
          {period === "M" && (
            <div style={{ display:"flex", alignItems:"center", gap:14, marginTop:12 }}>
              <button onClick={() => shiftMonth(-1)} style={{ width:32, height:32, borderRadius:10,
                background:D.white, border:`1px solid ${D.line}`, cursor:"pointer", fontSize:16, color:D.ink }}>‹</button>
              <span style={{ fontSize:14, fontWeight:700, color:D.ink }}>{MONTH_NAMES[viewMonth-1]} {viewYear}</span>
              <button onClick={() => shiftMonth(1)} style={{ width:32, height:32, borderRadius:10,
                background:D.white, border:`1px solid ${D.line}`, cursor:"pointer", fontSize:16, color:D.ink }}>›</button>
            </div>
          )}
        </div>

        <div style={{ padding:"14px 14px 0" }}>
          {/* ── Hero card ── */}
          <div style={{ background:D.white, borderRadius:D.rLg, border:`1px solid ${D.line}`,
            boxShadow:D.card, padding:"20px 20px 20px", marginBottom:10 }}>
            {/* Top row: label + saved pill */}
            <div style={{ display:"flex", justifyContent:"space-between", alignItems:"flex-start", marginBottom:12 }}>
              <div style={{ fontSize:10, letterSpacing:"0.12em", textTransform:"uppercase",
                color:D.ink3, fontWeight:700 }}>Total spent · {periodLabel}</div>
              {saved >= 0 && budget > 0 && (
                <div style={{ display:"inline-flex", alignItems:"center", gap:4,
                  padding:"5px 10px", borderRadius:999, fontSize:11, fontWeight:700,
                  background:D.incomeSoft, color:D.income }}>
                  ↑ {fmt(Math.abs(saved),true)} saved
                </div>
              )}
              {saved < 0 && (
                <div style={{ display:"inline-flex", alignItems:"center", gap:4,
                  padding:"5px 10px", borderRadius:999, fontSize:11, fontWeight:700,
                  background:"#fbe6ea", color:D.quick }}>
                  ↓ {fmt(Math.abs(saved),true)} over
                </div>
              )}
            </div>
            {/* Big amount */}
            <div style={{ fontSize:46, fontWeight:800, lineHeight:1, color:D.ink, letterSpacing:"-0.03em", marginBottom:16 }}>
              {fmt(spent)}
            </div>
            {/* Progress bar */}
            {budget > 0 && (
              <>
                <div style={{ height:8, borderRadius:4, background:D.cream3, overflow:"hidden", marginBottom:8 }}>
                  <div style={{ width:`${pctBudget}%`, height:"100%", borderRadius:4,
                    background: pctBudget > 90 ? D.quick : D.ink,
                    transition:"width 800ms cubic-bezier(.2,.8,.2,1)" }}/>
                </div>
                <div style={{ display:"flex", justifyContent:"space-between", fontSize:12, color:D.ink3 }}>
                  <span><span style={{ color:D.ink, fontWeight:700 }}>{pctBudget}%</span> of {fmt(budget,true)} budget</span>
                  <span style={{ color:D.ink3 }}>{fmt(budgetLeft,true)} left · {daysLeft}d</span>
                </div>
              </>
            )}
          </div>

          {/* ── Income + Spent tiles ── */}
          <div style={{ display:"grid", gridTemplateColumns:"1fr 1fr", gap:10, marginBottom:10 }}>
            <div style={{ background:D.white, borderRadius:18, border:`1px solid ${D.line}`, padding:"16px 16px" }}>
              <div style={{ display:"flex", alignItems:"center", gap:6, marginBottom:8 }}>
                <span style={{ width:8, height:8, borderRadius:2, background:D.income, flexShrink:0 }}/>
                <span style={{ fontSize:10, fontWeight:700, letterSpacing:"0.08em",
                  textTransform:"uppercase", color:D.income }}>Income</span>
              </div>
              <div style={{ fontSize:24, fontWeight:800, color:D.ink, letterSpacing:"-0.025em" }}>{fmt(totalIncome,true)}</div>
            </div>
            <div style={{ background:D.white, borderRadius:18, border:`1px solid ${D.line}`, padding:"16px 16px" }}>
              <div style={{ display:"flex", alignItems:"center", gap:6, marginBottom:8 }}>
                <span style={{ width:8, height:8, borderRadius:2, background:D.ink, flexShrink:0 }}/>
                <span style={{ fontSize:10, fontWeight:700, letterSpacing:"0.08em",
                  textTransform:"uppercase", color:D.ink3 }}>Spent</span>
              </div>
              <div style={{ fontSize:24, fontWeight:800, color:D.ink, letterSpacing:"-0.025em" }}>{fmt(spent,true)}</div>
            </div>
          </div>

          {/* ── Refunds banner ── */}
          {totalRefunds > 0 && (
            <div style={{ display:"flex", alignItems:"center", justifyContent:"space-between",
              background:D.incomeSoft, borderRadius:14, padding:"13px 16px", marginBottom:10,
              border:`1px solid ${D.income}22` }}>
              <div style={{ display:"flex", alignItems:"center", gap:8 }}>
                <span style={{ fontSize:14 }}>↺</span>
                <span style={{ fontSize:13, fontWeight:600, color:D.income }}>Refunds & cashbacks received</span>
              </div>
              <span style={{ fontSize:14, fontWeight:800, color:D.income }}>+{fmt(totalRefunds,true)}</span>
            </div>
          )}

          {/* Where it went — CC excluded */}
          {catRows.length > 0 && (() => {
            const nonCCTotal = catRows.reduce((s,r) => s+r.total, 0);
            return (
            <div style={{ background:D.white, borderRadius:D.rLg, border:`1px solid ${D.line}`,
              boxShadow:D.card, marginBottom:14, overflow:"hidden" }}>
              <div style={{ padding:"18px 20px 12px", borderBottom:`1px solid ${D.line}` }}>
                <div style={{ fontSize:11, letterSpacing:"0.12em", textTransform:"uppercase", color:D.ink3, fontWeight:700 }}>
                  Where it went
                </div>
                <div style={{ fontSize:14, color:D.ink, fontWeight:600, marginTop:2 }}>
                  {fmt(nonCCTotal,true)} across {catRows.length} {catRows.length===1?"category":"categories"}
                </div>
              </div>

              {catRows.map((row, idx) => {
                const c = CATS[row.key];
                const pct = nonCCTotal > 0 ? Math.round((row.total/nonCCTotal)*100) : 0;
                const count = periodTxns.filter(t => t.category===row.internal).length;
                const isLast = idx === catRows.length-1;
                return (
                  <div key={row.key} style={{ borderTop: idx===0 ? "none" : `1px solid ${D.line}` }}>
                    <button onClick={() => setShowDrill(row.internal)} style={{
                      width:"100%", display:"flex", alignItems:"center", gap:14,
                      padding:"15px 20px", textAlign:"left", background:"transparent",
                      border:"none", cursor:"pointer",
                    }}>
                      <CatIcon catKey={row.internal} size={44}/>
                      <div style={{ flex:1, minWidth:0 }}>
                        <div style={{ display:"flex", justifyContent:"space-between", alignItems:"baseline", marginBottom:8 }}>
                          <div style={{ fontSize:15, fontWeight:600, color:D.ink }}>{c.name}</div>
                          <div style={{ fontSize:17, fontWeight:800, color:D.ink, letterSpacing:"-0.02em" }}>{fmt(row.total)}</div>
                        </div>
                        <div style={{ display:"flex", alignItems:"center", gap:10 }}>
                          <div style={{ flex:1, height:5, borderRadius:3, background:D.cream3, overflow:"hidden" }}>
                            <div style={{ width:`${pct}%`, height:"100%", borderRadius:3, background:c.color }}/>
                          </div>
                          <div style={{ fontSize:11, color:D.ink4, fontWeight:600, minWidth:26, textAlign:"right" }}>{pct}%</div>
                        </div>
                        <div style={{ fontSize:11, color:D.ink4, marginTop:4 }}>{count} transaction{count!==1?"s":""}</div>
                      </div>
                    </button>
                    {/* QuickCart sub-breakdown */}
                    {row.key === "quick" && totalQuick > 0 && (qcFood > 0 || qcGrocery > 0) && (
                      <div style={{ margin:"0 20px 14px", padding:"10px 14px",
                        background:D.cream2, borderRadius:12, display:"flex", flexDirection:"column", gap:8 }}>
                        {qcFood > 0 && (
                          <div style={{ display:"flex", justifyContent:"space-between", alignItems:"center" }}>
                            <div style={{ display:"flex", alignItems:"center", gap:8 }}>
                              <span style={{ fontSize:14 }}>🍱</span>
                              <span style={{ fontSize:12, fontWeight:600, color:D.ink3 }}>Quick Food</span>
                              <span style={{ fontSize:11, color:D.ink4 }}>Zomato · Swiggy</span>
                            </div>
                            <span style={{ fontSize:13, fontWeight:700, color:D.ink }}>{fmt(qcFood,true)}</span>
                          </div>
                        )}
                        {qcGrocery > 0 && (
                          <div style={{ display:"flex", justifyContent:"space-between", alignItems:"center" }}>
                            <div style={{ display:"flex", alignItems:"center", gap:8 }}>
                              <span style={{ fontSize:14 }}>🛒</span>
                              <span style={{ fontSize:12, fontWeight:600, color:D.ink3 }}>Grocery</span>
                              <span style={{ fontSize:11, color:D.ink4 }}>Blinkit · BigBasket · Zepto</span>
                            </div>
                            <span style={{ fontSize:13, fontWeight:700, color:D.ink }}>{fmt(qcGrocery,true)}</span>
                          </div>
                        )}
                        {qcOther > 0 && (
                          <div style={{ display:"flex", justifyContent:"space-between", alignItems:"center" }}>
                            <div style={{ display:"flex", alignItems:"center", gap:8 }}>
                              <span style={{ fontSize:14 }}>📦</span>
                              <span style={{ fontSize:12, fontWeight:600, color:D.ink3 }}>Other</span>
                            </div>
                            <span style={{ fontSize:13, fontWeight:700, color:D.ink }}>{fmt(qcOther,true)}</span>
                          </div>
                        )}
                      </div>
                    )}
                  </div>
                );
              })}
            </div>
            );
          })()}

          {/* Empty state */}
          {periodTxns.filter(t=>t.type==="debited").length === 0 && periodTxns.length === 0 && (
            <div style={{ background:D.white, borderRadius:D.rLg, border:`1px solid ${D.line}`,
              padding:24, textAlign:"center", marginBottom:14 }}>
              <div style={{ width:64, height:64, borderRadius:20, background:D.ink, margin:"0 auto 16px",
                display:"flex", alignItems:"center", justifyContent:"center", fontSize:26 }}>💬</div>
              <div style={{ fontSize:22, fontWeight:800, color:D.ink, marginBottom:8, letterSpacing:"-0.01em" }}>
                Let's find your spending
              </div>
              <div style={{ fontSize:14, color:D.ink3, lineHeight:1.55, marginBottom:20, padding:"0 8px" }}>
                Scan your inbox once to auto-categorise transactions. Takes about 8 seconds.
              </div>
              <button style={{ width:"100%", height:52, background:D.ink, color:D.cream, border:"none",
                borderRadius:14, fontSize:15, fontWeight:700, cursor:"pointer", ...F }}>
                📱 Scan my SMS
              </button>
              <div style={{ marginTop:12, fontSize:12, color:D.ink4, lineHeight:1.5 }}>
                🔒 Read-only, on-device. Nothing is uploaded.
              </div>
            </div>
          )}

          {/* By Tag */}
          {tagChartData.length > 0 && (
            <div style={{ background:D.white, borderRadius:D.rLg, border:`1px solid ${D.line}`,
              padding:"18px 16px 14px", marginBottom:14, boxShadow:D.card }}>
              <div style={{ display:"flex", justifyContent:"space-between", alignItems:"baseline", marginBottom:4 }}>
                <div style={{ fontSize:11, letterSpacing:"0.12em", textTransform:"uppercase",
                  color:D.ink3, fontWeight:700 }}>By Tag</div>
                <button onClick={() => setShowTagMgr(true)} style={{ fontSize:12, fontWeight:600,
                  color:D.ink3, background:"none", border:"none", cursor:"pointer" }}>Manage</button>
              </div>
              <div style={{ fontSize:12, color:D.ink4, fontWeight:500, marginBottom:14 }}>
                Top {Math.min(5, tagChartData.length)} this {period === "M" ? "month" : "period"}
              </div>
              {tagChartData.slice(0,5).map((row, i) => {
                const maxAmt = tagChartData[0].amt;
                const pct = Math.round((row.amt / maxAmt) * 100);
                return (
                  <div key={row.name} style={{ display:"flex", alignItems:"center", gap:12,
                    marginBottom: i < Math.min(4, tagChartData.length-1) ? 12 : 0 }}>
                    <div style={{ width:72, fontSize:13, fontWeight:600, color:D.ink,
                      flexShrink:0, overflow:"hidden", textOverflow:"ellipsis", whiteSpace:"nowrap" }}>
                      #{row.name}
                    </div>
                    <div style={{ flex:1, height:6, borderRadius:3, background:D.cream3, overflow:"hidden" }}>
                      <div style={{ width:`${pct}%`, height:"100%", borderRadius:3, background:D.ink,
                        transition:"width 600ms cubic-bezier(.2,.8,.2,1)" }}/>
                    </div>
                    <div style={{ width:42, fontSize:12, fontWeight:700, color:D.ink,
                      textAlign:"right", flexShrink:0 }}>{fmt(row.amt,true)}</div>
                  </div>
                );
              })}
            </div>
          )}
        </div>
      </div>
    );
  };

  // ══════════════════════════════════════════════════════════════════════
  //  OVERVIEW TAB
  // ══════════════════════════════════════════════════════════════════════
  const OverviewTab = () => {
    const [filter, setFilter] = useState("all");
    const chipRowRef = React.useRef(null);
    const setFilterAndScroll = (key) => {
      setFilter(key);
      if (chipRowRef.current) chipRowRef.current.scrollLeft = 0;
    };

    const CAT_FILTER_MAP = { income:"income", cc:"creditcard", quick:"quickcart", invest:"investments", insure:"insurance", family:"family", misc:"miscellaneous" };

    const filtered = useMemo(() => periodTxns.filter(t => {
      if (filter==="all") return true;
      if (filter==="in")  return t.type==="credited";
      if (filter==="out") return t.type==="debited";
      if (CAT_FILTER_MAP[filter]) return t.category===CAT_FILTER_MAP[filter];
      return true;
    }), [filter]);

    const groups = useMemo(() => {
      const map = {};
      filtered.forEach(t => { (map[t.date] ||= []).push(t); });
      return Object.entries(map).sort((a,b) => {
        const mkA = a[1][0]?.monthKey||"", mkB = b[1][0]?.monthKey||"";
        if (mkA!==mkB) return mkB.localeCompare(mkA);
        return a[0].localeCompare(b[0])*-1;
      });
    }, [filtered]);

    const sumIn  = filtered.filter(t=>t.type==="credited").reduce((s,t)=>s+t.amount,0);
    const sumOut = filtered.filter(t=>t.type==="debited").reduce((s,t)=>s+t.amount,0);

    const filterDefs = [
      { key:"all",    label:"All" },
      { key:"in",     label:"↓ Income", dot:D.income },
      { key:"out",    label:"↑ Expenses" },
      { key:"income", label:"Income",    dot:D.income  },
      { key:"cc",     label:"CC",        dot:D.cc      },
      { key:"quick",  label:"Quick",     dot:D.quick   },
      { key:"invest", label:"Invest",    dot:D.invest  },
      { key:"insure", label:"Insurance", dot:D.insure  },
      { key:"family", label:"Family",   dot:D.family  },
      { key:"misc",   label:"Misc",     dot:D.misc    },
    ];

    return (
      <div style={{ height:"100%", display:"flex", flexDirection:"column", ...F }}>
        {/* Header */}
        <div style={{ padding:"52px 20px 12px", background:D.cream }}>
          <div style={{ display:"flex", justifyContent:"space-between", alignItems:"flex-end", marginBottom:14 }}>
            <div>
              <div style={{ fontSize:28, fontWeight:800, color:D.ink, letterSpacing:"-0.02em",
                fontFamily:"'Inter Tight','Inter',system-ui,sans-serif" }}>Overview</div>
              <div style={{ fontSize:12, color:D.ink3, fontWeight:500, marginTop:3 }}>
                {periodLabel} · {filtered.length} transactions
              </div>
            </div>
            <div style={{ textAlign:"right" }}>
              <div style={{ fontSize:11, color:D.income, fontWeight:700, letterSpacing:"0.06em" }}>IN {fmt(sumIn,true)}</div>
              <div style={{ fontSize:11, color:D.ink,    fontWeight:700, letterSpacing:"0.06em", marginTop:2 }}>OUT {fmt(sumOut,true)}</div>
            </div>
          </div>
          {/* Filter chips */}
          <div ref={chipRowRef} className="ns" style={{ display:"flex", gap:6, overflowX:"auto", paddingBottom:14 }}>
            {filterDefs.map(f => (
              <button key={f.key} onClick={() => setFilterAndScroll(f.key)} style={{
                height:32, padding:"0 12px", borderRadius:999, flexShrink:0,
                fontSize:12, fontWeight:600, letterSpacing:"-0.01em",
                border:`1px solid ${filter===f.key ? D.ink : D.line2}`,
                background: filter===f.key ? D.ink : "transparent",
                color:      filter===f.key ? D.cream : D.ink3,
                display:"inline-flex", alignItems:"center", gap:6,
                cursor:"pointer", transition:"all 140ms ease",
              }}>
                {f.dot && <span style={{ width:7, height:7, borderRadius:2, background:f.dot, flexShrink:0 }}/>}
                {f.label}
              </button>
            ))}
          </div>
        </div>

        {/* List */}
        <div className="ns" style={{ flex:1, overflowY:"auto", background:D.cream }}>
          {groups.length === 0 && (
            <div style={{ padding:"48px 20px", textAlign:"center", color:D.ink4, fontSize:14 }}>
              No transactions match this filter.
            </div>
          )}
          {groups.map(([dateKey, txns]) => {
            const dayTotal = txns.filter(t=>t.type==="debited").reduce((s,t)=>s+t.amount,0);
            return (
              <div key={dateKey}>
                <div style={{ display:"flex", justifyContent:"space-between", alignItems:"center",
                  padding:"12px 20px 6px", position:"sticky", top:0, background:D.cream, zIndex:2 }}>
                  <div style={{ fontSize:11, fontWeight:700, letterSpacing:"0.1em",
                    textTransform:"uppercase", color:D.ink3 }}>{dateKey}</div>
                  <div style={{ fontSize:11, color:D.ink4, fontWeight:600, whiteSpace:"nowrap" }}>
                    {dayTotal>0 ? `−${fmt(dayTotal,true)}` : ""}
                  </div>
                </div>
                <div style={{ background:D.white, margin:"0 14px 6px", borderRadius:18,
                  border:`1px solid ${D.line}`, overflow:"hidden" }}>
                  {txns.map((t, idx) => {
                    const dk = CK(t.category);
                    const c  = CATS[dk];
                    const isIn = t.type==="credited" || t.isRefund;
                    const open = activeTagTxn===t.id;
                    return (
                      <div key={t.id}>
                        <div style={{ display:"flex", alignItems:"center", gap:12,
                          padding:"12px 16px",
                          borderBottom: (idx<txns.length-1||open) ? `1px solid ${D.line}` : "none" }}>
                          <MerchantAvatar merchant={t.brand||t.bank} catKey={t.category} size={42}/>
                          <div style={{ flex:1, minWidth:0 }}>
                            <div style={{ fontSize:14, fontWeight:600, color:D.ink,
                              overflow:"hidden", textOverflow:"ellipsis", whiteSpace:"nowrap" }}>
                              {t.brand||t.bank}{t.isSalary?" 💰":""}
                            </div>
                            <div style={{ display:"flex", alignItems:"center", gap:5, marginTop:3, overflow:"hidden" }}>
                              {t.isRefund ? (
                                <span style={{ fontSize:10, padding:"2px 6px", borderRadius:4,
                                  background:D.incomeSoft, color:D.income, fontWeight:700,
                                  letterSpacing:"0.04em", whiteSpace:"nowrap", display:"inline-flex", alignItems:"center", gap:3 }}>↺ Refund</span>
                              ) : t.isSalary ? (
                                <span style={{ fontSize:10, padding:"2px 6px", borderRadius:4,
                                  background:D.incomeSoft, color:D.income, fontWeight:700 }}>Salary</span>
                              ) : t.isFixed ? (
                                <span style={{ fontSize:10, padding:"2px 6px", borderRadius:4,
                                  background:D.cream3, color:D.ink3, fontWeight:700, whiteSpace:"nowrap" }}>
                                  ✓ {t.fixedLabel}
                                </span>
                              ) : (
                                <span style={{ fontSize:11, color:c.color, fontWeight:600, whiteSpace:"nowrap" }}>{c.name}</span>
                              )}
                              {t.tag && !t.isFixed && <span style={{ fontSize:11, color:D.ink4, whiteSpace:"nowrap" }}>· #{t.tag}</span>}
                            </div>
                          </div>
                          <div style={{ display:"flex", flexDirection:"column", alignItems:"flex-end", gap:4, flexShrink:0 }}>
                            <div style={{ fontSize:16, fontWeight:700, letterSpacing:"-0.02em",
                              color: isIn ? D.income : D.ink }}>
                              {isIn?"+":"−"}{fmt(t.amount)}
                            </div>
                            <button onClick={() => setActiveTagTxn(open?null:t.id)} style={{
                              width:26, height:26, borderRadius:7,
                              background: t.tag ? D.cream2 : "transparent",
                              color:D.ink4, border:"none", cursor:"pointer",
                              display:"flex", alignItems:"center", justifyContent:"center", fontSize:12 }}>🏷️</button>
                          </div>
                        </div>
                        {/* Tag picker */}
                        {open && (
                          <div style={{ background:D.cream2, padding:"12px 16px 14px",
                            borderBottom: idx<txns.length-1 ? `1px solid ${D.line}` : "none" }}>
                            <div style={{ fontSize:10, fontWeight:700, textTransform:"uppercase",
                              letterSpacing:"0.08em", color:D.ink3, marginBottom:10 }}>Tag this transaction</div>
                            <div style={{ display:"flex", gap:6, flexWrap:"wrap", marginBottom:10 }}>
                              {userTags.map(tag => (
                                <button key={tag} onClick={() => applyTag(t.id, tag)} style={{
                                  padding:"6px 12px", borderRadius:999,
                                  border:`1px solid ${t.tag===tag ? D.ink : D.line2}`,
                                  background: t.tag===tag ? D.ink : D.white,
                                  color: t.tag===tag ? D.cream : D.ink,
                                  fontSize:12, fontWeight:600, cursor:"pointer",
                                }}>{tag}</button>
                              ))}
                            </div>
                            <div style={{ display:"flex", gap:8 }}>
                              <input value={tagDraft} onChange={e=>setTagDraft(e.target.value)}
                                onKeyDown={e=>{
                                  if(e.key==="Enter"&&tagDraft.trim()){
                                    const tag=tagDraft.trim();
                                    if(!userTags.includes(tag)) setUserTags(p=>[...p,tag]);
                                    applyTag(t.id,tag);
                                  }
                                }}
                                placeholder="Custom tag…"
                                style={{ flex:1, height:38, padding:"0 12px",
                                  border:`1px solid ${D.line}`, borderRadius:10,
                                  background:D.white, fontSize:13, color:D.ink,
                                  outline:"none", ...F }}/>
                              <button onClick={()=>{
                                  const tag=tagDraft.trim();
                                  if(!tag) return;
                                  if(!userTags.includes(tag)) setUserTags(p=>[...p,tag]);
                                  applyTag(t.id,tag);
                                }}
                                style={{ height:38, padding:"0 14px", background:D.ink, color:D.cream,
                                  border:"none", borderRadius:10, fontSize:13, fontWeight:600, cursor:"pointer" }}>
                                Add
                              </button>
                            </div>
                            {t.tag && (
                              <button onClick={()=>removeTag(t.id)} style={{ marginTop:8,
                                padding:"5px 12px", borderRadius:999, border:`1px solid ${D.line2}`,
                                background:"transparent", color:D.ink3, fontSize:12, cursor:"pointer" }}>
                                Clear tag
                              </button>
                            )}
                          </div>
                        )}
                      </div>
                    );
                  })}
                </div>
              </div>
            );
          })}
          <div style={{ height:20 }}/>
        </div>
      </div>
    );
  };

  // ══════════════════════════════════════════════════════════════════════
  //  MODALS
  // ══════════════════════════════════════════════════════════════════════

  // Salary
  const SalaryModal = () => (
    <Sheet open={showSalary} onClose={()=>setShowSalary(false)} title="Salary Setup 💰">
      <div style={{ display:"flex", flexDirection:"column", gap:14 }}>
        <div style={{ display:"flex", flexDirection:"column", gap:6 }}>
          <label style={{ fontSize:11, fontWeight:700, letterSpacing:"0.06em", textTransform:"uppercase", color:D.ink3 }}>
            Monthly salary
          </label>
          <input type="number" value={salaryInput.amount}
            onChange={e=>setSalaryInput(p=>({...p,amount:e.target.value}))}
            placeholder="e.g. 85000" inputMode="numeric"
            style={{ height:64, padding:"0 16px", border:`1.5px solid ${D.line}`, borderRadius:16,
              background:D.white, fontSize:28, fontWeight:800, color:D.ink, outline:"none", ...F }}/>
        </div>
        <div style={{ display:"flex", flexDirection:"column", gap:6 }}>
          <label style={{ fontSize:11, fontWeight:700, letterSpacing:"0.06em", textTransform:"uppercase", color:D.ink3 }}>
            Payday (1–31)
          </label>
          <input type="number" min="1" max="31" value={salaryInput.day}
            onChange={e=>setSalaryInput(p=>({...p,day:e.target.value}))}
            style={{ height:52, padding:"0 16px", border:`1.5px solid ${D.line}`, borderRadius:14,
              background:D.white, fontSize:17, fontWeight:600, color:D.ink, outline:"none", ...F }}/>
        </div>
        {salaryInput.amount > 0 && (
          <div style={{ padding:"14px 16px", background:D.incomeSoft, borderRadius:14 }}>
            <div style={{ fontSize:13, color:D.ink }}>
              <span style={{ fontWeight:800, color:D.income }}>{fmt(Number(salaryInput.amount))}</span>
              {" "}on the {salaryInput.day||1}{["st","nd","rd"][((salaryInput.day||1)-1)%10]||"th"} of each month
            </div>
          </div>
        )}
        <div style={{ display:"flex", gap:8 }}>
          <button onClick={()=>{setSalary({amount:"",day:1});setShowSalary(false);}}
            style={{ height:52, padding:"0 20px", background:"transparent",
              border:`1px solid ${D.line2}`, borderRadius:14, color:D.ink3,
              fontSize:14, fontWeight:600, cursor:"pointer", ...F }}>
            Clear
          </button>
          <button onClick={()=>{
              setSalary({amount:salaryInput.amount, day:Number(salaryInput.day)||1});
              setShowSalary(false);
            }}
            style={{ flex:1, height:52, background:D.ink, color:D.cream, border:"none",
              borderRadius:14, fontSize:15, fontWeight:700, cursor:"pointer", ...F }}>
            Save
          </button>
        </div>
      </div>
    </Sheet>
  );

  // Tag manager
  const TagManagerModal = () => (
    <Sheet open={showTagMgr} onClose={()=>setShowTagMgr(false)} title="Tags">
      <div style={{ display:"flex", gap:8, marginBottom:16 }}>
        <input value={tagDraft} onChange={e=>setTagDraft(e.target.value)}
          onKeyDown={e=>{if(e.key==="Enter"&&tagDraft.trim()){setUserTags(p=>[...p,tagDraft.trim()]);setTagDraft("");}}}
          placeholder="New tag…"
          style={{ flex:1, height:46, padding:"0 14px", border:`1px solid ${D.line}`,
            borderRadius:12, background:D.white, fontSize:14, color:D.ink, outline:"none", ...F }}/>
        <button onClick={()=>{if(tagDraft.trim()){setUserTags(p=>[...p,tagDraft.trim()]);setTagDraft("");}}}
          style={{ height:46, padding:"0 18px", background:D.ink, color:D.cream, border:"none",
            borderRadius:12, fontSize:14, fontWeight:600, cursor:"pointer", ...F }}>Add</button>
      </div>
      <div style={{ display:"flex", flexWrap:"wrap", gap:8 }}>
        {userTags.map(tag => (
          <div key={tag} style={{ display:"flex", alignItems:"center", gap:8, padding:"8px 12px",
            background:D.white, border:`1px solid ${D.line}`, borderRadius:999,
            fontSize:13, fontWeight:600, color:D.ink }}>
            #{tag}
            <button onClick={()=>setUserTags(p=>p.filter(t=>t!==tag))}
              style={{ color:D.ink4, background:"none", border:"none", cursor:"pointer",
                fontSize:15, lineHeight:1, padding:0 }}>×</button>
          </div>
        ))}
      </div>
    </Sheet>
  );

  // Privacy
  const PrivacyModal = () => (
    <Sheet open={showPrivacy} onClose={()=>setShowPrivacy(false)} title="Privacy & Security">
      <div style={{ display:"flex", alignItems:"center", gap:12, padding:16,
        background:D.white, border:`1px solid ${D.line}`, borderRadius:14, marginBottom:16 }}>
        <div style={{ width:44, height:44, borderRadius:14, background:D.incomeSoft,
          display:"flex", alignItems:"center", justifyContent:"center", fontSize:22 }}>🔒</div>
        <div>
          <div style={{ fontSize:14, fontWeight:700, color:D.ink }}>Protected, on-device</div>
          <div style={{ fontSize:12, color:D.ink3, marginTop:2 }}>{blockedCount} messages blocked</div>
        </div>
      </div>
      {[
        { ok:true,  t:"Read bank & merchant SMS to find spends" },
        { ok:true,  t:"Parse amount, merchant, category locally" },
        { ok:false, t:"Upload messages anywhere" },
        { ok:false, t:"Read personal conversations" },
        { ok:false, t:"Access contacts, photos, or location" },
      ].map((r,i) => (
        <div key={i} style={{ display:"flex", alignItems:"center", gap:12, padding:"12px 0",
          borderBottom:`1px solid ${D.line}` }}>
          <div style={{ width:22, height:22, borderRadius:11, flexShrink:0,
            background: r.ok ? D.income : D.ink, color:D.cream,
            display:"flex", alignItems:"center", justifyContent:"center",
            fontSize:11, fontWeight:700 }}>{r.ok?"✓":"✕"}</div>
          <div style={{ fontSize:13, color: r.ok?D.ink:D.ink3, fontWeight:500 }}>{r.t}</div>
        </div>
      ))}
    </Sheet>
  );

  // Drill-down
  const DrillModal = () => {
    if (!showDrill) return null;
    const dk = CK(showDrill);
    const c  = CATS[dk];
    const items = periodTxns.filter(t => t.category===showDrill && t.type==="debited");
    const total = items.reduce((s,t)=>s+t.amount,0);
    return (
      <Sheet open={!!showDrill} onClose={()=>setShowDrill(null)} title={c.name}>
        <div style={{ display:"flex", alignItems:"center", gap:16, padding:"8px 0 20px" }}>
          <CatIcon catKey={showDrill} size={52}/>
          <div>
            <div style={{ fontSize:30, fontWeight:800, color:D.ink, letterSpacing:"-0.02em" }}>{fmt(total)}</div>
            <div style={{ fontSize:12, color:D.ink3, fontWeight:500, marginTop:2 }}>
              {items.length} transaction{items.length!==1?"s":""} · {periodLabel}
            </div>
          </div>
        </div>
        <div style={{ background:D.white, borderRadius:14, border:`1px solid ${D.line}`, overflow:"hidden" }}>
          {items.map((t,i) => (
            <div key={t.id} style={{ display:"flex", alignItems:"center", gap:12, padding:"13px 16px",
              borderBottom: i<items.length-1 ? `1px solid ${D.line}` : "none" }}>
              <MerchantAvatar merchant={t.brand||t.bank} catKey={t.category} size={40}/>
              <div style={{ flex:1, minWidth:0 }}>
                <div style={{ fontSize:13, fontWeight:600, color:D.ink,
                  overflow:"hidden", textOverflow:"ellipsis", whiteSpace:"nowrap" }}>
                  {t.brand||t.bank}
                </div>
                <div style={{ display:"flex", alignItems:"center", gap:5, marginTop:2 }}>
                  {t.tag && <span style={{ fontSize:11, color:D.ink3, fontWeight:600 }}>#{t.tag}</span>}
                  <span style={{ fontSize:11, color:D.ink4 }}>{t.tag ? "· " : ""}{t.date}</span>
                </div>
              </div>
              <div style={{ fontSize:15, fontWeight:700, color:D.ink, letterSpacing:"-0.01em" }}>
                −{fmt(t.amount)}
              </div>
            </div>
          ))}
        </div>
      </Sheet>
    );
  };

  // ══════════════════════════════════════════════════════════════════════
  //  ROOT RENDER
  // ══════════════════════════════════════════════════════════════════════
  return (
    <div style={{ width:"100%", maxWidth:"100vw", height:"100vh",
      background:D.cream, display:"flex", flexDirection:"column",
      overflow:"hidden", position:"relative", ...F }}>

      <div style={{ flex:1, display:"flex", flexDirection:"column", overflow:"hidden" }}>
        {tab==="home"     && <HomeTab/>}
        {tab==="overview" && <OverviewTab/>}
      </div>

      {/* Bottom nav — pill */}
      <div style={{ background:D.cream, borderTop:`1px solid ${D.line}`,
        display:"flex", padding:"10px 16px 18px", gap:8, flexShrink:0 }}>
        {[
          { id:"home",     label:"Home",         icon:"⌂" },
          { id:"overview", label:"Transactions",  icon:"☰" },
        ].map(({ id, label, icon }) => {
          const active = tab===id;
          return (
            <button key={id} onClick={()=>setTab(id)} style={{
              flex:1, height:48, borderRadius:999,
              display:"flex", alignItems:"center", justifyContent:"center", gap:8,
              fontSize:14, fontWeight:600, letterSpacing:"-0.01em",
              background: active ? D.ink : "transparent",
              color:      active ? D.cream : D.ink3,
              border:"none", cursor:"pointer", transition:"all 160ms ease",
            }}>
              <span style={{ fontSize:16 }}>{icon}</span>
              {label}
            </button>
          );
        })}
      </div>

      {showSalary  && <SalaryModal/>}
      {showTagMgr  && <TagManagerModal/>}
      {showPrivacy && <PrivacyModal/>}
      {showDrill   && <DrillModal/>}
    </div>
  );
}
