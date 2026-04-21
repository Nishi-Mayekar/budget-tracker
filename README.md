# SMS Budget Tracker 💰

A personal finance app that automatically sorts your spending into categories — no login, no bank integration, no cloud. Everything stays on your phone.

> Built as a personal project to actually understand where my money goes each month.

---

## What it does

- **Auto-sorts spending** into QuickCart, Investments, Insurance, Family, and Miscellaneous
- **Breaks down QuickCart** — Food (Zomato/Swiggy) vs Grocery (Blinkit/BigBasket/Zepto)
- **Picks up SIPs** — Groww, Zerodha, Kuvera show up as Investments automatically
- **Tags transactions** — tag once, all same-brand transactions fill automatically
- **Fixed expense tracking** — declare your SIP, insurance, parents transfer once; app cross-checks amounts
- **100% on-device** — no server, no account, no data leaves your phone

---

## Privacy

The app only ever sees two things per transaction — the ₹ amount and the brand name (Zomato, Groww, etc.). That's it.

It **never** reads or stores:
- OTPs, PINs, or passwords — these are blocked before anything is read
- Account numbers or card numbers
- Any personal message text
- Anything is uploaded anywhere

The only outbound request the app makes is loading the Inter Tight font from Google Fonts.

---

## Tech stack

- React + Vite
- Capacitor 8.x (Android)
- Inter Tight — warm cream design system

---

## Made by

**Nmay** · nishimayekar

Personal project · Not affiliated with any bank or payment service
