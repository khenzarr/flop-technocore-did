import type { Metadata } from "next";
import "./globals.css";

export const metadata: Metadata = {
  title: "Technocore Agent Hub — Observer Preview",
  description: "Public Technocore observability preview. Production DID signing remains gated behind the Stage 2D local security core.",
  icons: {
    icon: "/favicon.svg",
    shortcut: "/favicon.svg",
  },
};

export default function RootLayout({ children }: Readonly<{ children: React.ReactNode }>) {
  return <html lang="en"><body>{children}</body></html>;
}
