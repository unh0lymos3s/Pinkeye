import type { ReactNode } from "react";
import { IBM_Plex_Mono } from "next/font/google";
import "./globals.css";
import Nav from "./Nav";

// Self-hosted at build time (no runtime request, no layout shift). Medium (500) is the base
// text weight globals.css applies — a step heavier than the browser default without going bold.
const ibmPlexMono = IBM_Plex_Mono({
  subsets: ["latin"],
  weight: ["400", "500", "600"],
  variable: "--font-ibm-plex-mono",
});

export const metadata = {
  title: "Pinkeye",
  description: "AI-powered DAST/SAST vulnerability-assessment and red-team harness.",
};

export default function RootLayout({ children }: { children: ReactNode }) {
  return (
    <html lang="en" className={ibmPlexMono.variable}>
      <body>
        <Nav />
        {children}
      </body>
    </html>
  );
}
