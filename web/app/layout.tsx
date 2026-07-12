import type { ReactNode } from "react";
import "./globals.css";
import Nav from "./Nav";

export const metadata = {
  title: "Codename Eye",
  description: "AI-powered DAST/SAST vulnerability-assessment and red-team harness.",
};

export default function RootLayout({ children }: { children: ReactNode }) {
  return (
    <html lang="en">
      <body>
        <Nav />
        {children}
      </body>
    </html>
  );
}
