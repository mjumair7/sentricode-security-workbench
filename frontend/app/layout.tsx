import type { Metadata } from "next";
import "./globals.css";

export const metadata: Metadata = {
  title: "SentriCode · Security workspace",
  description:
    "A local-first workspace for source code, secrets, dependencies, and confidentiality checks.",
  icons: { icon: "/favicon.svg" },
};

export default function RootLayout({ children }: Readonly<{ children: React.ReactNode }>) {
  return (
    <html lang="en">
      <body>{children}</body>
    </html>
  );
}
