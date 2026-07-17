import type {Metadata} from "next";
import "./styles.css";

export const metadata: Metadata = {
  title: "SentinelAI Threat Detection",
  description: "ML-powered cybersecurity threat detection dashboard"
};

export default function RootLayout({children}: Readonly<{ children: React.ReactNode }>) {
  return (
    <html lang="en">
      <body>{children}</body>
    </html>
  );
}

