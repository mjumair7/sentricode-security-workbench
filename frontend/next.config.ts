import type { NextConfig } from "next";

const development = process.env.NODE_ENV === "development";
const config: NextConfig = {
  output: development ? undefined : "export",
  images: { unoptimized: true },
  devIndicators: false,
  ...(development
    ? {
        async rewrites() {
          return [{ source: "/api/:path*", destination: "http://127.0.0.1:8000/api/:path*" }];
        },
      }
    : {}),
};
export default config;
