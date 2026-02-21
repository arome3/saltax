import type { NextConfig } from "next";

const nextConfig: NextConfig = {
  async rewrites() {
    return [
      {
        source: "/api/:path*",
        destination: "http://34.59.160.177:8080/api/:path*",
      },
      {
        source: "/ws/:path*",
        destination: "http://34.59.160.177:8080/ws/:path*",
      },
    ];
  },
};

export default nextConfig;
