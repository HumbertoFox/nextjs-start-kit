import type { NextConfig } from 'next';

const nextConfig: NextConfig = {
  images: {
    remotePatterns: [
      {
        protocol: 'https',
        hostname: 'dq47ivujyw249lvb.public.blob.vercel-storage.com',
        pathname: '/avatars/**',
      },
    ],
  },
}

export default nextConfig;