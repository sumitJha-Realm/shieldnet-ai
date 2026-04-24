'use client';

import { usePathname } from 'next/navigation';
import Sidebar from '../components/layout/Sidebar';
import Header from '../components/layout/Header';

export default function RootLayout({ children }) {
  return (
    <html lang="en">
      <head>
        <title>ShieldNet AI — Malicious URL Detection</title>
        <meta name="description" content="Real-Time Malicious URL Detection Platform for NIC" />
        <style>{`
          * { margin: 0; padding: 0; box-sizing: border-box; }
          body { font-family: 'Euclid Circular A', -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background: #f5f6f7; color: #1a1c1e; }
          #app-shell { display: flex; min-height: 100vh; }
          #sidebar { width: 260px; flex-shrink: 0; }
          #main-area { flex: 1; display: flex; flex-direction: column; min-width: 0; }
          #page-content { flex: 1; padding: 24px 32px; overflow-y: auto; }
        `}</style>
      </head>
      <body>
        <div id="app-shell">
          <div id="sidebar">
            <Sidebar />
          </div>
          <div id="main-area">
            <Header />
            <div id="page-content">
              {children}
            </div>
          </div>
        </div>
      </body>
    </html>
  );
}
