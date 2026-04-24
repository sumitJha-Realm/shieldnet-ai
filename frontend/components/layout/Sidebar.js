'use client';

import { usePathname } from 'next/navigation';
import Link from 'next/link';

const NAV_ITEMS = [
  { href: '/', label: 'Dashboard', icon: '📊' },
  { href: '/scan', label: 'URL Scanner', icon: '🔍' },
  { href: '/architecture', label: 'Architecture', icon: '🏗️' },
  { href: '/threats', label: 'Threat Database', icon: '⚠️' },
  { href: '/search', label: 'Search Playground', icon: '🧪' },
  { href: '/analytics', label: 'Analytics', icon: '📈' },
  { href: '/settings', label: 'Settings', icon: '⚙️' },
];

export default function Sidebar() {
  const pathname = usePathname();

  return (
    <nav style={{
      height: '100vh',
      background: '#001E2B',
      color: '#fff',
      display: 'flex',
      flexDirection: 'column',
      padding: '0',
      position: 'fixed',
      width: '260px',
      zIndex: 100,
    }}>
      {/* Logo */}
      <div style={{
        padding: '24px 20px',
        borderBottom: '1px solid rgba(255,255,255,0.1)',
        display: 'flex',
        alignItems: 'center',
        gap: '12px',
      }}>
        <div style={{
          width: 36, height: 36, borderRadius: 8,
          background: '#00ED64', display: 'flex',
          alignItems: 'center', justifyContent: 'center',
          fontSize: 18, fontWeight: 700, color: '#001E2B',
        }}>S</div>
        <div>
          <div style={{ fontWeight: 700, fontSize: 16 }}>ShieldNet AI</div>
          <div style={{ fontSize: 11, opacity: 0.6 }}>NIC Security Platform</div>
        </div>
      </div>

      {/* Nav Items */}
      <div style={{ flex: 1, padding: '12px 8px', overflowY: 'auto' }}>
        {NAV_ITEMS.map(item => {
          const isActive = pathname === item.href || (item.href !== '/' && pathname.startsWith(item.href));
          return (
            <Link key={item.href} href={item.href} style={{ textDecoration: 'none' }}>
              <div style={{
                display: 'flex', alignItems: 'center', gap: '12px',
                padding: '10px 12px', borderRadius: 8, marginBottom: 2,
                background: isActive ? 'rgba(0, 237, 100, 0.15)' : 'transparent',
                color: isActive ? '#00ED64' : 'rgba(255,255,255,0.8)',
                fontWeight: isActive ? 600 : 400, fontSize: 14,
                cursor: 'pointer', transition: 'background 0.15s',
              }}>
                <span style={{ fontSize: 18 }}>{item.icon}</span>
                {item.label}
              </div>
            </Link>
          );
        })}
      </div>

      {/* Footer */}
      <div style={{
        padding: '16px 20px',
        borderTop: '1px solid rgba(255,255,255,0.1)',
        fontSize: 11, opacity: 0.5,
      }}>
        ShieldNet AI v1.0.0<br />National Informatics Centre
      </div>
    </nav>
  );
}
