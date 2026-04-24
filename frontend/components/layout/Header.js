'use client';

import { usePathname } from 'next/navigation';

const PAGE_TITLES = {
  '/': 'Dashboard',
  '/scan': 'URL Scanner',
  '/threats': 'Threat Database',
  '/search': 'Search Playground',
  '/analytics': 'Analytics & Reports',
  '/settings': 'Platform Settings',
};

export default function Header() {
  const pathname = usePathname();
  const title = PAGE_TITLES[pathname] || 'ShieldNet AI';

  return (
    <header style={{
      height: 64,
      background: '#fff',
      borderBottom: '1px solid #e8edeb',
      display: 'flex',
      alignItems: 'center',
      justifyContent: 'space-between',
      padding: '0 32px',
    }}>
      <h1 style={{ fontSize: 20, fontWeight: 600, color: '#1a1c1e' }}>{title}</h1>
      <div style={{ display: 'flex', alignItems: 'center', gap: 16 }}>
        <div style={{
          width: 8, height: 8, borderRadius: '50%',
          background: '#00ED64',
        }} />
        <span style={{ fontSize: 13, color: '#5C6C75' }}>System Active</span>
        <div style={{
          width: 32, height: 32, borderRadius: '50%',
          background: '#E8EDEB', display: 'flex',
          alignItems: 'center', justifyContent: 'center',
          fontSize: 14, fontWeight: 600, color: '#001E2B',
        }}>A</div>
      </div>
    </header>
  );
}
