'use client';

const STATUS_COLORS = {
  blocked: '#CF4A22',
  allowed: '#00ED64',
  under_review: '#FFC010',
  flagged: '#FFC010',
};

export default function RecentActivity({ logs }) {
  return (
    <div style={{
      background: '#fff', borderRadius: 12, padding: 24,
      boxShadow: '0 1px 3px rgba(0,0,0,0.08)',
    }}>
      <h3 style={{ fontSize: 16, fontWeight: 600, marginBottom: 16, color: '#1a1c1e' }}>
        Recent Threat Activity
      </h3>
      <div style={{ overflowX: 'auto' }}>
        <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: 13 }}>
          <thead>
            <tr style={{ borderBottom: '2px solid #E8EDEB' }}>
              <th style={{ textAlign: 'left', padding: '8px 12px', color: '#5C6C75', fontWeight: 600 }}>Action</th>
              <th style={{ textAlign: 'left', padding: '8px 12px', color: '#5C6C75', fontWeight: 600 }}>Department</th>
              <th style={{ textAlign: 'left', padding: '8px 12px', color: '#5C6C75', fontWeight: 600 }}>Region</th>
              <th style={{ textAlign: 'left', padding: '8px 12px', color: '#5C6C75', fontWeight: 600 }}>Device</th>
              <th style={{ textAlign: 'left', padding: '8px 12px', color: '#5C6C75', fontWeight: 600 }}>Confidence</th>
              <th style={{ textAlign: 'left', padding: '8px 12px', color: '#5C6C75', fontWeight: 600 }}>Time</th>
            </tr>
          </thead>
          <tbody>
            {(logs || []).slice(0, 20).map((log, i) => (
              <tr key={log._id || i} style={{ borderBottom: '1px solid #F5F6F7' }}>
                <td style={{ padding: '8px 12px' }}>
                  <span style={{
                    display: 'inline-block', padding: '2px 8px', borderRadius: 4,
                    fontSize: 11, fontWeight: 600, textTransform: 'uppercase',
                    background: `${STATUS_COLORS[log.action] || '#5C6C75'}20`,
                    color: STATUS_COLORS[log.action] || '#5C6C75',
                  }}>{log.action}</span>
                </td>
                <td style={{ padding: '8px 12px' }}>{log.userDepartment}</td>
                <td style={{ padding: '8px 12px' }}>{log.ipRegion}</td>
                <td style={{ padding: '8px 12px' }}>{log.deviceType}</td>
                <td style={{ padding: '8px 12px' }}>{(log.aiConfidence * 100).toFixed(0)}%</td>
                <td style={{ padding: '8px 12px', color: '#5C6C75' }}>
                  {log.timestamp ? new Date(log.timestamp).toLocaleString() : '—'}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
        {(!logs || logs.length === 0) && (
          <div style={{ textAlign: 'center', padding: 32, color: '#5C6C75' }}>
            No recent activity. Seed the database to populate.
          </div>
        )}
      </div>
    </div>
  );
}
