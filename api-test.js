const fs = require('fs');

// Read connect.sid cookie from curl cookie jar
const jar = fs.readFileSync('cookies.txt', 'utf8');
const cookieLine = jar.split('\n').find(l => l.includes('connect.sid'));
const cookie = cookieLine ? cookieLine.split('\t').slice(-2).join('=') : '';
if (!cookie) { console.log('NO COOKIE FOUND'); process.exit(1); }

const BASE = 'http://localhost:3000';
const headers = { 'Content-Type': 'application/json', Cookie: cookie };

const tests = [
  ['POST', '/api/tasks', { title: 'Probe task', description: 'x', priority: 'medium', assigneeId: 1, dueDate: '2026-09-01' }],
  ['PUT', '/api/tasks/1', { title: 'Probe task edited', status: 'done' }],
  ['POST', '/api/announcements', { title: 'Probe', body: 'Probe body' }],
  ['POST', '/api/calendar', { title: 'Probe event', startTime: '2026-09-01T10:00:00', endTime: '2026-09-01T11:00:00' }],
  ['POST', '/api/notes', { title: 'Probe note', body: 'hello' }],
  ['PUT', '/api/profile', { name: 'Avara Owner', bio: 'test bio' }],
  ['PUT', '/api/prefs', { darkMode: false }],
  ['POST', '/api/leave', { type: 'vacation', startDate: '2026-10-01', endDate: '2026-10-02', reason: 'vacation' }],
  ['POST', '/api/goals', { title: 'Probe goal', description: 'x' }],
  ['POST', '/api/conversations/dm', { otherUserId: 1 }],
  ['POST', '/api/conversations/group', { name: 'probe conv', memberIds: [1] }],
  ['POST', '/api/time/clock-in', { note: 'x' }],
  ['POST', '/api/time/clock-out', {}],
  ['POST', '/api/meeting-notes', { title: 'Probe meeting', body: 'x' }],
  ['POST', '/api/courses', { title: 'Probe course', description: 'x', content: 'y', durationMinutes: 10 }],
  ['POST', '/api/expenses', { amount: 100, category: 'travel', description: 'x' }],
  ['POST', '/api/admin/site-content', { headline: 'h', subtitle: 's', ctaText: 'c' }],
  ['POST', '/api/surveys', { title: 'Probe survey', question: 'ok?' }],
  ['POST', '/api/jobs', { title: 'Probe job', department: 'x', description: 'y' }],
  ['POST', '/api/reviews', { cycle: '2026-H2', subjectId: 1, reviewerId: 1, type: 'self' }],
];

(async () => {
  const results = [];
  for (const [method, path, body] of tests) {
    try {
      const res = await fetch(BASE + path, { method, headers, body: JSON.stringify(body) });
      const text = await res.text();
      let summary = text.slice(0, 200);
      results.push(`${res.status} ${method} ${path} -> ${summary.replace(/\s+/g, ' ')}`);
    } catch (e) {
      results.push(`ERR ${method} ${path} -> ${e.message}`);
    }
  }
  console.log(results.join('\n'));
})();
