/* Makemarry Service Worker v1
   キャッシュは持たない（更新が即反映されるように）。
   役割は通知の受信と、通知タップでアプリを開くことだけ。 */

self.addEventListener('install', e => self.skipWaiting());
self.addEventListener('activate', e => e.waitUntil(self.clients.claim()));

/* Phase 3のサーバーからのプッシュを受け取る */
self.addEventListener('push', e => {
  let d = {};
  try { d = e.data ? e.data.json() : {}; } catch (err) { d = { body: e.data ? e.data.text() : '' }; }
  e.waitUntil(self.registration.showNotification(d.title || 'Makemarry', {
    body: d.body || '',
    icon: 'mm-icon-192.png',
    badge: 'mm-icon-192.png',
    data: { url: d.url || './makemarry.html', talkId: d.talkId || null }
  }));
});

/* 通知タップでアプリを開く（既に開いてたら前面へ） */
self.addEventListener('notificationclick', e => {
  e.notification.close();
  e.waitUntil(
    self.clients.matchAll({ type: 'window', includeUncontrolled: true }).then(list => {
      for (const c of list) {
        if (c.url.includes('makemarry') && 'focus' in c) return c.focus();
      }
      return self.clients.openWindow(e.notification.data && e.notification.data.url ? e.notification.data.url : './makemarry.html');
    })
  );
});
