// Frame studio 로컬 서버 (Express + JSON 파일 저장). 외부 DB 없이 data/ 폴더에 저장됩니다.
const express = require('express');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const PORT = process.env.PORT || 3000;
const DATA = path.join(__dirname, 'data');
const UP = path.join(DATA, 'uploads');
const DBF = path.join(DATA, 'db.json');
fs.mkdirSync(UP, { recursive: true });

let db = { users: [], sessions: {}, frames: [], posts: [] };
try { db = { ...db, ...JSON.parse(fs.readFileSync(DBF, 'utf8')) }; } catch (e) {}
const save = () => { fs.writeFileSync(DBF + '.tmp', JSON.stringify(db)); fs.renameSync(DBF + '.tmp', DBF); };
const uid = () => crypto.randomBytes(8).toString('hex');
const hash = (pw, salt) => crypto.scryptSync(pw, salt, 32).toString('hex');
const pub = (u) => ({ id: u.id, username: u.username });
const fail = (res, code, error) => res.status(code).json({ error });

const app = express();
app.use(express.json({ limit: '30mb' }));

// 세션 쿠키로 로그인 사용자 식별
app.use((req, res, next) => {
  const m = /(?:^|;\s*)sid=([a-f0-9]+)/.exec(req.headers.cookie || '');
  req.sid = m && m[1];
  req.user = req.sid ? db.users.find((u) => u.id === db.sessions[req.sid]) : null;
  next();
});
const need = (req, res, next) => (req.user ? next() : fail(res, 401, '로그인이 필요해요'));

function startSession(res, u) {
  const t = crypto.randomBytes(24).toString('hex');
  db.sessions[t] = u.id;
  save();
  res.setHeader('Set-Cookie', `sid=${t}; HttpOnly; Path=/; SameSite=Lax; Max-Age=2592000`);
}

// ───── 계정 ─────
app.post('/api/signup', (req, res) => {
  const { username, password, agree } = req.body || {};
  if (!agree) return fail(res, 400, '약관 동의가 필요해요');
  if (!/^[A-Za-z0-9_가-힣]{2,16}$/.test(username || '')) return fail(res, 400, '아이디는 2~16자의 한글·영문·숫자·_ 만 쓸 수 있어요');
  if (typeof password !== 'string' || password.length < 6) return fail(res, 400, '비밀번호는 6자 이상이어야 해요');
  if (db.users.some((u) => u.username.toLowerCase() === username.toLowerCase())) return fail(res, 409, '이미 있는 아이디예요');
  const salt = crypto.randomBytes(16).toString('hex');
  const u = { id: uid(), username, salt, hash: hash(password, salt), termsAt: new Date().toISOString() };
  db.users.push(u);
  startSession(res, u);
  res.json({ user: pub(u) });
});

app.post('/api/login', (req, res) => {
  const { username, password } = req.body || {};
  const u = db.users.find((x) => x.username.toLowerCase() === String(username || '').toLowerCase());
  const ok = u && crypto.timingSafeEqual(Buffer.from(hash(String(password || ''), u.salt)), Buffer.from(u.hash));
  if (!ok) return fail(res, 400, '아이디 또는 비밀번호가 틀렸어요');
  startSession(res, u);
  res.json({ user: pub(u) });
});

app.post('/api/logout', (req, res) => {
  if (req.sid) { delete db.sessions[req.sid]; save(); }
  res.setHeader('Set-Cookie', 'sid=; HttpOnly; Path=/; Max-Age=0');
  res.json({ ok: true });
});

app.get('/api/me', (req, res) => res.json({ user: req.user ? pub(req.user) : null }));

// ───── 프레임 (만든 사람만 수정·삭제) ─────
app.get('/api/frames', need, (req, res) => res.json({ frames: db.frames }));

app.post('/api/frames', need, (req, res) => {
  const b = req.body || {};
  if (!/^\w{1,40}$/.test(String(b.id || '')) || !Array.isArray(b.layers) || !b.consent || !['strip', 'grid'].includes(b.layout))
    return fail(res, 400, '프레임 정보가 올바르지 않아요 (책임 동의 필요)');
  const i = db.frames.findIndex((f) => f.id === b.id);
  if (i >= 0 && db.frames[i].owner !== req.user.id) return fail(res, 403, '내 프레임이 아니에요');
  const f = {
    id: b.id,
    name: String(b.name || '').slice(0, 20),
    creator: String(b.creator || req.user.username).slice(0, 20),
    bg: b.bg, layout: b.layout, layers: b.layers, preview: b.preview || [],
    consent: { v: 1, at: new Date().toISOString() }, // 서버 시각으로 동의 기록
    owner: req.user.id, updatedAt: Date.now(),
  };
  if (i >= 0) db.frames[i] = f; else db.frames.unshift(f);
  save();
  res.json({ ok: true });
});

app.delete('/api/frames/:id', need, (req, res) => {
  const f = db.frames.find((x) => x.id === req.params.id);
  if (!f) return fail(res, 404, '없는 프레임이에요');
  if (f.owner !== req.user.id) return fail(res, 403, '내 프레임이 아니에요');
  db.frames = db.frames.filter((x) => x !== f);
  save();
  res.json({ ok: true });
});

// ───── 게시물 (SNS 피드) ─────
app.get('/api/posts', need, (req, res) => {
  const posts = db.posts.filter((p) => !p.hidden).map((p) => ({
    id: p.id, username: p.username, frameId: p.frameId, frameName: p.frameName, frameCreator: p.frameCreator,
    caption: p.caption, url: '/uploads/' + p.file, likes: p.likes.length,
    liked: p.likes.includes(req.user.id), mine: p.userId === req.user.id, createdAt: p.createdAt,
  }));
  res.json({ posts });
});

app.post('/api/posts', need, (req, res) => {
  const { frameId, caption, image } = req.body || {};
  const m = /^data:image\/(png|jpeg);base64,([A-Za-z0-9+/=]+)$/.exec(image || '');
  if (!m) return fail(res, 400, '이미지 형식이 올바르지 않아요');
  const fr = db.frames.find((f) => f.id === frameId);
  if (!fr) return fail(res, 400, '프레임을 찾을 수 없어요');
  const file = uid() + (m[1] === 'png' ? '.png' : '.jpg');
  fs.writeFileSync(path.join(UP, file), Buffer.from(m[2], 'base64'));
  db.posts.unshift({
    id: uid(), userId: req.user.id, username: req.user.username,
    frameId, frameName: fr.name, frameCreator: fr.creator,
    caption: String(caption || '').slice(0, 200), file,
    likes: [], reports: [], hidden: false, createdAt: Date.now(),
  });
  save();
  res.json({ ok: true });
});

const findPost = (req, res) => {
  const p = db.posts.find((x) => x.id === req.params.id);
  if (!p) fail(res, 404, '없는 게시물이에요');
  return p;
};

app.post('/api/posts/:id/like', need, (req, res) => {
  const p = findPost(req, res); if (!p) return;
  const i = p.likes.indexOf(req.user.id);
  if (i >= 0) p.likes.splice(i, 1); else p.likes.push(req.user.id);
  save();
  res.json({ ok: true });
});

// 신고 3건이 쌓이면 자동으로 숨김 처리 (실서비스에서는 운영자 검토 절차 필요)
app.post('/api/posts/:id/report', need, (req, res) => {
  const p = findPost(req, res); if (!p) return;
  if (!p.reports.includes(req.user.id)) p.reports.push(req.user.id);
  if (p.reports.length >= 3) p.hidden = true;
  save();
  res.json({ ok: true });
});

app.delete('/api/posts/:id', need, (req, res) => {
  const p = findPost(req, res); if (!p) return;
  if (p.userId !== req.user.id) return fail(res, 403, '내 게시물이 아니에요');
  db.posts = db.posts.filter((x) => x !== p);
  try { fs.unlinkSync(path.join(UP, p.file)); } catch (e) {}
  save();
  res.json({ ok: true });
});

app.use('/uploads', (req, res, next) => { res.setHeader('X-Content-Type-Options', 'nosniff'); next(); }, express.static(UP));
app.use(express.static(path.join(__dirname, 'public')));
app.use((err, req, res, next) => fail(res, err.status || 500, err.status === 413 ? '파일이 너무 커요' : '서버 오류'));

app.listen(PORT, '127.0.0.1', () => console.log(`Frame studio: http://localhost:${PORT}`));
