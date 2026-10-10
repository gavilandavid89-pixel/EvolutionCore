'use strict';
const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const multer = require('multer');
const { Pool } = require('pg');
const crypto = require('crypto');

const app = express();
const PORT = Number(process.env.PORT || 3000);
const JWT_SECRET = process.env.JWT_SECRET || '';
const DATABASE_URL = process.env.DATABASE_URL || '';
const pool = DATABASE_URL ? new Pool({
  connectionString: DATABASE_URL,
  ssl: process.env.PGSSLMODE === 'disable' ? false : { rejectUnauthorized: false },
  max: 8,
  idleTimeoutMillis: 30000,
  connectionTimeoutMillis: 10000
}) : null;
const allowedOrigins = (process.env.CORS_ORIGINS || 'https://pril-tu-web-de-videos.onrender.com,http://localhost:3000,http://127.0.0.1:5500').split(',').map(x=>x.trim()).filter(Boolean);
app.set('trust proxy', 1);
app.use(helmet({ crossOriginResourcePolicy: { policy: 'cross-origin' }, contentSecurityPolicy: false }));
app.use(cors({ origin(origin, cb) { if (!origin || allowedOrigins.includes(origin) || /^https:\/\/.*\.onrender\.com$/.test(origin)) return cb(null, true); return cb(new Error('Origen no permitido por CORS')); }, credentials: true, exposedHeaders: ['Content-Range','Accept-Ranges','Content-Length'] }));
app.use(express.json({ limit: '1mb' }));
app.use('/api/auth', rateLimit({ windowMs: 15*60*1000, limit: 30, standardHeaders: true, legacyHeaders: false }));
const upload = multer({ storage: multer.memoryStorage(), limits: { fileSize: 40*1024*1024, files: 1 }, fileFilter(req,file,cb) { if (/^(video\/|image\/)/i.test(file.mimetype)) return cb(null,true); cb(new Error('Solo se aceptan videos e imágenes.')); } });

const schema = `
CREATE TABLE IF NOT EXISTS users (
 id BIGSERIAL PRIMARY KEY, name VARCHAR(70) NOT NULL, username VARCHAR(24) NOT NULL UNIQUE,
 email VARCHAR(254) NOT NULL UNIQUE, password_hash TEXT NOT NULL,
 bio VARCHAR(240) NOT NULL DEFAULT '', created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE TABLE IF NOT EXISTS posts (
 id BIGSERIAL PRIMARY KEY, user_id BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
 title VARCHAR(160) NOT NULL DEFAULT '', body TEXT NOT NULL DEFAULT '',
 kind VARCHAR(20) NOT NULL DEFAULT 'texto', link TEXT, poll JSONB,
 media BYTEA, media_type VARCHAR(100), media_name TEXT,
 created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE TABLE IF NOT EXISTS follows (
 follower_id BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
 followed_id BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
 created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(), PRIMARY KEY(follower_id, followed_id),
 CHECK(follower_id <> followed_id)
);
CREATE TABLE IF NOT EXISTS likes (
 user_id BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
 post_id BIGINT NOT NULL REFERENCES posts(id) ON DELETE CASCADE,
 created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(), PRIMARY KEY(user_id, post_id)
);
CREATE TABLE IF NOT EXISTS comments (
 id BIGSERIAL PRIMARY KEY, post_id BIGINT NOT NULL REFERENCES posts(id) ON DELETE CASCADE,
 user_id BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
 body VARCHAR(1200) NOT NULL, created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS posts_created_at_idx ON posts(created_at DESC);
CREATE INDEX IF NOT EXISTS posts_user_id_idx ON posts(user_id, created_at DESC);
CREATE INDEX IF NOT EXISTS comments_post_id_idx ON comments(post_id, created_at);
CREATE INDEX IF NOT EXISTS follows_followed_id_idx ON follows(followed_id);
CREATE TABLE IF NOT EXISTS notifications (id BIGSERIAL PRIMARY KEY,user_id BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,actor_id BIGINT REFERENCES users(id) ON DELETE SET NULL,kind VARCHAR(32) NOT NULL,message TEXT NOT NULL,post_id BIGINT REFERENCES posts(id) ON DELETE CASCADE,created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),read_at TIMESTAMPTZ);
CREATE TABLE IF NOT EXISTS messages (id BIGSERIAL PRIMARY KEY,sender_id BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,recipient_id BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,body VARCHAR(4000) NOT NULL,created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),read_at TIMESTAMPTZ,CHECK(sender_id<>recipient_id));
CREATE TABLE IF NOT EXISTS communities (id BIGSERIAL PRIMARY KEY,name VARCHAR(80) NOT NULL UNIQUE,slug VARCHAR(90) NOT NULL UNIQUE,description VARCHAR(500) NOT NULL DEFAULT '',creator_id BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,created_at TIMESTAMPTZ NOT NULL DEFAULT NOW());
CREATE TABLE IF NOT EXISTS community_members (community_id BIGINT NOT NULL REFERENCES communities(id) ON DELETE CASCADE,user_id BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,role VARCHAR(16) NOT NULL DEFAULT 'member',joined_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),PRIMARY KEY(community_id,user_id));
CREATE TABLE IF NOT EXISTS poll_votes (post_id BIGINT NOT NULL REFERENCES posts(id) ON DELETE CASCADE,user_id BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,option VARCHAR(240) NOT NULL,created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),PRIMARY KEY(post_id,user_id));
CREATE TABLE IF NOT EXISTS points_events (id BIGSERIAL PRIMARY KEY,user_id BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,event_key VARCHAR(200) NOT NULL UNIQUE,points INTEGER NOT NULL,reason VARCHAR(120) NOT NULL,created_at TIMESTAMPTZ NOT NULL DEFAULT NOW());
ALTER TABLE users ADD COLUMN IF NOT EXISTS settings JSONB NOT NULL DEFAULT '{}'::jsonb;
ALTER TABLE posts ADD COLUMN IF NOT EXISTS community_id BIGINT REFERENCES communities(id) ON DELETE SET NULL;
`;
let dbReady = false, dbInitError = null;
async function initDb() {
 if (!pool) { dbInitError = 'DATABASE_URL no está configurada'; return; }
 try { await pool.query('SELECT 1'); await pool.query(schema); dbReady = true; dbInitError = null; console.log('Pril database schema ready'); }
 catch(e) { dbInitError = e.message; console.error('Database init failed:', e.message); }
}
function needDb(req,res,next) { if (!pool || !dbReady) return res.status(503).json({ error: 'La base de datos todavía no está conectada. Configurá DATABASE_URL en el servicio de Pril.', code: 'DATABASE_NOT_READY' }); next(); }
function tokenFor(u) { return jwt.sign({ sub: String(u.id), username: u.username }, JWT_SECRET, { expiresIn: '30d' }); }
function safeUser(u) { return { id: Number(u.id), name: u.name, username: u.username, email: u.email, bio: u.bio || '', createdAt: u.created_at }; }
function auth(req,res,next) {
 const h=req.headers.authorization||'', t=h.startsWith('Bearer ')?h.slice(7):'';
 if(!t) return res.status(401).json({error:'Iniciá sesión para continuar.'});
 try { const p=jwt.verify(t,JWT_SECRET); req.userId=Number(p.sub); req.username=p.username; next(); }
 catch { return res.status(401).json({error:'Tu sesión venció. Volvé a iniciar sesión.'}); }
}
const usernameOk = s => /^[a-zA-Z0-9_]{3,24}$/.test(s);
app.get('/api/health', (req,res)=>res.json({ok:true,service:'Pril API',database:dbReady?'connected':'not_connected',databaseError:dbReady?undefined:(dbInitError||'pending')}));
app.get('/api', (req,res)=>res.json({service:'Pril API',version:1}));
app.post('/api/auth/register', needDb, async(req,res,next)=>{
 try {
  const name=String(req.body.name||'').trim(), username=String(req.body.username||'').trim().toLowerCase(), email=String(req.body.email||'').trim().toLowerCase(), password=String(req.body.password||'');
  if(name.length<2||name.length>70) return res.status(400).json({error:'El nombre debe tener entre 2 y 70 caracteres.'});
  if(!usernameOk(username)) return res.status(400).json({error:'El usuario debe tener 3–24 caracteres: letras, números o guion bajo.'});
  if(!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)||email.length>254) return res.status(400).json({error:'Ingresá un correo válido.'});
  if(password.length<8||password.length>128) return res.status(400).json({error:'La contraseña debe tener al menos 8 caracteres.'});
  const hash=await bcrypt.hash(password,12);
  const q=await pool.query('INSERT INTO users(name,username,email,password_hash) VALUES($1,$2,$3,$4) RETURNING id,name,username,email,bio,created_at',[name,username,email,hash]);
  const user=safeUser(q.rows[0]); res.status(201).json({token:tokenFor(q.rows[0]),user});
 } catch(e) { if(e.code==='23505') return res.status(409).json({error:'Ese usuario o correo ya está registrado.'}); next(e); }
});
app.post('/api/auth/login', needDb, async(req,res,next)=>{
 try {
  const identity=String(req.body.identity||req.body.email||req.body.username||'').trim().toLowerCase(), password=String(req.body.password||'');
  const q=await pool.query('SELECT * FROM users WHERE lower(email)=$1 OR lower(username)=$1 LIMIT 1',[identity]);
  if(!q.rowCount||!await bcrypt.compare(password,q.rows[0].password_hash)) return res.status(401).json({error:'Usuario/correo o contraseña incorrectos.'});
  res.json({token:tokenFor(q.rows[0]),user:safeUser(q.rows[0])});
 } catch(e){next(e)}
});
app.get('/api/me',needDb,auth,async(req,res,next)=>{try{const q=await pool.query('SELECT id,name,username,email,bio,created_at FROM users WHERE id=$1',[req.userId]);if(!q.rowCount)return res.status(404).json({error:'Cuenta no encontrada.'});res.json({user:safeUser(q.rows[0])})}catch(e){next(e)}});
const postSelect = `SELECT p.id,p.user_id,p.title,p.body,p.kind,p.link,p.poll,p.media_type,p.media_name,p.created_at,
 u.name,u.username,u.bio,
 (SELECT COUNT(*)::int FROM likes l WHERE l.post_id=p.id) AS like_count,
 (SELECT COUNT(*)::int FROM comments c WHERE c.post_id=p.id) AS comment_count,
 EXISTS(SELECT 1 FROM likes ml WHERE ml.post_id=p.id AND ml.user_id=$1) AS liked,
 EXISTS(SELECT 1 FROM follows f WHERE f.followed_id=p.user_id AND f.follower_id=$1) AS followed,
 (SELECT COUNT(*)::int FROM follows fr WHERE fr.followed_id=p.user_id) AS follower_count
 FROM posts p JOIN users u ON u.id=p.user_id`;
function serializePost(p) { return { id:Number(p.id), userId:Number(p.user_id), name:p.name, username:p.username, bio:p.bio||'', title:p.title, body:p.body, copy:p.body, kind:p.kind, type:p.kind, link:p.link, poll:p.poll, mediaType:p.media_type, mediaName:p.media_name, mediaUrl:p.media_type?'/api/posts/'+p.id+'/media':null, createdAt:p.created_at, time:new Date(p.created_at).toLocaleString('es-AR'), likes:Number(p.like_count), comments:Number(p.comment_count), liked:!!p.liked, following:!!p.followed, followers:Number(p.follower_count), letter:(p.name||'P').slice(0,1).toUpperCase(), handle:p.username }; }
app.get('/api/posts',needDb,async(req,res,next)=>{
 try {
  const viewer=Number(req.query.viewer)||0, feed=String(req.query.feed||'all'), limit=Math.min(100,Math.max(1,Number(req.query.limit)||50));
  let filter='', args=[viewer];
  if(feed==='following'&&viewer){filter=' AND EXISTS(SELECT 1 FROM follows ff WHERE ff.follower_id=$1 AND ff.followed_id=p.user_id)';}
  if(req.query.userId){args.push(Number(req.query.userId));filter+=' AND p.user_id=$'+args.length;}
  args.push(limit);
  const q=await pool.query(postSelect+filter+' ORDER BY p.created_at DESC LIMIT $'+args.length,args);
  res.json({posts:q.rows.map(serializePost)});
 } catch(e){next(e)}
});
app.post('/api/posts',needDb,auth,upload.single('media'),async(req,res,next)=>{
 try{
  const title=String(req.body.title||'').trim().slice(0,160), body=String(req.body.body||req.body.copy||'').trim().slice(0,10000), kind=String(req.body.kind||'texto').toLowerCase();
  const allowed=['video','imagen','gif','enlace','encuesta','texto'];
  if(!allowed.includes(kind))return res.status(400).json({error:'Tipo de publicación no válido.'});
  const link=String(req.body.link||'').trim(), poll=req.body.poll?JSON.parse(req.body.poll):null;
  if(!body&&!title&&!req.file&&!link&&!poll)return res.status(400).json({error:'Agregá texto, un archivo o un enlace.'});
  if(link&&!/^https?:\/\//i.test(link))return res.status(400).json({error:'El enlace debe comenzar con http:// o https://.'});
  if(kind==='video'&&req.file&&!req.file.mimetype.startsWith('video/'))return res.status(400).json({error:'Elegí un archivo de video.'});
  const q=await pool.query('INSERT INTO posts(user_id,title,body,kind,link,poll,media,media_type,media_name) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9) RETURNING id',[req.userId,title,body,kind,link||null,poll?JSON.stringify(poll):null,req.file?req.file.buffer:null,req.file?req.file.mimetype:null,req.file?req.file.originalname.slice(0,255):null]);
  const result=await pool.query(postSelect+' WHERE p.id=$2',[req.userId,q.rows[0].id]);res.status(201).json({post:serializePost(result.rows[0])});
 }catch(e){if(e instanceof SyntaxError)return res.status(400).json({error:'La encuesta no tiene un formato válido.'});next(e)}
});
app.get('/api/posts/:id/media',needDb,async(req,res,next)=>{
 try{
  const id=Number(req.params.id);if(!Number.isSafeInteger(id))return res.status(400).end();
  const q=await pool.query('SELECT media,media_type,media_name,octet_length(media)::bigint AS size FROM posts WHERE id=$1 AND media IS NOT NULL',[id]);
  if(!q.rowCount)return res.status(404).json({error:'Archivo no encontrado.'});
  const row=q.rows[0], buf=row.media, size=Number(row.size), range=req.headers.range;
  res.set('Accept-Ranges','bytes');res.set('Content-Type',row.media_type||'application/octet-stream');res.set('Cache-Control','public, max-age=300');
  if(range){const m=/bytes=(\d*)-(\d*)/.exec(range);if(!m)return res.status(416).end();let start=m[1]?Number(m[1]):Math.max(0,size-Number(m[2]));let end=m[2]&&m[1]?Math.min(Number(m[2]),size-1):size-1;if(start>=size||end<start)return res.status(416).set('Content-Range','bytes */'+size).end();const chunk=buf.subarray(start,end+1);res.status(206).set({'Content-Range':'bytes '+start+'-'+end+'/'+size,'Content-Length':chunk.length}).send(chunk);}
  else res.set('Content-Length',size).send(buf);
 }catch(e){next(e)}
});
app.post('/api/posts/:id/like',needDb,auth,async(req,res,next)=>{
 try{const id=Number(req.params.id);const found=await pool.query('SELECT id FROM posts WHERE id=$1',[id]);if(!found.rowCount)return res.status(404).json({error:'Publicación no encontrada.'});const del=await pool.query('DELETE FROM likes WHERE user_id=$1 AND post_id=$2 RETURNING post_id',[req.userId,id]);let liked=false;if(!del.rowCount){await pool.query('INSERT INTO likes(user_id,post_id) VALUES($1,$2) ON CONFLICT DO NOTHING',[req.userId,id]);liked=true;}const q=await pool.query('SELECT COUNT(*)::int AS count FROM likes WHERE post_id=$1',[id]);res.json({liked,likes:q.rows[0].count});}catch(e){next(e)}
});
app.get('/api/posts/:id/comments',needDb,async(req,res,next)=>{
 try{const q=await pool.query('SELECT c.id,c.body,c.created_at,u.id AS user_id,u.name,u.username FROM comments c JOIN users u ON u.id=c.user_id WHERE c.post_id=$1 ORDER BY c.created_at ASC LIMIT 100',[Number(req.params.id)]);res.json({comments:q.rows.map(c=>({id:Number(c.id),body:c.body,user:{id:Number(c.user_id),name:c.name,username:c.username},createdAt:c.created_at}))})}catch(e){next(e)}
});
app.post('/api/posts/:id/comments',needDb,auth,async(req,res,next)=>{
 try{const body=String(req.body.body||'').trim();if(!body||body.length>1200)return res.status(400).json({error:'El comentario debe tener entre 1 y 1200 caracteres.'});const q=await pool.query('INSERT INTO comments(post_id,user_id,body) SELECT p.id,$2,$3 FROM posts p WHERE p.id=$1 RETURNING id,post_id,user_id,body,created_at',[Number(req.params.id),req.userId,body]);if(!q.rowCount)return res.status(404).json({error:'Publicación no encontrada.'});const u=await pool.query('SELECT name,username FROM users WHERE id=$1',[req.userId]);res.status(201).json({comment:{id:Number(q.rows[0].id),body,user:{id:req.userId,name:u.rows[0].name,username:u.rows[0].username},createdAt:q.rows[0].created_at}})}catch(e){next(e)}
});
app.post('/api/users/:id/follow',needDb,auth,async(req,res,next)=>{
 try{const target=Number(req.params.id);if(target===req.userId)return res.status(400).json({error:'No podés seguirte a vos mismo.'});const found=await pool.query('SELECT id FROM users WHERE id=$1',[target]);if(!found.rowCount)return res.status(404).json({error:'Usuario no encontrado.'});const del=await pool.query('DELETE FROM follows WHERE follower_id=$1 AND followed_id=$2',[req.userId,target]);let following=false;if(!del.rowCount){await pool.query('INSERT INTO follows(follower_id,followed_id) VALUES($1,$2) ON CONFLICT DO NOTHING',[req.userId,target]);following=true;}const q=await pool.query('SELECT COUNT(*)::int AS count FROM follows WHERE followed_id=$1',[target]);res.json({following,followers:q.rows[0].count})}catch(e){next(e)}
});
app.get('/api/users/:id',needDb,async(req,res,next)=>{
 try{const viewer=Number(req.query.viewer)||0,q=await pool.query('SELECT u.id,u.name,u.username,u.bio,u.created_at,(SELECT COUNT(*)::int FROM follows f WHERE f.followed_id=u.id) AS followers,(SELECT COUNT(*)::int FROM follows f WHERE f.follower_id=u.id) AS following,(SELECT COUNT(*)::int FROM posts p WHERE p.user_id=u.id) AS posts,EXISTS(SELECT 1 FROM follows f WHERE f.follower_id=$2 AND f.followed_id=u.id) AS is_following FROM users u WHERE u.id=$1',[Number(req.params.id),viewer]);if(!q.rowCount)return res.status(404).json({error:'Usuario no encontrado.'});const u=q.rows[0];res.json({user:{id:Number(u.id),name:u.name,username:u.username,bio:u.bio,followers:u.followers,following:u.following,posts:u.posts,isFollowing:u.is_following}})}catch(e){next(e)}
});
app.get('/api/users/search',needDb,async(req,res,next)=>{
 try{const q=await pool.query('SELECT id,name,username,bio FROM users WHERE username ILIKE $1 OR name ILIKE $1 ORDER BY name LIMIT 20',['%'+String(req.query.q||'').slice(0,60)+'%']);res.json({users:q.rows.map(u=>({id:Number(u.id),name:u.name,username:u.username,bio:u.bio}))})}catch(e){next(e)}
});
app.patch('/api/me',needDb,auth,async(req,res,next)=>{
 try{const name=String(req.body.name||'').trim().slice(0,70),bio=String(req.body.bio||'').trim().slice(0,240);if(name.length<2)return res.status(400).json({error:'El nombre es demasiado corto.'});const q=await pool.query('UPDATE users SET name=$2,bio=$3 WHERE id=$1 RETURNING id,name,username,email,bio,created_at',[req.userId,name,bio]);res.json({user:safeUser(q.rows[0])})}catch(e){next(e)}
});
app.use((err,req,res,next)=>{console.error(err.message);if(err instanceof multer.MulterError)return res.status(err.code==='LIMIT_FILE_SIZE'?413:400).json({error:err.code==='LIMIT_FILE_SIZE'?'El archivo supera el límite de 40 MB.':'No se pudo procesar el archivo.'});res.status(500).json({error:'Ocurrió un error del servidor. Intentá de nuevo.'})});
app.listen(PORT,async()=>{console.log('Pril API listening on '+PORT);await initDb();if(!JWT_SECRET)console.error('WARNING: JWT_SECRET missing; set a long random secret in Render env vars.');});
process.on('SIGTERM',async()=>{if(pool)await pool.end();process.exit(0)});
