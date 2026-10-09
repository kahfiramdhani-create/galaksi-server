// GALAKSI server (Cloudflare Worker)
// Binding: DB (D1). Variabel: SECRET, ADMIN_CODE, TG_TOKEN, TG_CHAT, TG_SECRET
const H={'Access-Control-Allow-Origin':'*','Access-Control-Allow-Headers':'Authorization,Content-Type','Access-Control-Allow-Methods':'GET,POST,OPTIONS'};
const J=(o,s=200)=>new Response(JSON.stringify(o),{status:s,headers:{...H,'Content-Type':'application/json'}});
const E=(m,s=400)=>J({ok:false,error:m},s);
const enc=new TextEncoder(),hex=b=>[...new Uint8Array(b)].map(x=>x.toString(16).padStart(2,'0')).join('');
const hmac=async(k,m)=>hex(await crypto.subtle.sign('HMAC',await crypto.subtle.importKey('raw',enc.encode(k),{name:'HMAC',hash:'SHA-256'},false,['sign']),enc.encode(m)));
const pbk=async(pw,salt)=>hex(await crypto.subtle.deriveBits({name:'PBKDF2',hash:'SHA-256',salt:enc.encode(salt),iterations:100000},await crypto.subtle.importKey('raw',enc.encode(pw),'PBKDF2',false,['deriveBits']),256));
const mk=async(id,env)=>{const e=Date.now()+30*864e5;return id+'.'+e+'.'+await hmac(env.SECRET,id+'.'+e)};
const pub=u=>({id:u.id,nama:u.nama,nis:u.nis,kelas:u.kelas,email:u.email,role:u.role,status:u.status,alasan:u.alasan});
async function who(req,env){const[id,e,sig]=(req.headers.get('Authorization')||'').slice(7).split('.');if(!sig||+e<Date.now()||sig!==await hmac(env.SECRET,id+'.'+e))return null;return env.DB.prepare('SELECT * FROM users WHERE id=?').bind(id).first()}
const tg=(env,m,b)=>fetch('https://api.telegram.org/bot'+env.TG_TOKEN+'/'+m,b instanceof FormData?{method:'POST',body:b}:{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(b)});

export async function onRequest({request:req,env}){
  if(req.method==='OPTIONS')return new Response(null,{status:204,headers:H});
  const p=new URL(req.url).pathname.replace(/^\/api\/?/,'').split('/'),post=req.method==='POST';
  try{
    // tombol Setujui/Tolak dari Telegram
    if(p[0]==='tg'&&p[1]===env.TG_SECRET&&post){
      const cq=(await req.json()).callback_query;
      if(cq&&String(cq.from.id)===String(env.TG_CHAT)&&/^[ar]:/.test(cq.data||'')){
        const a=cq.data[0]==='a',id=cq.data.slice(2);
        await env.DB.prepare("UPDATE users SET status=?,alasan=? WHERE id=? AND role!='admin'").bind(a?'verified':'rejected',a?null:'Data tidak cocok dengan kartu',id).run();
        await tg(env,'answerCallbackQuery',{callback_query_id:cq.id,text:a?'Disetujui':'Ditolak'});
        await tg(env,'editMessageReplyMarkup',{chat_id:cq.message.chat.id,message_id:cq.message.message_id,reply_markup:{inline_keyboard:[[{text:a?'✅ Disetujui':'❌ Ditolak',callback_data:'x'}]]}});
      }
      return J({ok:true});
    }
    if(p[0]==='register'&&post){
      const f=await req.formData(),g=k=>String(f.get(k)||'').trim(),card=f.get('card');
      const d={nama:g('nama'),nis:g('nis'),kelas:g('kelas'),email:g('email').toLowerCase(),pw:String(f.get('password')||'')};
      if(d.nama.length<3||!/^\d{4,20}$/.test(d.nis)||!d.kelas||!/^\S+@\S+\.\S+$/.test(d.email)||d.pw.length<8)return E('Data tidak valid.');
      if(!card||typeof card==='string'||!card.type.startsWith('image/')||card.size>1.4e6)return E('Foto kartu tidak valid atau terlalu besar (maks. 1,4 MB).');
      if(await env.DB.prepare('SELECT 1 FROM users WHERE email=? OR nis=?').bind(d.email,d.nis).first())return E('Email atau NIS sudah terdaftar.',409);
      const id=crypto.randomUUID(),salt=crypto.randomUUID(),adm=!!env.ADMIN_CODE&&g('kode')===env.ADMIN_CODE,buf=await card.arrayBuffer();
      let b='';const a8=new Uint8Array(buf);for(let i=0;i<a8.length;i+=8192)b+=String.fromCharCode(...a8.subarray(i,i+8192));b=btoa(b);
      await env.DB.prepare('INSERT INTO users(id,nama,nis,kelas,email,salt,pw,role,status,at,card,ctype) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)').bind(id,d.nama,d.nis,d.kelas,d.email,salt,await pbk(d.pw,salt),adm?'admin':'murid',adm?'verified':'pending',Date.now(),b,card.type).run();
      if(!adm&&env.TG_TOKEN&&env.TG_CHAT){
        const x=new FormData();x.append('chat_id',env.TG_CHAT);x.append('photo',new Blob([buf],{type:card.type}),'kartu.jpg');
        x.append('caption','Pendaftar baru GALAKSI\n'+d.nama+'\nNIS '+d.nis+' · '+d.kelas+'\n'+d.email);
        x.append('reply_markup',JSON.stringify({inline_keyboard:[[{text:'✅ Setujui',callback_data:'a:'+id},{text:'❌ Tolak',callback_data:'r:'+id}]]}));
        await tg(env,'sendPhoto',x).catch(()=>{});
      }
      return J({ok:true,token:await mk(id,env),user:{id,nama:d.nama,nis:d.nis,kelas:d.kelas,email:d.email,role:adm?'admin':'murid',status:adm?'verified':'pending'}});
    }
    if(p[0]==='login'&&post){
      const b=await req.json(),id=String(b.id||'').toLowerCase(),u=await env.DB.prepare('SELECT * FROM users WHERE email=? OR nis=?').bind(id,id).first();
      if(!u||u.pw!==await pbk(String(b.password||''),u.salt))return E('Email/NIS atau kata sandi salah.',401);
      return J({ok:true,token:await mk(u.id,env),user:pub(u)});
    }
    const u=await who(req,env);if(!u)return E('Sesi berakhir. Masuk lagi.',401);
    if(p[0]==='me')return J({ok:true,user:pub(u)});
    if(p[0]==='password'&&post){
      const b=await req.json();
      if(u.pw!==await pbk(String(b.old||''),u.salt))return E('Kata sandi lama salah.');
      if(String(b.password||'').length<8)return E('Minimal 8 karakter.');
      const salt=crypto.randomUUID();await env.DB.prepare('UPDATE users SET salt=?,pw=? WHERE id=?').bind(salt,await pbk(b.password,salt),u.id).run();
      return J({ok:true});
    }
    if(p[0]==='card'){
      if(u.role!=='admin'&&u.id!==p[1])return E('Dilarang.',403);
      const o=await env.DB.prepare('SELECT card,ctype FROM users WHERE id=?').bind(p[1]).first();
      return o&&o.card?new Response(Uint8Array.from(atob(o.card),c=>c.charCodeAt(0)),{headers:{...H,'Content-Type':o.ctype||'image/jpeg','Cache-Control':'private, max-age=300'}}):E('Tidak ada.',404);
    }
    if(p[0]==='admin'&&p[1]==='decide'&&post){
      const b=await req.json(),t=await env.DB.prepare('SELECT * FROM users WHERE id=?').bind(b.id).first();
      const self=b.action==='delete'&&b.id===u.id&&u.status==='rejected';
      if(!self&&u.role!=='admin')return E('Khusus pengurus.',403);
      if(!t||(t.role==='admin'&&!self))return E('Akun tidak ditemukan.',404);
      if(b.action==='delete'){await env.DB.prepare('DELETE FROM users WHERE id=?').bind(t.id).run()}
      else await env.DB.prepare('UPDATE users SET status=?,alasan=? WHERE id=?').bind(b.action==='approve'?'verified':'rejected',b.action==='approve'?null:String(b.alasan||'Data tidak cocok dengan kartu').slice(0,200),t.id).run();
      return J({ok:true});
    }
    if(u.role!=='admin')return E('Khusus pengurus.',403);
    if(p[0]==='admin'&&p[1]==='users')return J({ok:true,users:(await env.DB.prepare("SELECT id,nama,nis,kelas,email,status,alasan FROM users WHERE role!='admin' ORDER BY at DESC").all()).results});
    return E('Tidak ditemukan.',404);
  }catch(e){return E('Kesalahan server.',500)}
}

export default{fetch:(request,env)=>onRequest({request,env})};
  
