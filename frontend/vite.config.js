import { defineConfig } from 'vite';
export default defineConfig({server:{proxy:{'/api':{target:process.env.CYPHERCHAT_API || 'http://127.0.0.1:8000',rewrite:p=>p.replace(/^\/api/,'')},'/ws':{target:process.env.CYPHERCHAT_API || 'http://127.0.0.1:8000',ws:true}}}});
