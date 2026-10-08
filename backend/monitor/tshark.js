// Run with: npm run monitor  (needs Wireshark/TShark installed + capture permission; on Windows run from an admin shell)
import {spawn} from 'child_process';import 'dotenv/config';
const IFACE=process.env.MONITOR_IFACE||'1',API=`http://localhost:${process.env.PORT||4000}/api/alerts`,seen=new Map();
const ts=spawn('tshark',['-i',IFACE,'-l','-T','fields','-e','ip.src','-Y','tcp.flags.syn==1 && tcp.flags.ack==0']);
ts.stdout.on('data',d=>d.toString().split('\n').filter(Boolean).forEach(ip=>seen.set(ip,(seen.get(ip)||0)+1)));
setInterval(async()=>{for(const[ip,n]of seen)if(n>100)await fetch(API,{method:'POST',headers:{'Content-Type':'application/json','X-Monitor-Key':process.env.MONITOR_KEY},body:JSON.stringify({sev:n>500?'High':'Medium',msg:`TShark: ${n} SYN packets in 10s from ${ip} (possible scan/flood)`})}).catch(()=>{});seen.clear()},10000);
ts.stderr.on('data',()=>{});ts.on('error',e=>console.error('TShark not found:',e.message));
