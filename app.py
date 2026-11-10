import csv, io, ipaddress, json, socket, threading, time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from flask import Flask, render_template, request, jsonify, Response
import errno
import select

app=Flask(__name__)
RULES=[]; HISTORY=[]; LOCK=threading.Lock()
COMMON={21:'FTP',22:'SSH',25:'SMTP',53:'DNS',80:'HTTP',110:'POP3',143:'IMAP',443:'HTTPS',445:'SMB',3306:'MySQL',3389:'RDP',5000: 'Flask / HTTP (common)',5432:'PostgreSQL',6379:'Redis',8080:'HTTP-alt'}

def resolve_target(target):
    target=target.strip()
    if not target or len(target)>253: raise ValueError('Enter a valid IP address or hostname')
    try: ip=ipaddress.ip_address(socket.gethostbyname(target))
    except (socket.gaierror,ValueError): raise ValueError('Hostname could not be resolved')
    if not (ip.is_private or ip.is_loopback): raise ValueError('Only private or localhost addresses are permitted')
    if ip.is_multicast or ip.is_unspecified or ip.is_link_local: raise ValueError('This target is not permitted')
    return str(ip)

def parse_ports(value):
    ports=set()
    for token in value.split(','):
        token=token.strip()
        if not token: continue
        if '-' in token:
            a,b=map(int,token.split('-'))
            if a>b or b-a>255: raise ValueError('Each port range must span at most 256 ports')
            ports.update(range(a,b+1))
        else: ports.add(int(token))
    if not ports or len(ports)>256 or any(not 1<=p<=65535 for p in ports): raise ValueError('Select 1–256 valid ports (1–65535)')
    return sorted(ports)

def service(port,protocol):
    try: return socket.getservbyport(port,protocol.lower())
    except OSError: return COMMON.get(port,'unknown')


def tcp_connect(ip, port):
    timeout = 1.5

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        try:
            sock.setblocking(False)
            result = sock.connect_ex((ip, port))

            # Connection succeeded immediately
            if result == 0:
                return 'open'

            # Connection is still in progress
            pending = {
                errno.EINPROGRESS,
                errno.EWOULDBLOCK,
                errno.EALREADY,
                10035,  # Windows WSAEWOULDBLOCK
                10036,  # Windows WSAEINPROGRESS
                10037   # Windows WSAEALREADY
            }

            if result in pending:
                # Wait for the connection to finish
                _, writable, exceptional = select.select(
                    [], [sock], [sock], timeout
                )

                if not writable and not exceptional:
                    return 'filtered'

                # Get the final connection result
                result = sock.getsockopt(
                    socket.SOL_SOCKET,
                    socket.SO_ERROR
                )

            if result == 0:
                return 'open'

            if result in (errno.ECONNREFUSED, 10061):
                return 'closed'

            if result in (errno.ETIMEDOUT, 10060):
                return 'filtered'

            if result in (
                errno.EHOSTUNREACH,
                errno.ENETUNREACH,
                10051,
                10065
            ):
                return 'unreachable'

            print(f"Port {port}: socket error {result}")
            return 'error'

        except (OSError, ValueError) as e:
            print(f"Port {port}: {e}")
            return 'error'

def nmap_scan(ip,ports,mode):
    try: import nmap
    except ImportError: raise ValueError('Install python-nmap and Nmap to use SYN/UDP scans')
    scanner=nmap.PortScanner()
    flag='-sS' if mode=='syn' else '-sU'
    try: scanner.scan(hosts=ip,ports=','.join(map(str,ports)),arguments=f'{flag} -Pn -n --max-retries 0 --host-timeout 25s')
    except Exception as exc: raise ValueError(f'Nmap scan failed (SYN/UDP may require administrator privileges): {exc}')
    proto='tcp' if mode=='syn' else 'udp'
    info=scanner[ip].get(proto,{}) if ip in scanner.all_hosts() else {}
    return [{'ip':ip,'port':p,'protocol':proto.upper(),'service':info.get(p,{}).get('name') or service(p,proto),'status':info.get(p,{}).get('state','unknown')} for p in ports]

def rule_match(rule,packet):
    try:
        if rule['ip']!='any' and ipaddress.ip_address(packet['ip']) not in ipaddress.ip_network(rule['ip'],strict=False): return False
    except ValueError: return False
    return (rule['port']=='any' or int(rule['port'])==int(packet['port'])) and (rule['protocol']=='any' or rule['protocol']==packet['protocol'])

def evaluate(packet):
    for rule in sorted(RULES,key=lambda x:(x['priority'],x['id'])):
        if rule_match(rule,packet): return {'decision':rule['action'],'matched_rule':rule['id'],'reason':'Matched priority rule'}
    return {'decision':'allow','matched_rule':None,'reason':'Default allow (no matching rule)'}

@app.get('/')
def home(): return render_template('index.html')

@app.post('/api/scan')
def scan():
    data=request.get_json(silent=True) or {}
    try:
        ip=resolve_target(str(data.get('target','')))
        ports=parse_ports(str(data.get('ports','21,22,53,80,443,8080')))
        mode=data.get('mode','connect')
        if mode not in ('connect','syn','udp'): raise ValueError('Invalid scan type')
        started=time.time()
        if mode=='connect':
            with ThreadPoolExecutor(max_workers=24) as pool:
                futures={pool.submit(tcp_connect,ip,p):p for p in ports}
                results=[{'ip':ip,'port':futures[f],'protocol':'TCP','service':service(futures[f],'tcp'),'status':f.result()} for f in as_completed(futures)]
            results.sort(key=lambda r:r['port'])
        else: results=nmap_scan(ip,ports,mode)
        stats = {
    'total': len(results),
    'open': sum(r['status'] == 'open' for r in results),
    'closed': sum(r['status'] == 'closed' for r in results),
    'other': sum(
        r['status'] not in ('open', 'closed')
        for r in results
    ),
    'filtered': sum(
        r['status'] == 'filtered'
        for r in results
    ),
    'seconds': round(time.time() - started, 2)}
        entry={'id':int(time.time()*1000),'date':datetime.now().isoformat(timespec='seconds'),'target':ip,'mode':mode,'stats':stats,'results':results}
        with LOCK: HISTORY.insert(0,entry); del HISTORY[20:]
        return jsonify(entry)
    except (ValueError,TypeError) as exc: return jsonify({'error':str(exc)}),400

@app.route('/api/rules',methods=['GET','POST'])
def rules():
    if request.method=='GET': return jsonify(sorted(RULES,key=lambda r:(r['priority'],r['id'])))
    data=request.get_json(silent=True) or {}
    try:
        action=data.get('action'); protocol=data.get('protocol'); rawip=str(data.get('ip','any')).strip() or 'any'; rawport=str(data.get('port','any')).strip() or 'any'
        if action not in ('allow','deny') or protocol not in ('tcp','udp','any'): raise ValueError('Invalid action/protocol')
        if rawip!='any': ipaddress.ip_network(rawip,strict=False)
        if rawport!='any' and not 1<=int(rawport)<=65535: raise ValueError('Invalid port')
        priority=int(data.get('priority',100))
        if not 0<=priority<=10000: raise ValueError('Priority must be 0–10000')
        rule={'id':int(time.time()*1000000),'action':action,'protocol':protocol,'ip':rawip,'port':rawport,'priority':priority}
        with LOCK: RULES.append(rule)
        return jsonify(rule),201
    except (ValueError,TypeError) as exc: return jsonify({'error':str(exc)}),400

@app.route('/api/rules/<int:rule_id>',methods=['DELETE','PUT'])
def change_rule(rule_id):
    with LOCK:
        existing=next((r for r in RULES if r['id']==rule_id),None)
        if not existing: return jsonify({'error':'Rule not found'}),404
        if request.method=='DELETE': RULES.remove(existing); return jsonify({'ok':True})
    data=request.get_json(silent=True) or {}
    # Reuse creation validation and replace only after successful validation.
    with app.test_request_context('/api/rules',method='POST',json=data):
        response=rules()
    if isinstance(response,tuple) and response[1]==400: return response
    new=response[0].get_json() if isinstance(response,tuple) else response.get_json()
    with LOCK:
        RULES[:]=[r for r in RULES if r['id'] not in (rule_id,new['id'])]
        new['id']=rule_id; RULES.append(new)
    return jsonify(new)

@app.post('/api/simulate')
def simulate():
    data=request.get_json(silent=True) or {}
    try:
        ip=str(ipaddress.ip_address(data.get('ip','')))
        port=int(data.get('port'))
        proto=str(data.get('protocol','tcp')).lower()
        if not 1<=port<=65535 or proto not in ('tcp','udp'): raise ValueError('Invalid port/protocol')
        return jsonify({'packet':{'ip':ip,'port':port,'protocol':proto},**evaluate({'ip':ip,'port':port,'protocol':proto})})
    except (ValueError,TypeError): return jsonify({'error':'Enter a valid IP, port, and protocol'}),400

@app.get('/api/history')
def history(): return jsonify([{'id':e['id'],'date':e['date'],'target':e['target'],'mode':e['mode'],'stats':e['stats']} for e in HISTORY])

@app.get('/api/export/<int:scan_id>')
def export(scan_id):
    entry=next((e for e in HISTORY if e['id']==scan_id),None)
    if not entry: return jsonify({'error':'Scan not found'}),404
    out=io.StringIO(); writer=csv.DictWriter(out,fieldnames=['ip','port','protocol','service','status']); writer.writeheader();writer.writerows(entry['results'])
    return Response(out.getvalue(),mimetype='text/csv',headers={'Content-Disposition':f'attachment; filename="scan_{scan_id}.csv"'})

if __name__=='__main__': app.run(host='127.0.0.1',port=5000,debug=False)
