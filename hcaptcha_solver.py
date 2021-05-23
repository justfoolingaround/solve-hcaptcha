import base64
import json
from datetime import datetime
from math import ceil, floor
from random import randrange
from urllib.parse import quote, unquote

HCAPTCHA_SITECONFIG = "https://hcaptcha.com/checksiteconfig"
HCAPTCHA_CAPTCHA = "https://hcaptcha.com/getcaptcha"
HCAPTCHA_CAPTCHA_CHECK = "https://hcaptcha.com/checkcaptcha/%s"
HCAPTCHA_HSL = "https://assets.hcaptcha.com/c/b147199/hsl.js"

HEADERS = {
    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/89.0.4389.128 Safari/537.36'
}

def get_mouse_movements(timestamp):
    last_movement = timestamp
    motion_count = randrange(0x3e8, 0x2710)
    c = 0
    
    while c < motion_count:
        last_movement += randrange(0x0, 0xa)
        yield [randrange(0x0, 0x1f4), randrange(0x0, 0x1f4), last_movement]
        c += 1

class HSL(object):
    """
    Static helper methods for hsl.
    """
    @staticmethod
    def ord_of_index(s, i):
        return ord(s[i]) if (len(s) - 1) >= i else 0
    
    @staticmethod
    def r(_r):
        t =  _r.split('.')
        return {
            'header': json.loads(base64.b64decode(t[0] + '==').decode()),
            'payload': json.loads(base64.b64decode(t[1] + '==').decode()),
            'signature': base64.b64decode((t[2] + '==').replace('_', '/').replace('-', '+')),
            'raw': {
                'header': t[0],
                'payload': t[1],
                'signature': t[2],
            }
        }
    
    @staticmethod
    def hash(r):
        e = [1518500249, 1859775393, 2400959708, 3395469782]
        n = [1732584193, 4023233417, 2562383102, 271733878, 3285377520]
        o = unquote(quote(r)) + chr(128)
        a = (len(o) / 4 + 2)
        i = ceil(a / 16)
        f = {}
        u = 0
        h = 0 
        while u < i:
            f.update({u: {}})
            for c in range(16):
                f[u].update({c: (HSL.ord_of_index(o, 64*u + 4*c + 0) << 24) | (HSL.ord_of_index(o, 64*u + 4*c + 1) << 16) | (HSL.ord_of_index(o, 64*u + 4*c + 2) << 8) |(HSL.ord_of_index(o, 64*u + 4*c + 3) << 0)})                
            u += 1
        f[i - 1].update({14: floor(8 * (len(o) - 1) / 2**32)})
        f[i - 1].update({15: 8 * len(o) - 1 & 4294967295})
        
        while h < i:
            s = {}
            for g in range(16):
                s.update({g: f[h][g]})
            
            for l in range(16, 80):
                s.update({l: HSL.rotate_left(s[l - 3] ^ s[l - 8] ^ s[l - 14] ^ s[l - 16], 1)})
            
            v, d, p, S, w = n
            for C in range(80):
                y = floor(C / 20)
                T = HSL.rotate_left(v, 5) + HSL.f(y, d, p, S) + w + e[y] + s[C] >> 0
                w = S
                S = p
                p = HSL.rotate_left(d, 30) >> 0
                d = v
                v = T
                
            n[0] += v >> 0
            n[1] += d >> 0
            n[2] += p >> 0
            n[3] += S >> 0
            n[4] += w >> 0
            h += 1
            
        return n
        
    @staticmethod
    def digest(r):
        return [r[0] >> 24 & 255, r[0] >> 16 & 255, r[0] >> 8 & 255, 255 & r[0], r[1] >> 24 & 255, r[1] >> 16 & 255, r[1] >> 8 & 255, 255 & r[1], r[2] >> 24 & 255, r[2] >> 16 & 255, r[2] >> 8 & 255, 255 & r[2], r[3] >> 24 & 255, r[3] >> 16 & 255, r[3] >> 8 & 255, 255 & r[3], r[4] >> 24 & 255, r[4] >> 16 & 255, r[4] >> 8 & 255, 255 & r[4]]
        
    @staticmethod
    def hex(r):
        t = []
        e = 0
        
        while e < len(r):
            e += 1
            t.append(("00000000" + ("%x" % r[e]))[-8:])
        
        return ''.join(t)

    e = "0123456789/:abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
    
    @staticmethod
    def i(r):
        return ''.join(HSL.e[r[n]] for n in range(len(r)))
    
    @staticmethod
    def a(r):
        t = len(r) - 1
        while t >= 0:
            if r[t] < (len(HSL.e) - 1):
                r[t] += 1
                return True
            r[t] = 0
            t -= 1
        return False
    
    @staticmethod
    def o(r, e):
        def inner(_r, t):
            n = 0
            _e = 0
            _o = []
            while n < (8 * len(t)):
                _e = t[floor(n / 8)] >> n % 8 & 1
                _o.append(_e)
                n += 1
            a = _o[0:_r]
            return 0 == a[0] and (not(1 in a) or (a.index(1) >= _r - 1))
        
        n = e
        _o = HSL.hash(n)
        return inner(r, HSL.digest(_o))        
                
        
    @staticmethod
    def n(r, t):
        def inner(_r, _t):
            for e in range(25):
                n = {}
                for f in range(e):
                    n.update({f: 0})

                while HSL.a(n):
                    m = HSL.i(n)
                    u = str(_t) + "::" + m
                    if HSL.o(_r, u):
                        return m
        return "1:%s:%s:%s::%s" % (r, datetime.utcnow().strftime('%Y%m%d%H%M%S'), t, inner(r, t))
                
    @staticmethod
    def rotate_left(r, t):
        return r << t | r >> 32 - t
        
    @staticmethod
    def f(r, t, e, n):
        return {
            0: lambda t, e, n: t & e ^ ~t & n,
            1: lambda t, e, n: t ^ e ^ n,
            2: lambda t, e, n: t & e ^ t & n ^ e & n,
            3: lambda t, e, n: t ^ e ^ n,
        }[r](t, e, n)
        
    @staticmethod
    def generate_that_guy(t):
        """
        You may steal the code but never change this function name. I shall kill you if you do that.
        """
        a = HSL.r(t).get('payload')
        
        assert bool(a.get('d')) and bool(a.get('s'))
        return HSL.n(a.get('s'), a.get('d'))


def solve_attempt(session, hcaptcha_site_key, host):
    hcaptcha_response = session.get(HCAPTCHA_SITECONFIG, params={'host': host, 'sitekey': hcaptcha_site_key, 'sc': '1', 'swa': '0'}, headers=HEADERS).json()

    ts = (datetime.now() - datetime(1970, 1, 1)).total_seconds() + randrange(0x1e, 0x78)

    with session.post(HCAPTCHA_CAPTCHA, data={'sitekey': hcaptcha_site_key, 'host': host, 'n': HSL.generate_that_guy(hcaptcha_response.get('c', {}).get('req')), 'c': hcaptcha_response.get('c'), 'motionData': {'st': ts, 'dct': ts, 'mm': [*get_mouse_movements(ts)]}}) as attempt1:
        attempt1_json = attempt1.json()
        uuid = attempt1_json.get('generated_pass_UUID', '')
        if uuid:
            return attempt1_json.get('generated_pass_UUID', '')
    
    key = attempt1_json.get('key')
    tasks = attempt1_json.get('tasklist', {})
    job = attempt1_json.get('request_type')
    
    ts = (datetime.now() - datetime(1970, 1, 1)).total_seconds() + randrange(0x1e, 0x78)
    
    captcha_response = {
        'answers': {k: bool(randrange(0, 2)) for k, v in tasks.items()},
        'sitekey': hcaptcha_site_key,
        'serverdomain': host,
        'job_mode': job,
        'motionData': {
            'st': ts,
            'dct': ts,
            'mm': [*get_mouse_movements(ts)]
        }
    }
    
    with session.post(HCAPTCHA_CAPTCHA_CHECK % key, headers=HEADERS, data=captcha_response) as attempt2:
        attempt2_json = attempt2.json()
        uuid = attempt2_json.get('generated_pass_UUID', '')
        if uuid:
            return attempt2_json.get('generated_pass_UUID', '')
    
    raise Exception('Failed to solve hCaptcha, please try again later.')