import requests, re

class Status:
    Ok     = 'ok'
    Bad    = 'bad'
    Mfa    = 'mfa'
    Locked = 'locked'
    Custom = 'custom'
    Retry  = 'retry'

class Microsoft:
    def __init__(self):
        
        self.session = requests.Session()

    def get(self, email: str, proxy: dict = None) -> tuple:
        r = self.session.get(f"https://login.microsoftonline.com/consumers/oauth2/v2.0/authorize?client_info=1&haschrome=1&login_hint={email}&mkt=en&response_type=code&client_id=e9b154d0-7658-433b-bb25-6b8e0a8a7c59&scope=profile%20openid%20offline_access%20https%3A%2F%2Foutlook.office.com%2FM365.Access&redirect_uri=msauth%3A%2F%2Fcom.microsoft.outlooklite%2Ffcg80qvoM1YMKJZibjBwQcDfOno%253D", proxies=proxy)

        a1_match = re.search(r'urlPost":"(.*?)"', r.text)
        a1 = a1_match.group(1) if a1_match else None
        ppft_match = re.search(r'name=\\"PPFT\\" id=\\"i0327\\" value=\\"(.*?)\\"', r.text)
        ppft = ppft_match.group(1) if ppft_match else None
        msprequ = r.cookies.get("MSPRequ")
        uaid = r.cookies.get("uaid")
        mspok = r.cookies.get("MSPOK")
        oparams = r.cookies.get("OParams")

        if a1 is None or ppft is None or msprequ is None or uaid is None or mspok is None or oparams is None:
            return False
            
        return (a1, ppft, msprequ, uaid, mspok, oparams)
        
    def auth(self, email: str, password: str, proxy: dict = None) -> tuple:
        LoginParams = self.get(email, proxy)
        if not LoginParams:
            print("microsoft is a bitch")
            return (Status.Retry, None, None)

        a1, ppft, msprequ, uaid, mspok, oparams = LoginParams

        r = self.session.post(a1,
            headers={
                "Host": "login.live.com",
                "Connection": "keep-alive",
                "Cache-Control": "max-age=0",
                "Upgrade-Insecure-Requests": "1",
                "Origin": "https://login.live.com",
                "Content-Type": "application/x-www-form-urlencoded",
                "User-Agent": "Mozilla/5.0 (Linux; Android 9; SM-G975N Build/PQ3B.190801.08041932; wv) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/91.0.4472.114 Mobile Safari/537.36 PKeyAuth/1.0",
                "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9",
                "X-Requested-With": "com.microsoft.outlooklite",
                "Sec-Fetch-Site": "same-origin",
                "Sec-Fetch-Mode": "navigate",
                "Sec-Fetch-User": "?1",
                "Sec-Fetch-Dest": "document",
                "Referer": a1,
                "Accept-Encoding": "gzip, deflate",
                "Accept-Language": "en-US,en;q=0.9",
                "Cookie": f"MSPRequ={msprequ}; uaid={uaid}; MSPOK={mspok}; OParams={oparams};"
            }, data=f"i13=1&login={email}&loginfmt={email}&type=11&LoginOptions=1&lrt=&lrtPartition=&hisRegion=&hisScaleUnit=&passwd={password}&ps=2&psRNGCDefaultType=&psRNGCEntropy=&psRNGCSLK=&canary=&ctx=&hpgrequestid=&PPFT={ppft}&PPSX=PassportR&NewUser=1&FoundMSAs=&fspost=0&i21=0&CookieDisclosure=0&IsFidoSupported=0&isSignupPost=0&isRecoveryAttemptPost=0&i19=9960", allow_redirects=False, proxies=proxy)
            
        if "JSH" in r.cookies or "JSHP" in r.cookies or "ANON" in r.cookies or "WLSSC" in r.cookies or "https://login.live.com/oauth20_desktop.srf?" in r.url or "fntobu-y" in r.text:
            return Status.Ok
        elif "account or password is incorrect" in r.text:
            return Status.Bad
        elif "https://account.live.com/identity/confirm" in r.url or "https://account.live.com/recover" in r.url:
            return Status.Mfa
        elif "https://account.live.com/Abuse" in r.url or "https://login.live.com/finisherror.srf" in r.url:
            return Status.Locked
        elif "too many times with" in r.text and "Too Many Requests" in r.text:
            return Status.Retry
        else:
            return Status.Custom
            
c = Microsoft()
status = c.auth("email", "password")
print(status)
