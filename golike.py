from model import GolikeAuth, auto_solve_captcha

class Golike_Instagram:
    def __init__(self, token):
        self.auth = GolikeAuth.from_token(token, enable_sig=True, fetch_session=True, captcha_solver=auto_solve_captcha, captcha_max_attempts=3)

    def me(self):
        try:
            response = self.auth.get('/users/me').json()
            return response
        except Exception:
            return {}
        if response["status"] == 200 and response["success"] == True:
            name     = response["data"]["name"]
            username = response["data"]["username"]
            id       = response["data"]["id"]
            coin     = response["data"]["coin"]
            _coin    = f"{coin:,}".replace(",", ".")

    def report(self):
        try:
            response = self.auth.get('/statistics/report').json()
            return response
        except Exception:
            return {}
        print(response)
        report = 0
        platforms = ["facebook", "instagram", "tiktok", "shopee", "twitter", "lazada", "youtube", "traffic", "review", "threads", "linkedin", "snapchat", "pinterest", "bluesky", "tumblr", "soundcloud"]
        if response["status"] == 200 and response["success"] == True:
            for platform in platforms:
                report += int(f"{response[platform]["pending_coin"]:,}".replace(",", "."))
                pending = int(f"{response["instagram"]["pending_coin"]:,}".replace(",", "."))
            print(report, pending)

    def account(self):
        try:
            response = self.auth.get('/instagram-account').json()
            return response
        except Exception:
            return {}
        response = self.auth.get('/instagram-account').json()
        if response["status"] == 200 and response["success"] == True:
            for taikhoan in response["data"]:
                username     = taikhoan["instagram_username"]
                id           = taikhoan["id"]
                uid          = taikhoan["instagram_id"]
                print(username, id, instagram_id)

    def get_jobs(self, account_id):
        try:
            response = self.auth.get('/advertising/publishers/instagram/jobs', params = {
                'instagram_account_id': account_id,
                'data': 'null',
            }).json()
            return response
        except Exception:
            return {}
        if response["status"] == 200 and response["success"] == True:
            for nhiemvu in (data if isinstance(data, list) else [data] if isinstance(data, dict) and data else []):
                ads_id    = nhiemvu["id"]
                link      = nhiemvu["link"]
                object_id = nhiemvu["object_id"]
                type_jobs = nhiemvu["type"]
                coin      = nhiemvu["fix_coin_job"]
                _coin     = f"{coin:,}".replace(",", ".")

    def complete_jobs(self, account_id, ads_id):
        try:
            response = self.auth.post('/advertising/publishers/instagram/complete-jobs', json = {
                'instagram_users_advertising_id': ads_id,
                'instagram_account_id': account_id,
                'async': True,
                'data': None,
            }).json()
            return response
        except Exception:
            return False
        if response["status"] == 200 and response["success"] == True:
            messa = response["message"]
            if "Báo cáo thành công" in messa:
                return True
            else:
                return False

    def skip_jobs(self, account_id, ads_id, object_id, type):
        try:
            self.auth.post('/report/send', json = {
                'description': 'Tôi không muốn làm Job này',
                'users_advertising_id': ads_id,
                'type': 'ads',
                'provider': 'instagram',
                'fb_id': account_id,
                'error_type': 0,
            }).json()
        except Exception:
            pass
        try:
            response = self.auth.post('/advertising/publishers/instagram/skip-jobs', json = {
                'ads_id': ads_id,
                'object_id': str(object_id),
                'account_id': account_id,
                'type': type,
            }).json()
            return response
        except Exception:
            return {}
        if response["status"] == 200 and response["success"] == True:
            messa = response["message"]
            if "Bỏ qua thành công !" in messa:
                return True
            else:
                return False

class Golike_Threads:
    def __init__(self, token):
        self.auth = GolikeAuth.from_token(token, enable_sig=True, fetch_session=True, captcha_solver=auto_solve_captcha, captcha_max_attempts=3)

    def me(self):
        try:
            response = self.auth.get('/users/me').json()
            return response
        except Exception:
            return {}
        if response["status"] == 200 and response["success"] == True:
            name     = response["data"]["name"]
            username = response["data"]["username"]
            id       = response["data"]["id"]
            coin     = response["data"]["coin"]
            _coin    = f"{coin:,}".replace(",", ".")

    def report(self):
        try:
            response = self.auth.get('/statistics/report').json()
            return response
        except Exception:
            return {}
        print(response)
        report = 0
        platforms = ["facebook", "instagram", "tiktok", "shopee", "twitter", "lazada", "youtube", "traffic", "review", "threads", "linkedin", "snapchat", "pinterest", "bluesky", "tumblr", "soundcloud"]
        if response["status"] == 200 and response["success"] == True:
            for platform in platforms:
                report += int(f"{response[platform]["pending_coin"]:,}".replace(",", "."))
                pending = int(f"{response["threads"]["pending_coin"]:,}".replace(",", "."))
            print(report, pending)

    def account(self):
        try:
            response = self.auth.get('/threads-account').json()
            return response
        except Exception:
            return {}
        response = self.auth.get('/instagram-account').json()
        if response["status"] == 200 and response["success"] == True:
            for taikhoan in response["data"]:
                username     = taikhoan["threads_username"]
                id           = taikhoan["id"]
                uid          = taikhoan["uid"]
                print(username, id, uid)

    def get_jobs(self, account_id):
        try:
            response = self.auth.get('/advertising/publishers/threads/jobs', params = {
                'account_id': account_id
            }).json()
            return response
        except Exception:
            return {}
        if response["status"] == 200 and response["success"] == True:
            for nhiemvu in (data if isinstance(data, list) else [data] if isinstance(data, dict) and data else []):
                ads_id    = nhiemvu["id"]
                link      = nhiemvu["link"]
                object_id = nhiemvu["object_id"]
                type_jobs = nhiemvu["type"]
                coin      = nhiemvu["fix_coin_job"]
                _coin     = f"{coin:,}".replace(",", ".")

    def complete_jobs(self, account_id, ads_id):
        try:
            response = self.auth.post('/advertising/publishers/threads/complete-jobs', json = {
                'account_id': account_id,
                'ads_id': ads_id,
            }).json()
            return response
        except Exception:
            return False
        if response["status"] == 200 and response["success"] == True:
            messa = response["message"]
            if "Báo cáo thành công" in messa:
                return True
            else:
                return False

    def skip_jobs(self, account_id, ads_id, object_id, type):
        try:
            response = self.auth.post('/advertising/publishers/threads/skip-jobs', json = {
                'account_id': account_id,
                'ads_id': ads_id,
                'object_id': str(object_id),
            }).json()
            return response
        except Exception:
            return {}
        if response["status"] == 200 and response["success"] == True:
            messa = response["message"]
            if "Bỏ qua thành công !" in messa:
                return True
            else:
                return False

class Golike_Pinterest:
    def __init__(self, token):
        self.auth = GolikeAuth.from_token(token, enable_sig=True, fetch_session=True, captcha_solver=auto_solve_captcha, captcha_max_attempts=3)

    def me(self):
        try:
            response = self.auth.get('/users/me').json()
            return response
        except Exception:
            return {}
        if response["status"] == 200 and response["success"] == True:
            name     = response["data"]["name"]
            username = response["data"]["username"]
            id       = response["data"]["id"]
            coin     = response["data"]["coin"]
            _coin    = f"{coin:,}".replace(",", ".")

    def report(self):
        try:
            response = self.auth.get('/statistics/report').json()
            return response
        except Exception:
            return {}
        print(response)
        report = 0
        platforms = ["facebook", "instagram", "tiktok", "shopee", "twitter", "lazada", "youtube", "traffic", "review", "threads", "linkedin", "snapchat", "pinterest", "bluesky", "tumblr", "soundcloud"]
        if response["status"] == 200 and response["success"] == True:
            for platform in platforms:
                report += int(f"{response[platform]["pending_coin"]:,}".replace(",", "."))
                pending = int(f"{response["pinterest"]["pending_coin"]:,}".replace(",", "."))
            print(report, pending)

    def account(self):
        try:
            response = self.auth.get('/pinterest-account').json()
            return response
        except Exception:
            return {}
        response = self.auth.get('/instagram-account').json()
        if response["status"] == 200 and response["success"] == True:
            for taikhoan in response["data"]:
                username     = taikhoan["pinterest_username"]
                id           = taikhoan["id"]
                uid          = taikhoan["uid"]
                print(username, id, uid)

    def get_jobs(self, account_id):
        try:
            response = self.auth.get('/advertising/publishers/pinterest/jobs', params = {
                'account_id': account_id
            }).json()
            return response
        except Exception:
            return {}
        if response["status"] == 200 and response["success"] == True:
            for nhiemvu in (data if isinstance(data, list) else [data] if isinstance(data, dict) and data else []):
                ads_id    = nhiemvu["id"]
                link      = nhiemvu["link"]
                object_id = nhiemvu["object_id"]
                type_jobs = nhiemvu["type"]
                coin      = nhiemvu["fix_coin_job"]
                _coin     = f"{coin:,}".replace(",", ".")

    def complete_jobs(self, account_id, ads_id):
        try:
            response = self.auth.post('/advertising/publishers/pinterest/complete-jobs', json = {
                'account_id': account_id,
                'ads_id': ads_id,
            }).json()
            return response
        except Exception:
            return False
        if response["status"] == 200 and response["success"] == True:
            messa = response["message"]
            if "Báo cáo thành công" in messa:
                return True
            else:
                return False

    def skip_jobs(self, account_id, ads_id, object_id, type):
        try:
            response = self.auth.post('/advertising/publishers/pinterest/skip-jobs', json = {
                'account_id': account_id,
                'ads_id': ads_id,
                'object_id': str(object_id),
            }).json()
            return response
        except Exception:
            return {}
        if response["status"] == 200 and response["success"] == True:
            messa = response["message"]
            if "Bỏ qua thành công !" in messa:
                return True
            else:
                return False

token = 'Bearer eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJodHRwOlwvXC9nYXRld2F5LmdvbGlrZS5uZXRcL2FwaVwvbG9naW4iLCJpYXQiOjE3OTU0OTc1MDEsImV4cCI6MTgyNzAzMzUwMSwibmJmIjoxNzk1NDk3NTAxLCJqdGkiOiJYODlaT0ZKc0RmbkVNUE83Iiwic3ViIjoiMDFNMEVNNjc2V1gyQzVHNkdSVjEyQVZXOVkiLCJwcnYiOiJiOTEyNzk5NzhmMTFhYTdiYzU2NzA0ODdmZmYwMWUyMjgyNTNmZTQ4In0.nW1k9N3wmdyXpj83cfPwBRpXw1ugjBPnSYCKZ5tLMLA'
response = Golike_Instagram(token).get_jobs('961042')
print(response)