import os
import re
import json
import time
import requests
from datetime import datetime

# GitHub API 相关配置（用于更新 Secret）
GITHUB_TOKEN = os.getenv('GITHUB_TOKEN')
GITHUB_REPO = os.getenv('GITHUB_REPOSITORY')  # 格式：owner/repo，由 GitHub Actions 自动提供


def set_github_output(name, value):
    """
    向 GitHub Actions 的输出文件写入键值对。
    支持多行文本（使用 EOF 分隔符），兼容本地调试。
    """
    if "GITHUB_OUTPUT" in os.environ:
        with open(os.environ["GITHUB_OUTPUT"], "a") as f:
            # 使用 heredoc 风格避免换行/特殊字符问题
            f.write(f"{name}<<EOF\n{value}\nEOF\n")
    else:
        # 本地调试时打印（不影响功能）
        print(f"[DEBUG] Would set output {name} = '''\n{value}\n'''")


def main():
    # 从环境变量获取配置
    cookie = os.getenv('INVITES_COOKIE')
    username = os.getenv('INVITES_USERNAME')
    password = os.getenv('INVITES_PASSWORD')
    
    if not cookie and not (username and password):
        error_msg = "未配置 Cookie 且未配置用户名密码，无法签到"
        print(f"错误：{error_msg}")
        set_github_output("checkin_result", "failure")
        set_github_output("checkin_msg", error_msg)
        return False

    # 基础配置
    USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36 Edg/142.0.0.0"
    RETRY_COUNT = 2
    RETRY_INTERVAL = 5  # 分钟

    for attempt in range(RETRY_COUNT):
        print(f"\n第 {attempt + 1} 次签到尝试")
        try:
            # 第一步：尝试用 Cookie 签到
            cookie_checkin_success = False
            if cookie:
                print("尝试使用现有 Cookie 签到...")
                cookie_checkin_success = cookie_checkin(cookie, USER_AGENT)
                if cookie_checkin_success:
                    return True

            # 第二步：Cookie 签到失败，尝试用户名密码登录后签到
            if not cookie_checkin_success and username and password:
                print("Cookie 签到失败，尝试用户名密码登录...")
                login_result = login_with_credentials(username, password, USER_AGENT)
                if not login_result["success"]:
                    print(f"登录失败：{login_result['error']}")
                    continue

                # 登录成功，获取新 Cookie 并更新
                new_cookie = login_result["cookie"]
                print(f"登录成功，新 Cookie：{new_cookie}")

                # 自动更新 GitHub Secrets 中的 Cookie
                if GITHUB_TOKEN and GITHUB_REPO:
                    update_secret_result = update_github_secret("INVITES_COOKIE", new_cookie)
                    if update_secret_result:
                        print("✅ GitHub Secrets 中的 Cookie 已自动更新")
                    else:
                        print("⚠️ GitHub Secrets 更新失败，请手动更新 Cookie")

                # 用新 Cookie 执行签到
                print("使用新 Cookie 执行签到...")
                new_cookie_checkin_success = cookie_checkin(new_cookie, USER_AGENT)
                if new_cookie_checkin_success:
                    return True

        except Exception as e:
            print(f"错误：签到过程中发生异常 - {str(e)}")
            if attempt < RETRY_COUNT - 1:
                print(f"等待 {RETRY_INTERVAL} 分钟后重试...")
                time.sleep(RETRY_INTERVAL * 60)

    # 所有尝试失败
    fail_msg = (
        f"❌ 所有 {RETRY_COUNT} 次签到尝试均失败\n"
        f"🕐 执行时间：{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n"
        f"💡 建议：检查用户名密码是否正确，或手动更新 Cookie"
    )
    print(fail_msg)
    set_github_output("checkin_result", "failure")
    set_github_output("checkin_msg", fail_msg)
    return False


def cookie_checkin(cookie, user_agent):
    """使用 Cookie 执行签到，返回是否成功"""
    try:
        # 提取 flarum_remember
        remember_match = re.search(r'flarum_remember=([^;]+)', cookie)
        if not remember_match:
            print("Cookie 中未找到 flarum_remember")
            return False
        flarum_remember = remember_match.group(1)

        # 获取新 session
        headers = {
            "Cookie": f"flarum_remember={flarum_remember}",
            "User-Agent": user_agent,
            "Upgrade-Insecure-Requests": "1",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7"
        }
        response = requests.get("https://invites.fun", headers=headers, allow_redirects=False, timeout=30)

        # 提取 flarum_session
        flarum_session = None
        if 'flarum_session' in response.cookies:
            flarum_session = response.cookies['flarum_session']
        else:
            cookies_header = response.headers.get('Set-Cookie', '')
            session_match = re.search(r'flarum_session=([^;]+)', cookies_header)
            if session_match:
                flarum_session = session_match.group(1)
        if not flarum_session:
            print("获取 flarum_session 失败，Cookie 可能已失效")
            return False

        # 构建新 Cookie
        new_cookie = f"flarum_remember={flarum_remember}; flarum_session={flarum_session}"

        # 获取 CSRF Token 和 UserID
        res = requests.get("https://invites.fun", headers={"Cookie": new_cookie, "User-Agent": user_agent}, timeout=30)
        if res.status_code != 200:
            print(f"请求主页面失败，状态码：{res.status_code}，Cookie 可能已失效")
            return False

        # 提取 CSRF Token
        csrf_match = re.search(r'"csrfToken":"(.*?)"', res.text)
        if not csrf_match:
            print("提取 CSRF Token 失败，Cookie 可能已失效")
            return False
        csrf_token = csrf_match.group(1)

        # 提取 UserID
        userid_match = re.search(r'"userId":(\d+)', res.text)
        if not userid_match:
            print("提取 UserID 失败，Cookie 可能已失效")
            return False
        user_id = userid_match.group(1)

        # 执行签到
        checkin_headers = {
            'Accept': '*/*',
            'Content-Type': 'application/json; charset=UTF-8',
            'Origin': 'https://invites.fun',
            'Referer': 'https://invites.fun/',
            'X-CSRF-Token': csrf_token,
            'X-HTTP-Method-Override': 'PATCH',
            'Cookie': new_cookie,
            'User-Agent': user_agent
        }
        payload = {
            'data': {
                'type': 'users',
                'attributes': {'canCheckin': False, 'totalContinuousCheckIn': 2},
                'id': user_id
            }
        }
        checkin_response = requests.post(
            f'https://invites.fun/api/users/{user_id}',
            headers=checkin_headers,
            json=payload,
            timeout=30
        )

        if checkin_response.status_code != 200:
            print(f"签到请求失败，状态码：{checkin_response.status_code}，Cookie 可能已失效")
            return False

        # 解析签到结果
        checkin_data = checkin_response.json()
        total_days = checkin_data['data']['attributes']['totalContinuousCheckIn']
        money = checkin_data['data']['attributes']['money']
        msg = (
            f"✅ 签到成功！\n"
            f"📅 连续签到：{total_days} 天\n"
            f"💊 剩余药丸：{money} 个\n"
            f"🕐 签到时间：{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n"
            f"🍪 Cookie 状态：正常"
        )
        print(msg)
        set_github_output("checkin_result", "success")
        set_github_output("checkin_msg", msg)
        return True

    except Exception as e:
        print(f"Cookie 签到异常：{str(e)}")
        return False


def login_with_credentials(username, password, user_agent):
    """使用用户名密码登录，返回登录结果（包含新 Cookie）"""
    try:
        # 第一步：获取初始 session 和 CSRF Token
        headers_get = {
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7',
            'Accept-Language': 'zh-CN,zh;q=0.9',
            'User-Agent': user_agent,
            'Upgrade-Insecure-Requests': '1'
        }
        response_get = requests.get('https://invites.fun/', headers=headers_get, timeout=30)
        if response_get.status_code != 200:
            return {"success": False, "error": "获取初始页面失败"}

        # 提取初始 session 和 CSRF Token
        flarum_session = response_get.cookies.get('flarum_session')
        csrf_token = response_get.headers.get('x-csrf-token')
        if not flarum_session or not csrf_token:
            return {"success": False, "error": "提取初始 session 或 CSRF Token 失败"}

        # 第二步：执行登录
        login_headers = {
            'Accept': '*/*',
            'Content-Type': 'application/json; charset=UTF-8',
            'Origin': 'https://invites.fun',
            'Referer': 'https://invites.fun/',
            'x-csrf-token': csrf_token,
            'User-Agent': user_agent
        }
        login_data = {
            'identification': username,
            'password': password,
            'remember': True
        }
        login_response = requests.post(
            'https://invites.fun/login',
            headers=login_headers,
            json=login_data,
            cookies={'flarum_session': flarum_session},
            timeout=30
        )

        if login_response.status_code != 200:
            return {"success": False, "error": f"登录请求失败，状态码：{login_response.status_code}"}

        # 提取新 Cookie
        flarum_remember = login_response.cookies.get('flarum_remember')
        flarum_session_new = login_response.cookies.get('flarum_session')
        if not flarum_remember or not flarum_session_new:
            return {"success": False, "error": "登录后未获取到有效 Cookie"}

        # 构造标准 Cookie 字符串
        new_cookie = f"flarum_remember={flarum_remember}; flarum_session={flarum_session_new}"
        return {
            "success": True,
            "cookie": new_cookie,
            "error": ""
        }

    except Exception as e:
        return {"success": False, "error": f"登录异常：{str(e)}"}


def update_github_secret(secret_name, secret_value):
    """通过 GitHub API 更新仓库 Secret"""
    try:
        import base64
        from cryptography.hazmat.primitives import serialization, hashes
        from cryptography.hazmat.primitives.asymmetric import padding

        # 1. 获取仓库的公共密钥（用于加密 Secret）
        pubkey_url = f"https://api.github.com/repos/{GITHUB_REPO}/actions/secrets/public-key"
        headers = {
            "Authorization": f"token {GITHUB_TOKEN}",
            "Accept": "application/vnd.github.v3+json"
        }
        pubkey_response = requests.get(pubkey_url, headers=headers, timeout=30)
        if pubkey_response.status_code != 200:
            print(f"获取公共密钥失败：{pubkey_response.status_code} - {pubkey_response.text}")
            return False
        pubkey_data = pubkey_response.json()
        public_key = pubkey_data["key"]
        key_id = pubkey_data["key_id"]

        # 2. 加密 Secret 值
        public_key_obj = serialization.load_pem_public_key(
            public_key.encode("utf-8"),
            backend=None
        )
        encrypted_value = public_key_obj.encrypt(
            secret_value.encode("utf-8"),
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        encrypted_b64 = base64.b64encode(encrypted_value).decode("utf-8")

        # 3. 上传加密后的 Secret
        update_url = f"https://api.github.com/repos/{GITHUB_REPO}/actions/secrets/{secret_name}"
        update_data = {
            "encrypted_value": encrypted_b64,
            "key_id": key_id
        }
        update_response = requests.put(
            update_url,
            headers=headers,
            json=update_data,
            timeout=30
        )
        if update_response.status_code in [201, 204]:
            return True
        else:
            print(f"更新 Secret 失败：{update_response.status_code} - {update_response.text}")
            return False

    except Exception as e:
        print(f"更新 Secret 异常：{str(e)}")
        return False


if __name__ == "__main__":
    success = main()
    # 可选：根据结果设置退出码（非必需，因已通过 outputs 控制）
    exit(0 if success else 1)
