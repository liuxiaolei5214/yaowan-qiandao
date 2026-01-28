import requests
import re
import os
from datetime import datetime

# 配置（需替换为新版签到接口，当前是原接口，需抓包更新）
BASE_URL = "https://invites.fun"
CHECKIN_API = "/api/extensions/flarum-ext-money/checkin"  # 需抓包替换为新版接口
HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Referer": BASE_URL,
    "Accept": "application/json, text/plain, */*",
    "Accept-Language": "zh-CN,zh;q=0.9,en;q=0.8",
    "X-CSRF-Token": "",  # 新增：部分接口需要CSRF Token
}

def set_github_output(name, value):
    """替换弃用的::set-output，使用官方推荐的环境文件方式"""
    with open(os.environ['GITHUB_OUTPUT'], 'a') as f:
        f.write(f"{name}={value}\n")

def extract_cookie_value(cookie_str, key):
    pattern = re.compile(rf"{key}=([^;]+)")
    match = pattern.search(cookie_str)
    return match.group(1) if match else None

def refresh_session(flarum_remember):
    session = requests.Session()
    session.headers.update(HEADERS)
    session.cookies.set("flarum_remember", flarum_remember, domain="invites.fun", path="/")
    try:
        response = session.get(BASE_URL)
        response.raise_for_status()
        # 提取CSRF Token（适配部分接口要求）
        csrf_token = re.search(r'content="([^"]+)" name="csrf-token"', response.text)
        if csrf_token:
            session.headers["X-CSRF-Token"] = csrf_token.group(1)
        return session, session.cookies.get("flarum_session")
    except Exception as e:
        print(f"刷新Session失败：{str(e)}")
        return session, None

def login(username, password):
    session = requests.Session()
    session.headers.update(HEADERS)
    try:
        resp = session.get(f"{BASE_URL}/login")
        csrf_token = re.search(r'name="csrfToken" value="([^"]+)"', resp.text).group(1)
        login_data = {
            "csrfToken": csrf_token,
            "identification": username,
            "password": password,
            "remember": "on"
        }
        login_resp = session.post(f"{BASE_URL}/login", data=login_data, allow_redirects=True)
        if "flarum_remember" in session.cookies and "flarum_session" in session.cookies:
            print("登录成功")
            return session, session.cookies.get("flarum_remember"), session.cookies.get("flarum_session")
        else:
            print("登录失败：无有效Cookie")
            return None, None, None
    except Exception as e:
        print(f"登录异常：{str(e)}")
        return None, None, None

def checkin(session):
    try:
        user_id = 304  # 固定兜底值（已验证有效）
        print(f"使用UserID：{user_id}")

        # 调用签到接口（需替换为抓包到的新版接口）
        checkin_resp = session.post(
            f"{BASE_URL}{CHECKIN_API}",
            json={"userId": user_id}
        )
        checkin_resp.raise_for_status()  # 检测接口状态码
        checkin_data = checkin_resp.json()

        # 签到成功逻辑
        success_msg = checkin_data.get("message", "签到成功")
        consecutive_days = checkin_data.get("days", 0)
        remaining_coins = checkin_data.get("money", 0)
        beijing_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        
        print("✅ 签到成功！")
        print(f"📅 连续签到：{consecutive_days}天")
        print(f"💊 剩余药丸：{remaining_coins}个")
        set_github_output("checkin_result", "success")
        set_github_output(
            "checkin_msg",
            f"连续签到：{consecutive_days}天，剩余药丸：{remaining_coins}个，签到时间：{beijing_time}（UserID：{user_id}）"
        )
        return True, success_msg

    except Exception as e:
        # 签到失败逻辑（输出具体错误）
        error_msg = f"接口返回错误：{str(e)}（UserID：{user_id}）"
        print(f"❌ 签到失败：{error_msg}")
        set_github_output("checkin_result", "failure")
        set_github_output("checkin_msg", error_msg)
        return False, error_msg

def main():
    invites_cookie = os.getenv("INVITES_COOKIE", "")
    invites_username = os.getenv("INVITES_USERNAME", "")
    invites_password = os.getenv("INVITES_PASSWORD", "")
    
    session = requests.Session()
    session.headers.update(HEADERS)
    flarum_remember = None
    flarum_session = None

    # 优先用Cookie登录
    if invites_cookie:
        flarum_remember = extract_cookie_value(invites_cookie, "flarum_remember")
        if flarum_remember:
            print("提取flarum_remember成功")
            session, flarum_session = refresh_session(flarum_remember)
            if flarum_session:
                print("获取flarum_session成功")
            else:
                print("Cookie失效，尝试账号密码登录")

    # Cookie失效则用账号密码
    if not flarum_session and invites_username and invites_password:
        session, flarum_remember, flarum_session = login(invites_username, invites_password)
        if not flarum_session:
            print("登录失败，无法签到")
            set_github_output("checkin_result", "failure")
            set_github_output("checkin_msg", "Cookie失效且账号密码登录失败")
            return

    # 执行签到
    if flarum_session:
        session.cookies.set("flarum_session", flarum_session, domain="invites.fun", path="/")
        checkin(session)
    else:
        print("无有效Cookie，无法签到")
        set_github_output("checkin_result", "failure")
        set_github_output("checkin_msg", "无有效Cookie")

if __name__ == "__main__":
    print("第1次签到尝试")
    main()
