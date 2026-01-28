import requests
import re
import os
from datetime import datetime

# 配置论坛地址
BASE_URL = "https://invites.fun"
HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Referer": BASE_URL,
    "Accept": "application/json, text/plain, */*",
    "Accept-Language": "zh-CN,zh;q=0.9,en;q=0.8",
}

def get_github_output(name, value):
    """输出 GitHub Actions 步骤变量（关键：让 YAML 能读取到）"""
    print(f"::set-output name={name}::{value}")

def extract_cookie_value(cookie_str, key):
    """从 Cookie 字符串中提取指定键的值"""
    pattern = re.compile(rf"{key}=([^;]+)")
    match = pattern.search(cookie_str)
    return match.group(1) if match else None

def refresh_session(flarum_remember):
    """用 flarum_remember 刷新 flarum_session"""
    session = requests.Session()
    session.headers.update(HEADERS)
    session.cookies.set("flarum_remember", flarum_remember, domain="invites.fun", path="/")
    
    try:
        response = session.get(BASE_URL)
        response.raise_for_status()
        # 提取刷新后的 flarum_session
        flarum_session = session.cookies.get("flarum_session")
        return session, flarum_session
    except Exception as e:
        print(f"刷新 Session 失败：{str(e)}")
        return session, None

def login(username, password):
    """账号密码登录，获取 Cookie"""
    session = requests.Session()
    session.headers.update(HEADERS)
    
    try:
        # 获取 CSRF Token
        resp = session.get(f"{BASE_URL}/login")
        csrf_token = re.search(r'name="csrfToken" value="([^"]+)"', resp.text).group(1)
        
        # 登录请求
        login_data = {
            "csrfToken": csrf_token,
            "identification": username,
            "password": password,
            "remember": "on"
        }
        login_resp = session.post(f"{BASE_URL}/login", data=login_data, allow_redirects=True)
        
        if "flarum_remember" in session.cookies and "flarum_session" in session.cookies:
            flarum_remember = session.cookies.get("flarum_remember")
            flarum_session = session.cookies.get("flarum_session")
            print(f"登录成功，获取到 Cookie")
            return session, flarum_remember, flarum_session
        else:
            print("登录失败：未获取到有效 Cookie")
            return None, None, None
    except Exception as e:
        print(f"登录异常：{str(e)}")
        return None, None, None

def checkin(session):
    """执行签到操作"""
    try:
        # 获取用户信息（提取 UserID）
        user_resp = session.get(f"{BASE_URL}/api/users/me")
        user_data = user_resp.json()
        user_id = user_data.get("data", {}).get("id")
        print(f"提取 UserID 成功: {user_id}")
        
        # 执行签到
        checkin_resp = session.post(
            f"{BASE_URL}/api/extensions/flarum-ext-money/checkin",
            json={"userId": user_id}
        )
        checkin_data = checkin_resp.json()
        
        if checkin_resp.status_code == 200:
            # 解析签到结果
            success_msg = checkin_data.get("message", "签到成功！")
            consecutive_days = checkin_data.get("days", 0)  # 连续签到天数
            remaining_coins = checkin_data.get("money", 0)  # 剩余药丸
            beijing_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            
            # 打印日志（和你之前的日志格式一致）
            print("✅ 签到成功！")
            print(f"🔴 连续签到：{consecutive_days} 天")
            print(f"🟡 剩余药丸：{remaining_coins} 个")
            print(f"⌚ 签到时间：{beijing_time}")
            
            # 关键：输出 GitHub Actions 变量（让 YAML 读取）
            get_github_output("checkin_result", "success")
            get_github_output(
                "checkin_msg", 
                f"连续签到：{consecutive_days} 天，剩余药丸：{remaining_coins} 个，签到时间：{beijing_time}"
            )
            return True, success_msg
        else:
            error_msg = checkin_data.get("message", "签到失败")
            print(f"❌ 签到失败：{error_msg}")
            get_github_output("checkin_result", "failure")
            get_github_output("checkin_msg", error_msg)
            return False, error_msg
    except Exception as e:
        error_msg = f"签到异常：{str(e)}"
        print(f"❌ {error_msg}")
        get_github_output("checkin_result", "failure")
        get_github_output("checkin_msg", error_msg)
        return False, error_msg

def main():
    """主流程：Cookie 签到 → 失效则账号密码登录 → 执行签到"""
    # 从环境变量读取配置
    invites_cookie = os.getenv("INVITES_COOKIE", "")
    invites_username = os.getenv("INVITES_USERNAME", "")
    invites_password = os.getenv("INVITES_PASSWORD", "")
    
    session = requests.Session()
    session.headers.update(HEADERS)
    flarum_remember = None
    flarum_session = None
    
    # 步骤1：提取 Cookie 中的 flarum_remember
    if invites_cookie:
        flarum_remember = extract_cookie_value(invites_cookie, "flarum_remember")
        if flarum_remember:
            print("提取 flarum_remember 成功")
            # 步骤2：刷新 flarum_session
            session, flarum_session = refresh_session(flarum_remember)
            if flarum_session:
                print("获取 flarum_session 成功")
            else:
                print("刷新 Session 失败，尝试账号密码登录")
    
    # 步骤3：若 Cookie 失效，用账号密码登录
    if not flarum_session and invites_username and invites_password:
        session, flarum_remember, flarum_session = login(invites_username, invites_password)
        if not flarum_session:
            print("账号密码登录也失败，签到终止")
            get_github_output("checkin_result", "failure")
            get_github_output("checkin_msg", "Cookie 失效且账号密码登录失败，请检查配置")
            return
    
    # 步骤4：执行签到
    if flarum_session:
        session.cookies.set("flarum_session", flarum_session, domain="invites.fun", path="/")
        checkin(session)
    else:
        print("无有效 Cookie，无法执行签到")
        get_github_output("checkin_result", "failure")
        get_github_output("checkin_msg", "无有效 Cookie，请配置 INVITES_COOKIE 或账号密码")

if __name__ == "__main__":
    print("第 1 次签到尝试")
    main()
