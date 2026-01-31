# -*- coding: utf-8 -*-
"""药丸论坛自动签到脚本（最终稳定版）"""
import requests
import re
import os
from datetime import datetime
from datetime import timezone

# 核心配置
BASE_URL = "https://invites.fun"
USER_ID = 304  # 抓包确认的真实签到ID
HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/144.0.0.0 Safari/537.36 Edg/144.0.0.0",
    "Referer": BASE_URL,
    "Accept": "application/json, text/plain, */*",
    "Accept-Language": "zh-CN,zh;q=0.9,en;q=0.8",
    "Content-Type": "application/json; charset=UTF-8",
    "X-Http-Method-Override": "PATCH",
    "Sec-Ch-Ua": '"Not/A)Brand";v="8", "Chromium";v="144", "Microsoft Edge";v="144"',
    "Sec-Ch-Ua-Mobile": "?0",
    "Sec-Ch-Ua-Platform": '"Windows"',
    "Sec-Fetch-Mode": "cors",
    "Sec-Fetch-Site": "same-origin",
    "Origin": BASE_URL
}

def set_github_output(name, value):
    """GitHub Actions输出（转义特殊字符）"""
    safe_value = (
        value.replace("\n", "\\n")
        .replace("'", "")
        .replace('"', '')
        .replace("`", "")
        .replace("$", "\\$")
    )
    if "GITHUB_OUTPUT" in os.environ:
        with open(os.environ["GITHUB_OUTPUT"], "a", encoding="utf-8") as f:
            f.write(f"{name}={safe_value}\n")
    else:
        print(f"[DEBUG] {name}={safe_value}")

def extract_cookie_value(cookie_str, key):
    """从Cookie提取指定值"""
    if not cookie_str:
        return None
    pattern = re.compile(rf"{key}=([^;]+)")
    match = pattern.search(cookie_str)
    return match.group(1) if match else None

def get_latest_csrf_token(session):
    """获取CSRF Token"""
    try:
        resp = session.get(BASE_URL, headers=HEADERS, timeout=10)
        resp.raise_for_status()
        csrf_token = resp.headers.get("X-Csrf-Token") or re.search(r'<meta name="csrf-token" content="([^"]+)">', resp.text)
        return csrf_token.group(1) if isinstance(csrf_token, re.Match) else csrf_token
    except Exception as e:
        print(f"获取CSRF Token失败：{str(e)}")
        return None

def refresh_session(cookie_str):
    """刷新会话"""
    session = requests.Session()
    session.headers["Cookie"] = cookie_str
    csrf_token = get_latest_csrf_token(session)
    if csrf_token:
        session.headers["X-Csrf-Token"] = csrf_token
        print(f"刷新Session成功，CSRF Token：{csrf_token[:10]}***")
        return session, True
    return session, False

def login(username, password):
    """账号密码登录"""
    session = requests.Session()
    try:
        login_page_resp = session.get(f"{BASE_URL}/login", headers=HEADERS, timeout=10)
        login_page_resp.raise_for_status()
        csrf_token = re.search(r'name="csrfToken" value="([^"]+)"', login_page_resp.text)
        if not csrf_token:
            print("登录失败：未找到CSRF Token")
            return None, None, None

        login_data = {"csrfToken": csrf_token.group(1), "identification": username, "password": password, "remember": "on"}
        login_resp = session.post(f"{BASE_URL}/login", data=login_data, headers={"Content-Type": "application/x-www-form-urlencoded"}, allow_redirects=False, timeout=10)
        login_resp.raise_for_status()

        cookies = session.cookies.get_dict()
        flarum_remember = cookies.get("flarum_remember")
        flarum_session = cookies.get("flarum_session")
        if flarum_remember and flarum_session:
            full_cookie = f"flarum_remember={flarum_remember}; flarum_session={flarum_session}"
            print("登录成功，获取完整Cookie")
            csrf_token = get_latest_csrf_token(session)
            if csrf_token:
                session.headers["X-Csrf-Token"] = csrf_token
            session.headers["Cookie"] = full_cookie
            return session, flarum_remember, flarum_session
        print("登录失败：Cookie不完整")
        return None, None, None
    except Exception as e:
        print(f"登录异常：{str(e)}")
        return None, None, None

def checkin(session):
    """执行签到"""
    resp_text = ""
    checkin_resp = None
    try:
        # 获取签到前数据
        pre_resp = session.get(f"{BASE_URL}/api/users/{USER_ID}", headers=session.headers, timeout=10)
        pre_resp.raise_for_status()
        pre_data = pre_resp.json()
        pre_continuous = pre_data.get("data", {}).get("attributes", {}).get("totalContinuousCheckIn", 0)
        pre_money = pre_data.get("data", {}).get("attributes", {}).get("money", 0)

        # 发送签到请求
        checkin_data = {"data": {"attributes": {"action": "checkin", "userId": USER_ID}}}
        checkin_headers = session.headers.copy()
        checkin_headers["X-Http-Method-Override"] = "PATCH"
        checkin_resp = session.post(f"{BASE_URL}/api/users/{USER_ID}", json=checkin_data, headers=checkin_headers, timeout=10)
        checkin_resp.raise_for_status()
        resp_text = checkin_resp.text
        resp_json = checkin_resp.json()

        # 校验签到结果
        attributes = resp_json.get("data", {}).get("attributes", {})
        post_continuous = attributes.get("totalContinuousCheckIn", 0)
        post_money = attributes.get("money", 0)
        last_checkin = attributes.get("lastCheckinTime", "")
        
        today = datetime.now().strftime("%Y-%m-%d")
        checkin_date = datetime.strptime(last_checkin, "%Y-%m-%d %H:%M:%S").replace(tzinfo=timezone.utc).astimezone(tz=None).strftime("%Y-%m-%d") if last_checkin else today

        if checkin_date == today:
            success_msg = f"✅ 签到成功！\n连续天数：{post_continuous}天（+{post_continuous - pre_continuous}）\n药丸数量：{post_money}个（+{post_money - pre_money}）"
            set_github_output("checkin_result", "success")
            set_github_output("checkin_msg", success_msg)
            print(success_msg)
            return True
        else:
            error_msg = f"❌ 伪成功！签到日期：{checkin_date}（当天应为{today}）"
            set_github_output("checkin_result", "failure")
            set_github_output("checkin_msg", error_msg)
            print(error_msg)
            return False

    except requests.exceptions.HTTPError as e:
        if checkin_resp and checkin_resp.status_code in [400, 409, 422]:
            error_msg = f"ℹ️ 重复签到：当天已完成签到（状态码{checkin_resp.status_code}）"
            set_github_output("checkin_result", "success")
            set_github_output("checkin_msg", error_msg)
            print(error_msg)
            return True
        error_msg = f"❌ 签到失败：{checkin_resp.status_code if checkin_resp else '未知'}错误\n响应：{resp_text[:200]}"
    except Exception as e:
        error_msg = f"❌ 签到异常：{str(e)}\n响应：{resp_text[:200]}" if resp_text else f"❌ 签到异常：{str(e)}"
    
    set_github_output("checkin_result", "failure")
    set_github_output("checkin_msg", error_msg)
    print(error_msg)
    return False

def main():
    """主函数"""
    print("=== 药丸论坛签到脚本启动 ===")
    # 读取环境变量
    cookie = os.getenv("INVITES_COOKIE", "")
    username = os.getenv("INVITES_USERNAME", "")
    password = os.getenv("INVITES_PASSWORD", "")

    session = None
    cookie_valid = False

    # Cookie登录
    if cookie:
        print("=== 尝试Cookie登录 ===")
        session, cookie_valid = refresh_session(cookie)
    else:
        print("未配置Cookie，将尝试账号密码登录")

    # 账号密码兜底
    if not cookie_valid and username and password:
        print("=== 尝试账号密码登录 ===")
        session, _, _ = login(username, password)
        cookie_valid = session is not None

    # 执行签到
    if session and cookie_valid:
        print("=== 开始签到 ===")
        checkin(session)
    else:
        error_msg = "❌ 无有效会话，签到终止"
        set_github_output("checkin_result", "failure")
        set_github_output("checkin_msg", error_msg)
        print(error_msg)

if __name__ == "__main__":
    main()
