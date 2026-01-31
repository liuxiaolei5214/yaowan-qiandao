import requests
import re
import os
from datetime import datetime
from datetime import timezone

# 核心配置（严格匹配抓包结果）
BASE_URL = "https://invites.fun"
USER_ID = 304  # 抓包确认的真实签到ID（必须是304）
HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/144.0.0.0 Safari/537.36 Edg/144.0.0.0",
    "Referer": BASE_URL,
    "Accept": "application/json, text/plain, */*",
    "Accept-Language": "zh-CN,zh;q=0.9,en;q=0.8",
    "Content-Type": "application/json; charset=UTF-8",
    "X-Http-Method-Override": "PATCH",  # 恢复抓包中的伪PATCH头
    "Sec-Ch-Ua": '"Not/A)Brand";v="8", "Chromium";v="144", "Microsoft Edge";v="144"',
    "Sec-Ch-Ua-Mobile": "?0",
    "Sec-Ch-Ua-Platform": '"Windows"',
    "Sec-Fetch-Mode": "cors",
    "Sec-Fetch-Site": "same-origin",
    "Origin": BASE_URL
}

def set_github_output(name, value):
    """GitHub Actions 输出（修复格式错误，转义特殊字符）"""
    value = value.replace("\n", "\\n").replace("'", "").replace('"', '')
    if "GITHUB_OUTPUT" in os.environ:
        with open(os.environ["GITHUB_OUTPUT"], "a", encoding="utf-8") as f:
            f.write(f"{name}={value}\n")
    else:
        print(f"[DEBUG] {name}={value}")  # 本地调试用

def extract_cookie_value(cookie_str, key):
    """从Cookie字符串提取指定键的值"""
    pattern = re.compile(rf"{key}=([^;]+)")
    match = pattern.search(cookie_str)
    return match.group(1) if match else None

def get_latest_csrf_token(session):
    """动态获取CSRF Token（多方式兜底）"""
    try:
        resp = session.get(BASE_URL, headers=HEADERS)
        resp.raise_for_status()
        # 方式1：响应头（优先）
        csrf_token = resp.headers.get("X-Csrf-Token")
        if csrf_token:
            return csrf_token
        # 方式2：HTML元标签
        csrf_token = re.search(r'<meta name="csrf-token" content="([^"]+)">', resp.text)
        if csrf_token:
            return csrf_token.group(1)
        # 方式3：JS变量
        csrf_token = re.search(r'X-Csrf-Token": "([^"]+)"', resp.text)
        return csrf_token.group(1) if csrf_token else None
    except Exception as e:
        print(f"获取CSRF Token失败：{str(e)}")
        return None

def refresh_session(cookie_str):
    """用完整Cookie刷新会话（同时包含flarum_remember和flarum_session）"""
    session = requests.Session()
    # 直接设置完整Cookie，避免仅提取单个字段丢失登录态
    session.headers["Cookie"] = cookie_str
    # 获取最新CSRF Token
    csrf_token = get_latest_csrf_token(session)
    if csrf_token:
        session.headers["X-Csrf-Token"] = csrf_token
        print(f"刷新Session成功，CSRF Token：{csrf_token[:10]}***")
        return session, True
    else:
        print("刷新Session失败：未获取到CSRF Token")
        return session, False

def login(username, password):
    """账号密码登录（动态CSRF Token）"""
    session = requests.Session()
    try:
        # 获取登录页CSRF Token
        login_page_resp = session.get(f"{BASE_URL}/login", headers=HEADERS)
        login_page_resp.raise_for_status()
        csrf_token = re.search(r'name="csrfToken" value="([^"]+)"', login_page_resp.text)
        if not csrf_token:
            print("登录失败：未找到登录页CSRF Token")
            return None, None, None
        login_csrf = csrf_token.group(1)

        # 发送登录请求
        login_data = {
            "csrfToken": login_csrf,
            "identification": username,
            "password": password,
            "remember": "on"
        }
        login_resp = session.post(
            f"{BASE_URL}/login",
            data=login_data,
            headers={"Content-Type": "application/x-www-form-urlencoded"},
            allow_redirects=False
        )
        login_resp.raise_for_status()

        # 提取完整Cookie（包含flarum_remember + flarum_session）
        cookies = session.cookies.get_dict()
        flarum_remember = cookies.get("flarum_remember")
        flarum_session = cookies.get("flarum_session")
        if flarum_remember and flarum_session:
            full_cookie = f"flarum_remember={flarum_remember}; flarum_session={flarum_session}"
            print("登录成功，获取到完整Cookie")
            # 登录后更新CSRF Token
            csrf_token = get_latest_csrf_token(session)
            if csrf_token:
                session.headers["X-Csrf-Token"] = csrf_token
            session.headers["Cookie"] = full_cookie
            return session, flarum_remember, flarum_session
        else:
            print("登录失败：未获取到flarum_remember或flarum_session")
            return None, None, None
    except Exception as e:
        print(f"登录异常：{str(e)}")
        return None, None, None

def checkin(session):
    """执行签到（严格匹配网页端抓包请求）"""
    resp_text = ""
    checkin_resp = None
    try:
        # 1. 获取签到前的基准数据（用于对比）
        pre_resp = session.get(f"{BASE_URL}/api/users/{USER_ID}", headers=session.headers)
        pre_resp.raise_for_status()
        pre_data = pre_resp.json()
        pre_continuous_days = pre_data.get("data", {}).get("attributes", {}).get("totalContinuousCheckIn", 0)
        pre_money = pre_data.get("data", {}).get("attributes", {}).get("money", 0)

        # 2. 构造与抓包完全一致的签到请求体
        checkin_data = {
            "data": {
                "attributes": {
                    "action": "checkin",
                    "userId": USER_ID
                }
            }
        }

        # 3. 发送与抓包一致的POST请求（带伪PATCH头）
        checkin_headers = session.headers.copy()
        checkin_headers["X-Http-Method-Override"] = "PATCH"  # 强制保留抓包中的伪PATCH头
        checkin_resp = session.post(  # 改回POST（关键！）
            f"{BASE_URL}/api/users/{USER_ID}",
            json=checkin_data,
            headers=checkin_headers
        )
        checkin_resp.raise_for_status()
        resp_text = checkin_resp.text
        resp_json = checkin_resp.json()

        # 4. 提取签到后数据
        attributes = resp_json.get("data", {}).get("attributes", {})
        post_continuous_days = attributes.get("totalContinuousCheckIn", 0)
        post_money = attributes.get("money", 0)
        last_checkin_time = attributes.get("lastCheckinTime", "")

        # 5. 格式化时间并校验是否为当天
        checkin_date = ""
        today = datetime.now().strftime("%Y-%m-%d")
        if last_checkin_time:
            utc_time = datetime.strptime(last_checkin_time, "%Y-%m-%d %H:%M:%S")
            beijing_time = utc_time.replace(tzinfo=timezone.utc).astimezone(tz=None)
            checkin_time = beijing_time.strftime("%Y-%m-%d %H:%M:%S")
            checkin_date = beijing_time.strftime("%Y-%m-%d")
        else:
            checkin_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            checkin_date = today

        # 6. 多维度判定真实签到状态
        is_real_success = checkin_date == today
        success_reasons = []
        if is_real_success:
            success_reasons.append("签到日期为当天")
            if post_continuous_days > pre_continuous_days:
                success_reasons.append(f"连续天数从{pre_continuous_days}→{post_continuous_days}（已增加）")
            if post_money > pre_money:
                success_reasons.append(f"药丸数量从{pre_money}→{post_money}（奖励到账）")
            success_msg = f"✅ 真实签到成功！\n📅 连续签到：{post_continuous_days}天\n💰 剩余药丸：{post_money}个\n⏰ 签到时间：{checkin_time}\n🔍 校验依据：{'; '.join(success_reasons)}"
            set_github_output("checkin_result", "success")
            set_github_output("checkin_msg", success_msg)
            print(success_msg)
            return True, success_msg
        else:
            error_msg = f"❌ 伪成功！接口返回200但未实际签到\n📅 签到日期：{checkin_date}（当天应为{today}）\n🔍 校验依据：签到日期非当天"
            set_github_output("checkin_result", "failure")
            set_github_output("checkin_msg", error_msg)
            print(error_msg)
            return False, error_msg

    except requests.exceptions.HTTPError as e:
        error_msg = f"❌ 签到失败：接口返回{checkin_resp.status_code if checkin_resp else '未知'}错误\n响应内容：{resp_text[:200]}"
    except Exception as e:
        error_msg = f"❌ 签到异常：{str(e)}"
        if checkin_resp:
            error_msg += f"\n接口状态码：{checkin_resp.status_code}"
        if resp_text:
            error_msg += f"\n响应内容：{resp_text[:200]}"
    
    print(error_msg)
    set_github_output("checkin_result", "failure")
    set_github_output("checkin_msg", error_msg)
    return False, error_msg

def main():
    """主逻辑：Cookie优先 → 账号密码兜底 → 执行签到"""
    # 读取环境变量
    invites_cookie = os.getenv("INVITES_COOKIE", "")
    invites_username = os.getenv("INVITES_USERNAME", "")
    invites_password = os.getenv("INVITES_PASSWORD", "")

    session = None
    cookie_valid = False

    # 步骤1：Cookie登录（使用完整Cookie）
    if invites_cookie:
        print("=== 尝试使用Cookie登录 ===")
        session, cookie_valid = refresh_session(invites_cookie)
    else:
        print("未配置INVITES_COOKIE环境变量")

    # 步骤2：Cookie失效则账号密码登录
    if not cookie_valid and invites_username and invites_password:
        print("=== Cookie失效，尝试账号密码登录 ===")
        session, _, _ = login(invites_username, invites_password)
        if session:
            cookie_valid = True
        else:
            error_msg = "❌ 登录失败，无法执行签到"
            set_github_output("checkin_result", "failure")
            set_github_output("checkin_msg", error_msg)
            print(error_msg)
            return

    # 步骤3：执行签到
    if session:
        print("=== 开始执行签到 ===")
        checkin(session)
    else:
        error_msg = "❌ 无有效会话，无法执行签到"
        set_github_output("checkin_result", "failure")
        set_github_output("checkin_msg", error_msg)
        print(error_msg)

if __name__ == "__main__":
    print("=== 药丸论坛签到脚本（抓包匹配终极版）===")
    main()
