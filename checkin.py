import requests
import re
import os
from datetime import datetime
from datetime import timezone

# 配置（已适配新版接口，无需修改）
BASE_URL = "https://invites.fun"
USER_ID = 304  # 你的固定UserID
HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/144.0.0.0 Safari/537.36",
    "Referer": BASE_URL,
    "Accept": "application/json, text/plain, */*",
    "Accept-Language": "zh-CN,zh;q=0.9,en;q=0.8",
    "Content-Type": "application/json; charset=UTF-8",
    "X-Http-Method-Override": "PATCH",  # 新版接口核心请求头
}

def set_github_output(name, value):
    """GitHub Actions 官方推荐的输出方式（替代弃用的::set-output）"""
    if "GITHUB_OUTPUT" in os.environ:
        with open(os.environ["GITHUB_OUTPUT"], "a", encoding="utf-8") as f:
            f.write(f"{name}={value}\n")
    else:
        print(f"[DEBUG] {name}={value}")  # 本地调试用

def extract_cookie_value(cookie_str, key):
    """从Cookie字符串中提取指定键的值"""
    pattern = re.compile(rf"{key}=([^;]+)")
    match = pattern.search(cookie_str)
    return match.group(1) if match else None

def get_latest_csrf_token(session):
    """动态获取最新CSRF Token（优先响应头，兜底HTML）"""
    try:
        resp = session.get(BASE_URL, headers=HEADERS)
        resp.raise_for_status()
        # 方式1：从响应头获取（Flarum 优先推荐）
        csrf_token = resp.headers.get("X-Csrf-Token")
        if csrf_token:
            return csrf_token
        # 方式2：从HTML元标签提取（兜底）
        csrf_token = re.search(r'<meta name="csrf-token" content="([^"]+)">', resp.text)
        if csrf_token:
            return csrf_token.group(1)
        # 方式3：从JS变量提取（终极兜底）
        csrf_token = re.search(r'X-Csrf-Token": "([^"]+)"', resp.text)
        return csrf_token.group(1) if csrf_token else None
    except Exception as e:
        print(f"获取CSRF Token失败：{str(e)}")
        return None

def refresh_session(flarum_remember):
    """用Cookie刷新会话并获取CSRF Token"""
    session = requests.Session()
    # 设置Cookie
    session.cookies.set("flarum_remember", flarum_remember, domain="invites.fun", path="/")
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
        # 1. 获取登录页CSRF Token
        login_page_resp = session.get(f"{BASE_URL}/login", headers=HEADERS)
        login_page_resp.raise_for_status()
        csrf_token = re.search(r'name="csrfToken" value="([^"]+)"', login_page_resp.text)
        if not csrf_token:
            print("登录失败：未找到登录页CSRF Token")
            return None, None, None
        login_csrf = csrf_token.group(1)

        # 2. 发送登录请求
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

        # 3. 校验登录结果
        flarum_remember = session.cookies.get("flarum_remember")
        flarum_session = session.cookies.get("flarum_session")
        if flarum_remember and flarum_session:
            print("登录成功，获取到有效Cookie")
            # 登录后更新CSRF Token
            csrf_token = get_latest_csrf_token(session)
            if csrf_token:
                session.headers["X-Csrf-Token"] = csrf_token
            return session, flarum_remember, flarum_session
        else:
            print("登录失败：未获取到flarum_remember或flarum_session")
            return None, None, None
    except Exception as e:
        print(f"登录异常：{str(e)}")
        return None, None, None

def checkin(session):
    """执行签到（调用新版 /api/users/304 接口）"""
    # 初始化关键变量，避免未定义
    resp_text = ""
    checkin_resp = None
    try:
        # 1. 构造签到请求体（与Cloudflare一致）
        checkin_data = {
            "data": {
                "attributes": {
                    "action": "checkin",
                    "userId": USER_ID
                }
            }
        }

        # 2. 发送签到请求
        checkin_resp = session.post(
            f"{BASE_URL}/api/users/{USER_ID}",
            json=checkin_data,
            headers=session.headers
        )
        checkin_resp.raise_for_status()  # 非200状态码抛出异常
        resp_text = checkin_resp.text
        resp_json = checkin_resp.json()

        # 3. 提取核心签到信息（与Cloudflare通知格式对齐）
        attributes = resp_json.get("data", {}).get("attributes", {})
        continuous_days = attributes.get("totalContinuousCheckIn", 0)
        remaining_money = attributes.get("money", 0)
        last_checkin_time = attributes.get("lastCheckinTime", "")
        
        # 格式化签到时间（北京时间）
        if last_checkin_time:
            # 转换为北京时间（原时间是UTC）
            utc_time = datetime.strptime(last_checkin_time, "%Y-%m-%d %H:%M:%S")
            beijing_time = utc_time.replace(tzinfo=timezone.utc).astimezone(tz=None)
            checkin_time = beijing_time.strftime("%Y-%m-%d %H:%M:%S")
        else:
            checkin_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        # 4. 输出结果并设置GitHub Output
        success_msg = f"✅ 签到成功！\n📅 连续签到：{continuous_days}天\n💰 剩余药丸：{remaining_money}个\n⏰ 签到时间：{checkin_time}"
        print(success_msg)
        set_github_output("checkin_result", "success")
        set_github_output("checkin_msg", success_msg)
        return True, success_msg

    except requests.exceptions.HTTPError as e:
        # 处理接口HTTP错误（确保变量已定义）
        if checkin_resp:
            error_msg = f"❌ 签到失败：接口返回{checkin_resp.status_code}错误\n响应内容：{resp_text[:200]}"
        else:
            error_msg = f"❌ 签到失败：HTTP请求错误\n错误详情：{str(e)}"
    except Exception as e:
        # 处理其他异常
        error_msg = f"❌ 签到异常：{str(e)}"
        # 补充响应信息（如果有）
        if checkin_resp:
            error_msg += f"\n接口状态码：{checkin_resp.status_code}"
        if resp_text:
            error_msg += f"\n响应内容：{resp_text[:200]}"
    
    print(error_msg)
    set_github_output("checkin_result", "failure")
    set_github_output("checkin_msg", error_msg)
    return False, error_msg

def main():
    """主逻辑：Cookie优先 → 登录兜底 → 执行签到"""
    # 从环境变量读取配置（与原脚本一致）
    invites_cookie = os.getenv("INVITES_COOKIE", "")
    invites_username = os.getenv("INVITES_USERNAME", "")
    invites_password = os.getenv("INVITES_PASSWORD", "")

    session = None
    cookie_valid = False

    # 步骤1：优先使用Cookie登录
    if invites_cookie:
        flarum_remember = extract_cookie_value(invites_cookie, "flarum_remember")
        if flarum_remember:
            print("=== 尝试使用Cookie登录 ===")
            session, cookie_valid = refresh_session(flarum_remember)
        else:
            print("Cookie格式错误：未提取到flarum_remember")

    # 步骤2：Cookie失效则用账号密码登录
    if not cookie_valid and invites_username and invites_password:
        print("=== Cookie失效，尝试账号密码登录 ===")
        session, _, _ = login(invites_username, invites_password)
        # 账号密码登录成功后，更新cookie_valid为True（原逻辑缺失）
        if session:
            cookie_valid = True
        else:
            error_msg = "❌ 登录失败，无法执行签到"
            set_github_output("checkin_result", "failure")
            set_github_output("checkin_msg", error_msg)
            return

    # 步骤3：执行签到（修复逻辑：只要session存在就执行，不管cookie_valid）
    if session:
        print("=== 开始执行签到 ===")
        checkin(session)
    else:
        error_msg = "❌ 无有效会话，无法执行签到"
        set_github_output("checkin_result", "failure")
        set_github_output("checkin_msg", error_msg)
        print(error_msg)

if __name__ == "__main__":
    print("=== 药丸论坛签到脚本（GitHub版·新版接口）===")
    main()
