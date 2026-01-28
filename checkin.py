import os
import re
import json
import time
import requests
from datetime import datetime

def main():
    # 从环境变量获取 Cookie
    cookie = os.getenv('INVITES_COOKIE')
    if not cookie:
        print('错误：未配置 INVITES_COOKIE 环境变量')
        # 输出结果标识，供 Actions 判断
        print("::set-output name=checkin_result::failure")
        print("::set-output name=checkin_msg::未配置Cookie")
        return False

    # 配置
    USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36 Edg/142.0.0.0"
    RETRY_COUNT = 2
    RETRY_INTERVAL = 5  # 分钟

    for attempt in range(RETRY_COUNT):
        print(f"\n第 {attempt + 1} 次签到尝试")
        try:
            # 1. 提取 flarum_remember
            remember_match = re.search(r'flarum_remember=([^;]+)', cookie)
            if not remember_match:
                print("错误：Cookie 中未找到 flarum_remember")
                continue
            flarum_remember = remember_match.group(1)
            print("提取 flarum_remember 成功")

            # 2. 获取新的 session
            headers = {
                "Cookie": f"flarum_remember={flarum_remember}",
                "User-Agent": USER_AGENT,
                "Upgrade-Insecure-Requests": "1",
                "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7"
            }
            
            response = requests.get(
                "https://invites.fun",
                headers=headers,
                allow_redirects=False,
                timeout=30
            )
            
            # 提取 flarum_session
            flarum_session = None
            if 'flarum_session' in response.cookies:
                flarum_session = response.cookies['flarum_session']
            else:
                # 从响应头提取
                cookies_header = response.headers.get('Set-Cookie', '')
                session_match = re.search(r'flarum_session=([^;]+)', cookies_header)
                if session_match:
                    flarum_session = session_match.group(1)
            
            if not flarum_session:
                print("错误：获取 flarum_session 失败")
                continue
            print("获取 flarum_session 成功")

            # 3. 构建新的 cookie
            new_cookie = f"flarum_remember={flarum_remember}; flarum_session={flarum_session}"
            
            # 4. 获取 CSRF Token 和 UserID
            res = requests.get(
                "https://invites.fun",
                headers={"Cookie": new_cookie, "User-Agent": USER_AGENT},
                timeout=30
            )
            
            if res.status_code != 200:
                print(f"错误：请求主页面失败，状态码: {res.status_code}")
                continue
            
            # 提取 CSRF Token
            csrf_match = re.search(r'"csrfToken":"(.*?)"', res.text)
            if not csrf_match:
                print("错误：提取 CSRF Token 失败")
                continue
            csrf_token = csrf_match.group(1)
            print("提取 CSRF Token 成功")
            
            # 提取 UserID
            userid_match = re.search(r'"userId":(\d+)', res.text)
            if not userid_match:
                print("错误：提取 UserID 失败")
                continue
            user_id = userid_match.group(1)
            print(f"提取 UserID 成功: {user_id}")
            
            # 5. 执行签到
            checkin_headers = {
                'Accept': '*/*',
                'Content-Type': 'application/json; charset=UTF-8',
                'Origin': 'https://invites.fun',
                'Referer': 'https://invites.fun/',
                'X-CSRF-Token': csrf_token,
                'X-HTTP-Method-Override': 'PATCH',
                'Cookie': new_cookie,
                'User-Agent': USER_AGENT
            }
            
            payload = {
                'data': {
                    'type': 'users',
                    'attributes': {
                        'canCheckin': False,
                        'totalContinuousCheckIn': 2,
                    },
                    'id': user_id,
                }
            }
            
            checkin_response = requests.post(
                f'https://invites.fun/api/users/{user_id}',
                headers=checkin_headers,
                json=payload,
                timeout=30
            )
            
            if checkin_response.status_code != 200:
                print(f"错误：签到请求失败，状态码: {checkin_response.status_code}")
                continue
            
            # 解析签到结果
            checkin_data = checkin_response.json()
            total_days = checkin_data['data']['attributes']['totalContinuousCheckIn']
            money = checkin_data['data']['attributes']['money']
            
            msg = f"✅ 签到成功！\n📅 连续签到：{total_days} 天\n💊 剩余药丸：{money} 个\n🕐 签到时间：{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"
            print(msg)
            # 输出成功结果
            print("::set-output name=checkin_result::success")
            print(f"::set-output name=checkin_msg::{msg}")
            return True
            
        except Exception as e:
            print(f"错误：签到过程中发生异常 - {str(e)}")
            if attempt < RETRY_COUNT - 1:
                print(f"等待 {RETRY_INTERVAL} 分钟后重试...")
                time.sleep(RETRY_INTERVAL * 60)
    
    fail_msg = f"❌ 所有 {RETRY_COUNT} 次签到尝试均失败\n🕐 时间：{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"
    print(fail_msg)
    # 输出失败结果
    print("::set-output name=checkin_result::failure")
    print(f"::set-output name=checkin_msg::{fail_msg}")
    return False

if __name__ == "__main__":
    success = main()
    exit(0 if success else 1)
