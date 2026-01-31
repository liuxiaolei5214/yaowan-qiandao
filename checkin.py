name: 药丸论坛自动签到

on:
  # 定时运行（每天凌晨0点30分，时区UTC+8）
  schedule:
    - cron: '30 16 * * *'  # UTC时间16:30 = 北京时间00:30
  # 手动触发
  workflow_dispatch:

jobs:
  checkin:
    runs-on: ubuntu-latest
    steps:
      - name: 检出代码
        uses: actions/checkout@v4

      - name: 设置Python环境
        uses: actions/setup-python@v5
        with:
          python-version: '3.10'

      - name: 安装依赖
        run: |
          python -m pip install --upgrade pip
          pip install requests
          sudo apt-get update && sudo apt-get install -y jq  # 安装jq用于构造JSON

      - name: 记录触发时间
        run: |
          echo "触发时间：$(date '+%Y-%m-%d %H:%M:%S')"

      - name: 执行签到脚本
        id: checkin_step
        env:
          INVITES_COOKIE: ${{ secrets.INVITES_COOKIE }}
          INVITES_USERNAME: ${{ secrets.INVITES_USERNAME }}
          INVITES_PASSWORD: ${{ secrets.INVITES_PASSWORD }}
        run: |
          python checkin.py

      - name: 发送企业微信通知
        env:
          WECHAT_WEBHOOK: ${{ secrets.WECHAT_WEBHOOK }}
          CHECKIN_RESULT: ${{ steps.checkin_step.outputs.checkin_result }}
          CHECKIN_MSG: ${{ steps.checkin_step.outputs.checkin_msg }}
        run: |
          # 构造通知内容
          if [ "$CHECKIN_RESULT" = "success" ]; then
              TITLE="✅ 药丸论坛签到成功"
          else
              TITLE="❌ 药丸论坛签到失败"
          fi
          
          # 构造Markdown内容（转义特殊字符）
          CONTENT="### $TITLE\n$(echo "$CHECKIN_MSG" | sed 's/\\n/\n/g')\n\n📢 GitHub Actions 自动推送"
          
          # 构造JSON并发送请求
          JSON_DATA=$(jq -n \
              --arg msgtype "markdown" \
              --arg content "$CONTENT" \
              '{"msgtype": $msgtype, "markdown": {"content": $content}}')
          
          curl -X POST "$WECHAT_WEBHOOK" \
              -H "Content-Type: application/json" \
              -d "$JSON_DATA"
