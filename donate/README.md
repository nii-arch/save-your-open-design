# 赞助图存放目录

把收款码图片放在这里，然后在 `README.md` 的「赞助」段落里取消注释即可。

## 步骤

1. 把微信赞赏码截图保存为 `wechat.jpg`（或 `.png`）
2. 放到本目录下，最终路径：`donate/wechat.jpg`
3. 打开 `README.md`，找到「赞助」段落，把这三行的注释去掉：

   ```markdown
   <!--
   <img src="donate/wechat.jpg" width="220" alt="微信赞赏码">
   -->
   ```

   改成：

   ```markdown
   <img src="donate/wechat.jpg" width="220" alt="微信赞赏码">
   ```

4. 提交推送

## 建议

- **用「赞赏码」而不是「个人收款码」**。赞赏码不带好友申请，不会暴露微信号。
- **图片宽度控制在 200~260px**，太大会占满屏幕。
- **金额定位放低**。`¥9.9` / `¥19.9` 这种「请喝咖啡」最稳，大额容易触发微信风控。
- **写清楚是赞助，不是购买**。README 里已经加了这句说明，别删。

## 如果要换成爱发电

用 [爱发电](https://afdian.com) 更正规：有订单记录、后台、不暴露个人收款码。

建好页面后，把链接填进 `.github/FUNDING.yml`：

```yaml
custom: ["https://afdian.com/a/你的页面"]
```

GitHub 仓库页右上角就会出现 Sponsor 按钮。
