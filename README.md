# LLM 内容审核插件

当前版本：`1.2.0`

`astrbot_plugin_llm_audit` 会先根据关键词累计风险分，达到阈值后调用后台配置的 LLM Provider 二次审核；只有 LLM 返回 `violation=true` 且 `confidence>=70` 时才限制用户。

## 网页编辑内置风险词库

在插件管理页打开“内置风险词库”，可以查看、增加、修改或删除内置触发词，点击“保存词库”后立即生效。每行格式为 `关键词 | 分数 | 分类 | 备注`，以 `#` 开头的行为注释；保存时会检查格式并提示错误行号。网页修改的词库保存在 AstrBot 的 `plugin_data/astrbot_plugin_llm_audit/keywords.txt`，插件更新后仍会使用它。首次编辑前显示插件随包提供的 `keywords.txt`。审核配置中的“自定义关键词”仍会附加到词库中。

## 后台配置

插件通过 `_conf_schema.json` 提供 AstrBot 后台配置页。安装后至少配置：

- `enabled`：是否启用插件。
- `audit_scope`：审核范围，默认 `private`，只审核私聊。
- `audit_ai_messages`：是否审核 AI/机器人消息，默认开启。
- `audit_provider_id`：用于审核的 AstrBot LLM Provider。
- `score_threshold`：累计风险分达到该值后触发 LLM 审核。
- `max_score_per_message`：单条消息最多加分。
- `review_cooldown_minutes`：同一用户复审冷却时间。
- `llm_user_history_count`：发送给 LLM 的用户历史消息数量，默认 30。
- `llm_group_context_count`：发送给 LLM 的上下文数量，默认 30。
- `ban_scope`：`group` 仅当前群限制，`global` 全局限制。
- `custom_keywords`：在插件配置页添加自定义关键词，每行一条。
- `audit_prompt`：要求模型只输出 JSON 的审核提示词。
- `blocked_notice`：用户被限制时收到的提示。

## 配置页添加关键词

在后台配置项 `custom_keywords` 中按行填写：

```text
关键词 | 分数 | 分类 | 备注
```

示例：

```text
高风险短语 | 5 | violence | 后台配置添加
另一个短语 | 3 | abuse | 后台配置添加
```

保存配置后，重载插件或使用 `/audit_reload_keywords` 让配置立即生效。`custom_keywords` 会与插件内置 `keywords.txt` 合并读取，重复关键词会自动去重。

插件详情页中的“风险与封禁管理”页面可以查看当前风险积分账号、封禁账号并解除封禁，也可以直接编辑审核配置。页面配置项与 AstrBot 插件配置页同步。

分类建议使用：`sexual`、`violence`、`abuse`、`illegal`、`self_harm`。

插件 Page 使用 AstrBot 4.26.0 起提供的 Pages 与 bridge API，插件最低版本要求为 4.26.0。

## 管理员命令

- `/audit_reload_keywords`：重新读取 `keywords.txt` 和后台 `custom_keywords`。
- `/audit_logs [数量]`：查看最近审核日志，默认 10 条，最多 50 条。
- `/audit_blacklist`：查看黑名单和风险分。
- `/audit_unban 平台:用户ID`：解除全局限制。
- `/audit_unban 平台:群ID:用户ID`：解除群内限制。
- `/audit_status 用户ID`：查看用户审核状态。
- `/audit_clear_expired`：清理过期限制和风险分。

## 日志与状态

插件会在 AstrBot 数据目录的 `plugin_data/astrbot_plugin_llm_audit/` 下保存：

- `state.json`：风险分、封禁次数等状态。
- `audit_logs.json`：最近 1000 条审核日志。
