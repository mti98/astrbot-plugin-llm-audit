import json
import math
import re
import time
from collections import defaultdict, deque
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from astrbot.api import AstrBotConfig, logger
from astrbot.api.event import AstrMessageEvent, filter
from astrbot.api.star import Context, Star, register
from astrbot.api.web import error_response, json_response, request

try:
    import yaml
except Exception:  # pragma: no cover
    yaml = None

try:
    from astrbot.core.utils.astrbot_path import get_astrbot_data_path
except Exception:  # pragma: no cover
    get_astrbot_data_path = None


PLUGIN_NAME = "astrbot_plugin_llm_audit"
PLUGIN_VERSION = "1.2.0"

DEFAULT_AUDIT_PROMPT = """你是聊天内容安全审核器。

请根据以下内容判断用户消息是否存在明显违规风险。

重点检查：
1. 色情、性交易、未成年人性内容
2. 暴力威胁、恐怖威胁、明确伤害他人
3. 严重辱骂、人身攻击、歧视仇恨
4. 违法交易、诈骗、毒品、违禁品
5. [用户触发屏蔽词]、自杀鼓励或教唆

注意：
- 普通讨论、新闻讨论、游戏讨论、引用他人内容、无明显恶意的玩笑，不应轻易判违规。
- 只有存在明确违规意图或明显风险时才判定 violation 为 true。
- 如果上下文不足，请倾向 violation 为 false。

你只能输出以下 JSON：

{
  "violation": true,
  "categories": ["sexual", "violence", "abuse", "illegal", "self_harm"],
  "reason": "简短中文原因",
  "confidence": 0
}

字段规则：
- violation：true 或 false
- categories：风险分类数组，没有风险则 []
- reason：简短中文说明
- confidence：0 到 100 的整数

不要输出 Markdown，不要输出代码块，不要输出额外解释。"""

DEFAULT_BLOCKED_NOTICE = "你因发布违规内容已被限制使用机器人。"
DEFAULT_LLM_USER_HISTORY_COUNT = 30
DEFAULT_LLM_GROUP_CONTEXT_COUNT = 30
DEFAULT_MAX_SCORE_PER_MESSAGE = 6
DEFAULT_MIN_KEYWORD_LENGTH = 1
DEFAULT_REVIEW_COOLDOWN_MINUTES = 10
DEFAULT_MAX_RISK_SCORE = 30
DEFAULT_BAN_BASE_HOURS = 6
DEFAULT_BAN_MULTIPLIER = 2
DEFAULT_BAN_MAX_HOURS = 168
DEFAULT_PERMANENT_BAN_AFTER = 0
DEFAULT_BAN_SCOPE = "group"
DEFAULT_SAFE_SCORE_AFTER_REVIEW = 3
DEFAULT_CONFIDENCE_THRESHOLD = 70
MAX_AUDIT_LOGS = 1000


try:
    AUDIT_MESSAGE_FILTER = filter.event_message_type(
        filter.EventMessageType.ALL,
        priority=100,
    )
except Exception as exc:  # pragma: no cover
    logger.warning("%s message filter unavailable: %s", PLUGIN_NAME, exc)

    def AUDIT_MESSAGE_FILTER(func):
        return func


@dataclass
class KeywordRule:
    word: str
    score: int
    category: str = ""
    enabled: bool = True


@register(PLUGIN_NAME, "user", "关键词计分 + LLM 复审内容审核插件", PLUGIN_VERSION)
class LlmAuditPlugin(Star):
    def __init__(self, context: Context, config: AstrBotConfig | None = None):
        super().__init__(context)
        self.config = config if config is not None else {}
        self.state: dict[str, Any] = {}
        self.state_file: Path | None = None
        self.audit_log_file: Path | None = None
        self.web_keyword_file: Path | None = None
        self.keyword_rules: list[KeywordRule] = []
        self.keyword_load_error_count = 0
        self._initialized = False
        self._last_cleanup_at = 0
        self._recent_user_messages: dict[str, deque[dict[str, Any]]] = defaultdict(
            self._new_user_history
        )
        self._recent_group_messages: dict[str, deque[dict[str, Any]]] = defaultdict(
            self._new_group_history
        )
        self._review_inflight: set[str] = set()
        self._register_web_apis()

    async def initialize(self):
        self._ensure_defaults()
        self._init_storage()
        self._load_state()
        self._load_keywords()
        self._migrate_blacklist()
        self._cleanup_scores(int(time.time()))
        self._initialized = True
        logger.info(
            "%s loaded: %s keyword rules, %s blacklisted users",
            PLUGIN_NAME,
            len(self.keyword_rules),
            len(self._blacklist_entries()),
        )

    async def terminate(self):
        self._save_state()

    def _register_web_apis(self):
        register_api = getattr(self.context, "register_web_api", None)
        if not callable(register_api):
            logger.warning("%s plugin page API is unavailable in this AstrBot version", PLUGIN_NAME)
            return
        routes = (
            ("dashboard", self._web_dashboard, ["GET"], "审核风险和封禁账号"),
            ("settings", self._web_settings, ["GET"], "读取审核插件配置"),
            ("settings/save", self._web_save_settings, ["POST"], "保存审核插件配置"),
            ("keywords", self._web_keywords, ["GET"], "读取内置风险词库"),
            ("keywords/save", self._web_save_keywords, ["POST"], "保存内置风险词库"),
            ("unban", self._web_unban, ["POST"], "解除审核封禁"),
        )
        for suffix, handler, methods, description in routes:
            try:
                register_api(
                    f"/{PLUGIN_NAME}/{suffix}", handler, methods, description
                )
            except Exception as exc:
                logger.warning(
                    "%s plugin page API registration failed for %s: %s",
                    PLUGIN_NAME,
                    suffix,
                    exc,
                )

    async def _web_dashboard(self):
        await self._ensure_runtime()
        now = int(time.time())
        self._migrate_blacklist()
        scores = []
        for item in self._active_scores(now):
            score = self._safe_int(item.get("score"), 0)
            if score <= 0:
                continue
            scores.append(
                {
                    "user_id": str(item.get("user_id", "")),
                    "sender_name": str(item.get("sender_name", "")),
                    "platform": str(item.get("platform", "")),
                    "group_id": str(item.get("group_id", "")),
                    "score": score,
                    "reset_at": str(item.get("reset_at_text", "")),
                    "score_key": str(item.get("score_key", "")),
                    "hits": item.get("last_hits", [])[:8]
                    if isinstance(item.get("last_hits"), list)
                    else [],
                }
            )
        blocked = []
        for raw_entry in self._blacklist_entries():
            entry = self._normalize_blacklist_entry(raw_entry)
            if not entry:
                continue
            blocked.append(
                {
                    "user_id": entry["user_id"],
                    "sender_name": entry["sender_name"],
                    "platform": entry["platform"],
                    "group_id": entry["group_id"],
                    "user_key": entry["user_key"],
                    "ban_scope": entry["ban_scope"],
                    "permanent": entry["permanent"],
                    "blocked_until": self._format_time(entry["blocked_until"]),
                    "reason": entry["reason"],
                    "strike_count": entry["strike_count"],
                    "score": self._score_for_entry(entry),
                }
            )
        blocked.sort(key=lambda entry: (not entry["permanent"], entry["blocked_until"]))
        return json_response(
            {
                "scores": scores[:200],
                "blocked": blocked[:200],
                "score_count": len(scores),
                "blocked_count": len(blocked),
                "updated_at": self._format_time(now),
            }
        )

    def _web_config_schema(self) -> dict[str, Any]:
        schema_path = Path(__file__).parent / "_conf_schema.json"
        try:
            loaded = json.loads(schema_path.read_text(encoding="utf-8"))
        except Exception as exc:
            logger.warning("%s config schema read failed: %s", PLUGIN_NAME, exc)
            return {}
        return loaded if isinstance(loaded, dict) else {}

    async def _web_settings(self):
        await self._ensure_runtime()
        fields = []
        for key, spec in self._web_config_schema().items():
            if not isinstance(spec, dict) or spec.get("invisible"):
                continue
            if key == "blacklisted_users":
                continue
            fields.append(
                {
                    "key": key,
                    "type": spec.get("type", "string"),
                    "label": spec.get("description", key),
                    "hint": spec.get("hint", ""),
                    "default": spec.get("default"),
                    "value": self.config.get(key, spec.get("default")),
                    "options": spec.get("options", []),
                    "labels": spec.get("labels", []),
                }
            )
        return json_response({"fields": fields})

    async def _web_save_settings(self):
        await self._ensure_runtime()
        payload = await request.json(default={})
        updates = payload.get("settings") if isinstance(payload, dict) else None
        if not isinstance(updates, dict):
            return error_response("配置数据格式不正确。", status_code=400)

        schema = self._web_config_schema()
        changed_keywords = False
        for key, value in updates.items():
            spec = schema.get(key)
            if not isinstance(spec, dict) or spec.get("invisible") or key == "blacklisted_users":
                return error_response(f"不允许修改配置项：{key}", status_code=400)
            kind = spec.get("type", "string")
            if kind == "bool":
                if not isinstance(value, bool):
                    return error_response(f"“{spec.get('description', key)}”必须是开关值。", status_code=400)
            elif kind == "int":
                if isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(value) or int(value) != value:
                    return error_response(f"“{spec.get('description', key)}”必须是整数。", status_code=400)
                minimum = 0 if key in {"score_reset_hours", "review_cooldown_minutes", "max_score_per_message", "permanent_ban_after", "llm_user_history_count", "llm_group_context_count"} else 1
                if value < minimum or value > 1000000:
                    return error_response(f"“{spec.get('description', key)}”超出允许范围。", status_code=400)
                value = int(value)
            elif kind == "float":
                if isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(value) or value < 1 or value > 1000:
                    return error_response(f"“{spec.get('description', key)}”必须是 1 到 1000 之间的数字。", status_code=400)
                value = float(value)
            else:
                if not isinstance(value, str):
                    return error_response(f"“{spec.get('description', key)}”必须是文本。", status_code=400)
                maximum = 20000 if key in {"audit_prompt", "custom_keywords"} else 4000
                if len(value) > maximum:
                    return error_response(f"“{spec.get('description', key)}”长度不能超过 {maximum} 个字符。", status_code=400)
                options = spec.get("options")
                if isinstance(options, list) and options and value not in options:
                    return error_response(f"“{spec.get('description', key)}”选项无效。", status_code=400)
            self.config[key] = value
            changed_keywords = changed_keywords or key == "custom_keywords"

        self._save_config()
        if changed_keywords:
            self._load_keywords()
        return json_response({"saved": True, "message": "配置已保存。"})

    def _web_keyword_source(self) -> Path:
        if self.web_keyword_file and self.web_keyword_file.exists():
            return self.web_keyword_file
        return self._keyword_file_path()

    async def _web_keywords(self):
        await self._ensure_runtime()
        source = self._web_keyword_source()
        try:
            content = self._read_text_by_encoding(source)
        except Exception as exc:
            logger.warning("%s keyword editor read failed: %s", PLUGIN_NAME, exc)
            return error_response("风险词库读取失败。", status_code=500)
        return json_response({
            "content": content,
            "source": "网页修改" if source == self.web_keyword_file else "插件内置文件",
            "rule_count": len(self.keyword_rules),
            "error_count": self.keyword_load_error_count,
        })

    async def _web_save_keywords(self):
        await self._ensure_runtime()
        payload = await request.json(default={})
        content = payload.get("content") if isinstance(payload, dict) else None
        if not isinstance(content, str):
            return error_response("风险词库内容必须是文本。", status_code=400)
        if len(content) > 200000 or len(content.splitlines()) > 5000:
            return error_response("风险词库超过 20 万字符或 5000 行限制。", status_code=400)
        for number, raw in enumerate(content.splitlines(), 1):
            line = raw.strip()
            if not line or line.startswith("#"):
                continue
            if "|" in line:
                parts = [part.strip() for part in line.split("|")]
                if len(parts) < 3 or not parts[0] or not parts[2]:
                    return error_response(f"第 {number} 行格式应为：关键词 | 分数 | 分类 | 备注。", status_code=400)
                if not parts[1].isdigit() or int(parts[1]) < 1:
                    return error_response(f"第 {number} 行的分数必须是正整数。", status_code=400)
        if not self.web_keyword_file:
            return error_response("风险词库目录尚未初始化。", status_code=500)
        try:
            self.web_keyword_file.parent.mkdir(parents=True, exist_ok=True)
            temporary = self.web_keyword_file.with_suffix(".tmp")
            temporary.write_text(content, encoding="utf-8")
            temporary.replace(self.web_keyword_file)
            self._load_keywords()
        except Exception as exc:
            logger.warning("%s keyword editor save failed: %s", PLUGIN_NAME, exc)
            return error_response("风险词库保存失败。", status_code=500)
        return json_response({
            "saved": True,
            "rule_count": len(self.keyword_rules),
            "error_count": self.keyword_load_error_count,
            "message": "风险词库已保存并生效。",
        })

    async def _web_unban(self):
        await self._ensure_runtime()
        payload = await request.json(default={})
        target = str(payload.get("user_key", "") or "").strip() if isinstance(payload, dict) else ""
        if not target:
            return error_response("缺少账号标识。", status_code=400)
        removed = self._unban_by_key(target, int(time.time()))
        if not removed:
            return error_response("没有找到匹配的封禁账号。", status_code=404)
        self._save_state()
        return json_response({"unbanned": True, "count": len(removed)})

    @AUDIT_MESSAGE_FILTER
    async def audit_message(self, event: AstrMessageEvent):
        await self._ensure_runtime()

        if not self._bool_cfg("enabled", True):
            return
        is_ai_message = self._is_ai_message_event(event)
        if is_ai_message and not self._bool_cfg("audit_ai_messages", True):
            return
        if self._bool_cfg("ignore_admins", True) and self._is_admin_event(event) and not is_ai_message:
            return

        now = int(time.time())
        if now - self._last_cleanup_at >= 300:
            self._cleanup_scores(now)
            self._migrate_blacklist()
            self._last_cleanup_at = now

        identity = self._event_identity(event)
        if not identity["user_id"] or not identity["platform"]:
            return
        if not self._event_in_audit_scope(identity):
            return

        block_entry = None if is_ai_message else self._find_active_block_entry(identity, now)
        if block_entry:
            notice = self._render_notice(block_entry, event, now)
            event.stop_event()
            if notice:
                yield event.plain_result(notice)
            return

        message_text = self._message_text(event)
        if not message_text:
            return

        self._record_history(identity, message_text, event, now)
        hits, added_score = self._score_message(message_text)
        if added_score <= 0:
            return

        score_key = self._score_key(identity)
        score_rec = self._get_score_record(score_key, now, identity)
        max_risk_score = self._int_cfg("max_risk_score", DEFAULT_MAX_RISK_SCORE, minimum=1)
        score_rec["score"] = min(
            max_risk_score,
            int(score_rec.get("score", 0)) + added_score,
        )
        score_rec["updated_at"] = now
        score_rec["reset_at"] = now + self._hours_cfg("score_reset_hours", 24) * 3600
        score_rec["user_id"] = identity["user_id"]
        score_rec["platform"] = identity["platform"]
        score_rec["group_id"] = identity["group_id"]
        score_rec["sender_name"] = identity["sender_name"]
        score_rec["ban_scope"] = self._ban_scope(identity)
        score_rec["last_message"] = self._truncate_text(message_text, 1000)
        score_rec["last_hits"] = hits
        score_rec["last_hit_at"] = now

        self._append_score_hit_history(score_rec, hits, now)
        self._save_state()

        audit_log = self._build_audit_log_record(
            now=now,
            event=event,
            identity=identity,
            message_text=message_text,
            hits=hits,
            added_score=added_score,
            current_score=int(score_rec.get("score", 0)),
        )

        if score_rec["score"] < self._int_cfg("score_threshold", 10, minimum=1):
            self._append_audit_log(audit_log)
            return

        cooldown_seconds = self._int_cfg(
            "review_cooldown_minutes",
            DEFAULT_REVIEW_COOLDOWN_MINUTES,
            minimum=0,
        ) * 60
        last_review_at = self._safe_int(score_rec.get("last_review_at"), 0)
        if cooldown_seconds > 0 and last_review_at and now - last_review_at < cooldown_seconds:
            audit_log["error"] = "LLM 审核冷却中，本次不重复调用。"
            self._append_audit_log(audit_log)
            logger.info(
                "%s review cooldown user_id=%s score=%s",
                PLUGIN_NAME,
                identity["user_id"],
                score_rec.get("score", 0),
            )
            return

        if score_key in self._review_inflight:
            audit_log["error"] = "LLM 审核进行中，本次不重复调用。"
            self._append_audit_log(audit_log)
            return

        # Reserve the review slot before yielding to the provider. Other messages
        # arriving while this call is in flight must not start duplicate reviews.
        self._review_inflight.add(score_key)
        reviewed_score = self._safe_int(score_rec.get("score"), 0)
        score_rec["last_review_at"] = now
        self._save_state()
        try:
            decision = await self._review_with_llm(
                event=event,
                identity=identity,
                score_rec=score_rec,
                hits=hits,
                now=now,
            )
        except Exception as exc:
            logger.warning(
                "%s LLM review failed user_id=%s error=%s",
                PLUGIN_NAME,
                identity["user_id"],
                exc,
            )
            decision = {
                "violation": False,
                "categories": [],
                "reason": "LLM 复审失败。",
                "confidence": 0,
                "raw": "",
                "error": f"LLM 复审失败: {exc}",
            }
        finally:
            self._review_inflight.discard(score_key)
        score_rec["last_review_violation"] = bool(decision["violation"])
        score_rec["last_review_reason"] = decision.get("reason", "")
        audit_log["triggered_llm"] = True
        audit_log["llm_raw_response"] = decision.get("raw", "")
        audit_log["llm_parsed_result"] = {
            "violation": bool(decision.get("violation", False)),
            "categories": decision.get("categories", []),
            "reason": decision.get("reason", ""),
            "confidence": decision.get("confidence", 0),
        }
        audit_log["violation"] = bool(decision.get("violation", False))
        audit_log["error"] = decision.get("error", "")
        if not audit_log["error"] and not str(self.config.get("audit_provider_id", "")).strip():
            audit_log["error"] = "missing audit_provider_id"

        if not self._decision_allows_ban(decision):
            if not decision.get("error"):
                concurrent_added_score = max(
                    0,
                    self._safe_int(score_rec.get("score"), 0) - reviewed_score,
                )
                safe_score = self._int_cfg(
                    "safe_score_after_review",
                    DEFAULT_SAFE_SCORE_AFTER_REVIEW,
                    minimum=0,
                )
                score_rec["score"] = min(max_risk_score, safe_score + concurrent_added_score)
            audit_log["current_risk_score"] = int(score_rec.get("score", 0))
            if decision.get("violation") and self._confidence_value(decision) < DEFAULT_CONFIDENCE_THRESHOLD:
                logger.info(
                    "%s LLM violation ignored by low confidence user_id=%s confidence=%s",
                    PLUGIN_NAME,
                    identity["user_id"],
                    decision.get("confidence", 0),
                )
            self._save_state()
            self._append_audit_log(audit_log)
            return

        if is_ai_message:
            self.state.setdefault("scores", {}).pop(score_key, None)
            audit_log["ban_executed"] = False
            audit_log["ban_duration_hours"] = 0
            audit_log["current_risk_score"] = 0
            audit_log["error"] = "AI message violation stopped; no user was banned."
            self._save_state()
            self._append_audit_log(audit_log)
            event.stop_event()
            return

        block_entry = self._ban_user(identity, decision, now, hits, score_key)
        audit_log["ban_executed"] = True
        audit_log["ban_duration_hours"] = block_entry.get("duration_hours", 0)
        audit_log["current_risk_score"] = 0
        self._save_state()
        self._append_audit_log(audit_log)
        notice = self._render_notice(block_entry, event, now)
        event.stop_event()
        if notice:
            yield event.plain_result(notice)

    @filter.command("audit_blacklist")
    async def audit_blacklist_command(self, event: AstrMessageEvent):
        """查看审核黑名单、风险分数和最近命中。"""
        await self._ensure_runtime()
        if not self._is_admin_event(event):
            yield event.plain_result("只有管理员可以查看审核黑名单。")
            return

        now = int(time.time())
        self._migrate_blacklist()
        entries = self._blacklist_entries()
        scores = self._active_scores(now)

        lines = ["黑名单："]
        if not entries:
            lines.append("暂无黑名单用户。")
        else:
            for entry in entries[:30]:
                lines.append(self._format_block_entry(entry, now))
            if len(entries) > 30:
                lines.append(f"还有 {len(entries) - 30} 条未显示。")

        lines.append("")
        lines.append("当前风险分数：")
        if not scores:
            lines.append("暂无分数记录。")
        else:
            for item in scores[:30]:
                hits = item.get("last_hits", [])
                hit_text = self._format_hits(hits)
                lines.append(
                    f"- {item.get('score_key')} 分数={item.get('score', 0)} "
                    f"下次清零={item.get('reset_at_text', '')} 命中={hit_text}"
                )
            if len(scores) > 30:
                lines.append(f"还有 {len(scores) - 30} 条未显示。")

        yield event.plain_result("\n".join(lines))

    @filter.command("audit_unban")
    async def audit_unban_command(self, event: AstrMessageEvent):
        """解封黑名单用户，用法：/audit_unban 平台:用户ID 或 /audit_unban 平台:群ID:用户ID。"""
        await self._ensure_runtime()
        if not self._is_admin_event(event):
            yield event.plain_result("只有管理员可以解除审核黑名单。")
            return

        raw = (getattr(event, "message_str", "") or "").strip()
        parts = raw.split(maxsplit=1)
        target = parts[1].strip() if len(parts) > 1 else ""
        if not target:
            yield event.plain_result("请提供要解封的用户键，例如：/audit_unban aiocqhttp:123456")
            return

        now = int(time.time())
        removed = self._unban_by_key(target, now)
        if not removed:
            yield event.plain_result(f"未找到黑名单用户：{target}")
            return

        self._save_state()
        yield event.plain_result(
            f"已解除拉黑：{target}，当前分数已设为 {self._int_cfg('post_unban_score', 4, minimum=0)}。"
        )

    @filter.command("audit_clear_expired")
    async def audit_clear_expired_command(self, event: AstrMessageEvent):
        """清理已过期的审核拉黑和风险分。"""
        await self._ensure_runtime()
        if not self._is_admin_event(event):
            yield event.plain_result("只有管理员可以清理审核记录。")
            return

        now = int(time.time())
        before_blacklist = len(self._blacklist_entries())
        before_scores = len(self.state.get("scores", {}))
        self._migrate_blacklist()
        self._cleanup_scores(now)
        after_blacklist = len(self._blacklist_entries())
        after_scores = len(self.state.get("scores", {}))
        yield event.plain_result(
            "已清理过期记录："
            f"黑名单 {before_blacklist - after_blacklist} 条，"
            f"风险分 {before_scores - after_scores} 条。"
        )

    @filter.command("audit_status")
    async def audit_status_command(self, event: AstrMessageEvent):
        """查看用户审核状态，用法：/audit_status 用户ID 或 /audit_status 平台:用户ID。"""
        await self._ensure_runtime()
        if not self._is_admin_event(event):
            yield event.plain_result("只有管理员可以查看审核状态。")
            return

        raw = (getattr(event, "message_str", "") or "").strip()
        parts = raw.split(maxsplit=1)
        target = parts[1].strip() if len(parts) > 1 else ""
        if not target:
            yield event.plain_result("请提供要查询的用户 ID，例如：/audit_status 123456")
            return

        now = int(time.time())
        self._migrate_blacklist()
        self._cleanup_scores(now)
        parsed = self._parse_user_key(target)
        lines = [f"审核状态：{target}"]

        matched_entries = []
        for entry in self._blacklist_entries():
            normalized = self._normalize_blacklist_entry(entry)
            if not normalized:
                continue
            if parsed:
                if self._entry_matches_unban_target(normalized, target, parsed):
                    matched_entries.append(normalized)
            elif str(normalized.get("user_id", "")) == target:
                matched_entries.append(normalized)

        if matched_entries:
            lines.append("黑名单：")
            for entry in matched_entries[:10]:
                lines.append(self._format_block_entry(entry, now))
        else:
            lines.append("黑名单：未命中")

        matched_scores = []
        for item in self._active_scores(now):
            if parsed:
                if item.get("platform") != parsed["platform"]:
                    continue
                if item.get("user_id") != parsed["user_id"]:
                    continue
                if parsed["group_id"] and item.get("group_id", "") != parsed["group_id"]:
                    continue
                matched_scores.append(item)
            elif str(item.get("user_id", "")) == target:
                matched_scores.append(item)

        if matched_scores:
            lines.append("风险分：")
            for item in matched_scores[:10]:
                lines.append(
                    f"- {item.get('score_key')} 分数={item.get('score', 0)} "
                    f"下次清零={item.get('reset_at_text', '')} 命中={self._format_hits(item.get('last_hits', []))}"
                )
        else:
            lines.append("风险分：无")

        yield event.plain_result("\n".join(lines))

    @filter.command("audit_reload_keywords")
    async def audit_reload_keywords_command(self, event: AstrMessageEvent):
        """重新读取 keywords.txt。"""
        await self._ensure_runtime()
        if not self._is_admin_event(event):
            yield event.plain_result("只有管理员可以重新加载审核关键词。")
            return

        self._load_keywords()
        yield event.plain_result(
            f"关键词已重新加载：成功 {len(self.keyword_rules)} 条，格式错误 {self.keyword_load_error_count} 行。"
        )

    @filter.command("audit_logs")
    async def audit_logs_command(self, event: AstrMessageEvent):
        """查看最近审核日志，用法：/audit_logs [数量]。"""
        await self._ensure_runtime()
        if not self._is_admin_event(event):
            yield event.plain_result("只有管理员可以查看审核日志。")
            return

        raw = (getattr(event, "message_str", "") or "").strip()
        parts = raw.split(maxsplit=1)
        limit = 10
        if len(parts) > 1:
            limit = self._safe_int(parts[1], 10)
        limit = max(1, min(50, limit))
        logs = self._read_audit_logs()
        recent = logs[-limit:]
        if not recent:
            yield event.plain_result("暂无审核日志。")
            return

        lines = [f"最近 {len(recent)} 条审核日志："]
        for item in reversed(recent):
            hit_words = item.get("matched_keywords", [])
            hit_text = "、".join(
                self._truncate_text(str(hit.get("word", "")), 12)
                for hit in hit_words[:3]
                if isinstance(hit, dict)
            )
            lines.append(
                f"- {item.get('time', '')} {item.get('platform', '')} "
                f"{item.get('group_id') or item.get('session_id') or 'private'} "
                f"用户={item.get('user_id', '')} 加分={item.get('added_score', 0)} "
                f"累计={item.get('current_risk_score', 0)} LLM={item.get('triggered_llm', False)} "
                f"违规={item.get('violation', False)} 封禁={item.get('ban_executed', False)} "
                f"命中={hit_text or '无'} 消息={self._truncate_text(str(item.get('message', '')), 60)}"
            )
        yield event.plain_result("\n".join(lines))

    async def _ensure_runtime(self):
        if not self._initialized:
            await self.initialize()

    def _ensure_defaults(self):
        current_prompt = str(self.config.get("audit_prompt", "") or "")
        if not current_prompt.strip() or "violation" not in current_prompt:
            self.config["audit_prompt"] = DEFAULT_AUDIT_PROMPT
            self._save_config()
        current_notice = str(self.config.get("blocked_notice", "") or "")
        if not current_notice.strip() or "浣犲凡" in current_notice:
            self.config["blocked_notice"] = DEFAULT_BLOCKED_NOTICE
            self._save_config()
        if "blacklisted_users" not in self.config:
            self.config["blacklisted_users"] = []
            self._save_config()
        if "keyword_path" not in self.config:
            self.config["keyword_path"] = "keywords.txt"
            self._save_config()
        for key, value in {
            "enabled": True,
            "audit_scope": "private",
            "audit_ai_messages": True,
            "score_threshold": 12,
            "keyword_score": 2,
            "custom_keywords": "",
            "score_reset_hours": 24,
            "review_cooldown_minutes": DEFAULT_REVIEW_COOLDOWN_MINUTES,
            "llm_user_history_count": DEFAULT_LLM_USER_HISTORY_COUNT,
            "llm_group_context_count": DEFAULT_LLM_GROUP_CONTEXT_COUNT,
            "max_score_per_message": DEFAULT_MAX_SCORE_PER_MESSAGE,
            "max_risk_score": DEFAULT_MAX_RISK_SCORE,
            "min_keyword_length": DEFAULT_MIN_KEYWORD_LENGTH,
            "ban_base_hours": DEFAULT_BAN_BASE_HOURS,
            "ban_multiplier": DEFAULT_BAN_MULTIPLIER,
            "ban_max_hours": DEFAULT_BAN_MAX_HOURS,
            "permanent_ban_after": DEFAULT_PERMANENT_BAN_AFTER,
            "ban_scope": DEFAULT_BAN_SCOPE,
            "ignore_admins": True,
        }.items():
            if key not in self.config:
                self.config[key] = value
                self._save_config()
        if self._int_cfg("min_keyword_length", DEFAULT_MIN_KEYWORD_LENGTH, minimum=1) > DEFAULT_MIN_KEYWORD_LENGTH:
            self.config["min_keyword_length"] = DEFAULT_MIN_KEYWORD_LENGTH
            self._save_config()
    def _init_storage(self):
        if get_astrbot_data_path:
            base = Path(get_astrbot_data_path())
            data_dir = base / "plugin_data" / PLUGIN_NAME
        else:
            data_dir = Path(__file__).parent / "data"
        data_dir.mkdir(parents=True, exist_ok=True)
        self.state_file = data_dir / "state.json"
        self.audit_log_file = data_dir / "audit_logs.json"
        self.web_keyword_file = data_dir / "keywords.txt"

    def _load_state(self):
        self.state = {
            "scores": {},
            "strikes": {},
            "history": {},
        }
        if not self.state_file or not self.state_file.exists():
            return
        try:
            loaded = json.loads(self.state_file.read_text(encoding="utf-8"))
        except Exception as exc:
            logger.warning("%s state load failed: %s", PLUGIN_NAME, exc)
            return
        if not isinstance(loaded, dict):
            return
        if isinstance(loaded.get("scores"), dict):
            self.state["scores"] = loaded["scores"]
        if isinstance(loaded.get("strikes"), dict):
            self.state["strikes"] = loaded["strikes"]
        if isinstance(loaded.get("history"), dict):
            self.state["history"] = loaded["history"]

    def _save_state(self):
        if not self.state_file:
            return
        try:
            self.state_file.parent.mkdir(parents=True, exist_ok=True)
            self.state_file.write_text(
                json.dumps(self.state, ensure_ascii=False, indent=2),
                encoding="utf-8",
            )
        except Exception as exc:
            logger.warning("%s state save failed: %s", PLUGIN_NAME, exc)

    def _build_audit_log_record(
        self,
        now: int,
        event: AstrMessageEvent,
        identity: dict[str, str],
        message_text: str,
        hits: list[dict[str, Any]],
        added_score: int,
        current_score: int,
    ) -> dict[str, Any]:
        return {
            "time": self._format_time(now),
            "timestamp": now,
            "platform": identity.get("platform", ""),
            "group_id": identity.get("group_id", ""),
            "session_id": self._call_event(event, "get_session_id"),
            "user_id": identity.get("user_id", ""),
            "user_nickname": identity.get("sender_name", ""),
            "message": message_text,
            "matched_keywords": hits,
            "added_score": added_score,
            "current_risk_score": current_score,
            "triggered_llm": False,
            "llm_raw_response": "",
            "llm_parsed_result": {},
            "violation": False,
            "ban_executed": False,
            "ban_duration_hours": 0,
            "error": "",
        }

    def _read_audit_logs(self) -> list[dict[str, Any]]:
        if not self.audit_log_file or not self.audit_log_file.exists():
            return []
        try:
            loaded = json.loads(self.audit_log_file.read_text(encoding="utf-8"))
        except Exception as exc:
            logger.warning("%s audit log load failed: %s", PLUGIN_NAME, exc)
            return []
        if not isinstance(loaded, list):
            return []
        return [item for item in loaded if isinstance(item, dict)]

    def _append_audit_log(self, record: dict[str, Any]):
        if not self.audit_log_file:
            return
        try:
            logs = self._read_audit_logs()
            logs.append(record)
            if len(logs) > MAX_AUDIT_LOGS:
                logs = logs[-MAX_AUDIT_LOGS:]
            self.audit_log_file.parent.mkdir(parents=True, exist_ok=True)
            self.audit_log_file.write_text(
                json.dumps(logs, ensure_ascii=False, indent=2),
                encoding="utf-8",
            )
        except Exception as exc:
            logger.warning("%s audit log save failed: %s", PLUGIN_NAME, exc)

    def _keyword_file_path(self) -> Path:
        path_value = str(self.config.get("keyword_path", "keywords.txt")).strip() or "keywords.txt"
        keyword_path = Path(path_value)
        if not keyword_path.is_absolute():
            keyword_path = Path(__file__).parent / keyword_path
        return keyword_path

    def _load_keywords(self):
        keyword_path = self._web_keyword_source()

        self.keyword_rules = []
        self.keyword_load_error_count = 0
        if not keyword_path.exists():
            logger.warning("%s keyword file missing: %s", PLUGIN_NAME, keyword_path)
        else:
            suffix = keyword_path.suffix.lower()
            try:
                if suffix in {".json"}:
                    loaded = json.loads(keyword_path.read_text(encoding="utf-8"))
                    self.keyword_rules = self._parse_rule_payload(loaded)
                elif suffix in {".yaml", ".yml"}:
                    if yaml is None:
                        raise RuntimeError("PyYAML unavailable")
                    loaded = yaml.safe_load(keyword_path.read_text(encoding="utf-8"))
                    self.keyword_rules = self._parse_rule_payload(loaded)
                else:
                    self.keyword_rules = self._parse_legacy_keywords(self._read_text_by_encoding(keyword_path))
            except UnicodeDecodeError:
                try:
                    self.keyword_rules = self._parse_legacy_keywords(self._read_text_by_encoding(keyword_path))
                except Exception as exc:
                    logger.warning("%s keyword load failed: %s", PLUGIN_NAME, exc)
            except Exception as exc:
                logger.warning("%s keyword load failed: %s", PLUGIN_NAME, exc)

        custom_keywords = str(self.config.get("custom_keywords", "") or "").strip()
        if custom_keywords:
            self.keyword_rules.extend(self._parse_legacy_keywords(custom_keywords))

        self.keyword_rules = self._dedupe_rules(self.keyword_rules)
        logger.info(
            "%s keywords loaded: %s rules, %s malformed lines from %s",
            PLUGIN_NAME,
            len(self.keyword_rules),
            self.keyword_load_error_count,
            keyword_path,
        )

    def _read_text_by_encoding(self, path: Path) -> str:
        last_error: Exception | None = None
        for encoding in ("utf-8-sig", "utf-8", "gb18030", "gbk"):
            try:
                return path.read_text(encoding=encoding)
            except Exception as exc:
                last_error = exc
        if last_error:
            raise last_error
        return path.read_text(encoding="utf-8")

    def _parse_rule_payload(self, loaded: Any) -> list[KeywordRule]:
        rules: list[KeywordRule] = []
        if isinstance(loaded, list):
            for item in loaded:
                if isinstance(item, str):
                    rules.append(self._rule_from_word(item))
                elif isinstance(item, dict):
                    word = str(item.get("word", "")).strip()
                    if not word:
                        continue
                    rules.append(
                        KeywordRule(
                            word=word,
                            score=self._safe_int(item.get("score"), self._int_cfg("keyword_score", 2, minimum=1)),
                            category=str(item.get("category", "")).strip(),
                            enabled=self._safe_bool(item.get("enabled"), True),
                        )
                    )
        elif isinstance(loaded, dict):
            maybe_rules = loaded.get("rules")
            if isinstance(maybe_rules, list):
                return self._parse_rule_payload(maybe_rules)
            maybe_keywords = loaded.get("keywords")
            if isinstance(maybe_keywords, list):
                return self._parse_rule_payload(maybe_keywords)
        return rules

    def _parse_legacy_keywords(self, raw: str) -> list[KeywordRule]:
        rules: list[KeywordRule] = []
        default_score = self._int_cfg("keyword_score", 2, minimum=1)
        min_len = self._int_cfg("min_keyword_length", DEFAULT_MIN_KEYWORD_LENGTH, minimum=1)
        seen: set[str] = set()
        for line in raw.splitlines():
            text = line.strip()
            if not text or text.startswith("#"):
                continue
            if "|" in text:
                parts = [part.strip() for part in text.split("|")]
                candidate = parts[0] if parts else ""
                if not candidate or len(parts) < 3:
                    self.keyword_load_error_count += 1
                    logger.warning("%s keyword format invalid: %s", PLUGIN_NAME, text)
                    continue
                if len(candidate) < min_len or candidate in seen:
                    continue
                parsed_score = self._safe_int(parts[1] if len(parts) > 1 else None, -1)
                if parsed_score <= 0:
                    self.keyword_load_error_count += 1
                    logger.warning("%s keyword score invalid: %s", PLUGIN_NAME, text)
                    continue
                seen.add(candidate)
                rules.append(
                    KeywordRule(
                        word=candidate,
                        score=max(1, parsed_score),
                        category=parts[2] if len(parts) > 2 else "",
                        enabled=True,
                    )
                )
                continue
            for word in re.split(r"[\s,，、;；|]+", text):
                candidate = word.strip()
                if len(candidate) < min_len:
                    continue
                if candidate in seen:
                    continue
                seen.add(candidate)
                rules.append(KeywordRule(word=candidate, score=default_score, category="", enabled=True))
        return rules

    def _rule_from_word(self, word: str) -> KeywordRule:
        return KeywordRule(
            word=word.strip(),
            score=self._int_cfg("keyword_score", 2, minimum=1),
            category="",
            enabled=True,
        )

    def _dedupe_rules(self, rules: list[KeywordRule]) -> list[KeywordRule]:
        min_len = self._int_cfg("min_keyword_length", DEFAULT_MIN_KEYWORD_LENGTH, minimum=1)
        seen: set[str] = set()
        deduped: list[KeywordRule] = []
        for rule in rules:
            word = rule.word.strip()
            dedupe_key = word.lower()
            if len(word) < min_len:
                continue
            if dedupe_key in seen:
                continue
            seen.add(dedupe_key)
            deduped.append(rule)
        return deduped

    def _new_user_history(self):
        return deque(maxlen=max(50, self._int_cfg("llm_user_history_count", DEFAULT_LLM_USER_HISTORY_COUNT, minimum=0) * 6 + 10))

    def _new_group_history(self):
        return deque(maxlen=max(50, self._int_cfg("llm_group_context_count", DEFAULT_LLM_GROUP_CONTEXT_COUNT, minimum=0) * 6 + 10))

    def _message_text(self, event: AstrMessageEvent) -> str:
        text = (
            getattr(event, "message_str", "")
            or self._call_event(event, "get_message_outline")
            or self._extract_event_result_text(event)
        )
        return str(text or "").strip()

    def _extract_event_result_text(self, event: AstrMessageEvent) -> str:
        for attr_name in ("result", "reply", "response", "content", "text"):
            value = getattr(event, attr_name, None)
            text = self._stringify_message_like(value)
            if text:
                return text
        for method_name in ("get_result", "get_reply", "get_response"):
            method = getattr(event, method_name, None)
            if callable(method):
                try:
                    text = self._stringify_message_like(method())
                except Exception:
                    text = ""
                if text:
                    return text
        return ""

    def _stringify_message_like(self, value: Any) -> str:
        if value is None:
            return ""
        if isinstance(value, str):
            return value.strip()
        for attr_name in ("message", "message_str", "text", "content", "content_str", "chain"):
            attr = getattr(value, attr_name, None)
            if isinstance(attr, str) and attr.strip():
                return attr.strip()
        return str(value or "").strip()

    def _event_in_audit_scope(self, identity: dict[str, str]) -> bool:
        scope = str(self.config.get("audit_scope", "private") or "private").strip().lower()
        if scope in {"all", "both", "*"}:
            return True
        return not bool(identity.get("group_id"))

    def _is_ai_message_event(self, event: AstrMessageEvent) -> bool:
        message_obj = getattr(event, "message_obj", None)
        sender = getattr(message_obj, "sender", None)
        markers = [
            getattr(event, "role", ""),
            getattr(sender, "role", ""),
            getattr(sender, "type", ""),
            getattr(message_obj, "type", ""),
            event.__class__.__name__,
            message_obj.__class__.__name__ if message_obj is not None else "",
        ]
        marker_text = " ".join(str(item).lower() for item in markers if item)
        if any(word in marker_text for word in ("ai", "assistant", "bot", "robot", "llm", "result")):
            return True
        for attr_name in ("is_ai", "is_bot", "is_self", "from_self"):
            value = getattr(event, attr_name, None)
            if callable(value):
                try:
                    if bool(value()):
                        return True
                except Exception:
                    continue
            elif bool(value):
                return True
        return False

    def _score_message(self, text: str) -> tuple[list[dict[str, Any]], int]:
        if not self.keyword_rules:
            return [], 0

        min_len = self._int_cfg("min_keyword_length", DEFAULT_MIN_KEYWORD_LENGTH, minimum=1)
        max_per_msg = self._int_cfg("max_score_per_message", DEFAULT_MAX_SCORE_PER_MESSAGE, minimum=0)
        lowered = text.lower()
        matched_words: set[str] = set()
        hits: list[dict[str, Any]] = []
        total = 0
        now = int(time.time())

        for rule in self.keyword_rules:
            word = rule.word.strip()
            match_key = word.lower()
            if not rule.enabled or len(word) < min_len:
                continue
            if match_key in matched_words:
                continue
            if match_key not in lowered:
                continue
            matched_words.add(match_key)
            score = max(1, int(rule.score))
            hit = {
                "word": word,
                "category": rule.category,
                "score": score,
                "hit_at": now,
            }
            hits.append(hit)
            total += score
            if max_per_msg > 0 and total >= max_per_msg:
                total = max_per_msg
                break

        if max_per_msg > 0:
            total = min(total, max_per_msg)

        return hits, total

    async def _review_with_llm(
        self,
        event: AstrMessageEvent,
        identity: dict[str, str],
        score_rec: dict[str, Any],
        hits: list[dict[str, Any]],
        now: int,
    ) -> dict[str, Any]:
        provider_id = str(self.config.get("audit_provider_id", "")).strip()
        if not provider_id:
            logger.warning("%s audit_provider_id is not configured; LLM review skipped.", PLUGIN_NAME)
            return {
                "violation": False,
                "categories": [],
                "reason": "未配置审核 LLM 供应商，跳过复审。",
                "confidence": 0,
                "raw": "",
                "error": "未配置审核 LLM 供应商。",
            }

        prompt = self._build_review_prompt(event, identity, score_rec, hits, now)
        try:
            resp = await self.context.llm_generate(
                chat_provider_id=provider_id,
                prompt=prompt,
            )
        except Exception as exc:
            logger.warning(
                "%s LLM call failed user_id=%s error=%s",
                PLUGIN_NAME,
                identity["user_id"],
                exc,
            )
            return {
                "violation": False,
                "categories": [],
                "reason": f"LLM 调用失败: {exc}",
                "confidence": 0,
                "raw": "",
                "error": f"LLM 调用失败: {exc}",
            }

        raw_text = self._extract_llm_text(resp)
        return self._parse_llm_decision(raw_text, identity["user_id"])

    def _build_review_prompt(
        self,
        event: AstrMessageEvent,
        identity: dict[str, str],
        score_rec: dict[str, Any],
        hits: list[dict[str, Any]],
        now: int,
    ) -> str:
        audit_prompt = str(self.config.get("audit_prompt", "")).strip() or DEFAULT_AUDIT_PROMPT
        user_history_count = self._int_cfg("llm_user_history_count", DEFAULT_LLM_USER_HISTORY_COUNT, minimum=0)
        group_context_count = self._int_cfg("llm_group_context_count", DEFAULT_LLM_GROUP_CONTEXT_COUNT, minimum=0)

        trigger_message = self._truncate_text(self._message_text(event), 1800)
        user_messages = self._collect_recent_user_messages(identity, user_history_count)
        group_messages = self._collect_recent_group_messages(identity, group_context_count)

        hit_lines = []
        for hit in hits:
            hit_lines.append(
                f"- {hit['word']} | 分类: {hit.get('category', '') or '未分类'} | 分数: {hit['score']}"
            )
        hit_text = "\n".join(hit_lines) if hit_lines else "无"

        user_lines = []
        for item in user_messages:
            user_lines.append(
                f"[{self._format_time(int(item['ts']))}] {item.get('sender_name') or item['user_id']}: {self._truncate_text(str(item.get('text', '')), 600)}"
            )
        user_context_text = "\n".join(user_lines) if user_lines else "无"

        group_lines = []
        for item in group_messages:
            group_lines.append(
                f"[{self._format_time(int(item['ts']))}] {item.get('sender_name') or item.get('user_id')}: {self._truncate_text(str(item.get('text', '')), 400)}"
            )
        group_context_text = "\n".join(group_lines) if group_lines else "无"

        prompt_parts = [
            audit_prompt,
            "说明：只能根据下面提供的内容判断，不要猜测未提供的上下文。",
            f"当前用户 ID: {identity['user_id']}",
            f"当前用户昵称: {identity['sender_name']}",
            f"当前风险分数: {score_rec.get('score', 0)}",
            f"本次命中关键词:\n{hit_text}",
            f"当前触发消息:\n{trigger_message}",
            f"当前用户最近消息（最近 {user_history_count} 条）:\n{user_context_text}",
        ]
        if group_context_count > 0:
            prompt_parts.append(
                f"最近群消息（最近 {group_context_count} 条，仅作极少量上下文，默认关闭）:\n{group_context_text}"
            )

        prompt_parts.append(
            """请严格只输出一个 JSON 对象，不能输出解释、Markdown 或代码块。
JSON 格式：
{
  "violation": true,
  "categories": ["文爱", "色情", "性暗示", "暴力血腥", "辱骂攻击", "极端主义或违法动员", "涉政风险"],
  "reason": "一句话说明原因",
  "confidence": 0.0
}
"""
        )

        prompt_parts.append(
            '最终输出要求：只能输出一个 JSON 对象。不要输出 Markdown、代码块或额外解释。'
            'confidence 必须是 0 到 100 的整数。'
        )
        prompt = "\n\n".join(prompt_parts)
        return self._limit_prompt_length(prompt, trigger_message, user_messages, group_messages)

    def _limit_prompt_length(
        self,
        prompt: str,
        trigger_message: str,
        user_messages: list[dict[str, Any]],
        group_messages: list[dict[str, Any]],
    ) -> str:
        max_len = 6000
        if len(prompt) <= max_len:
            return prompt

        lines = [
            prompt.split("请严格只输出一个 JSON 对象", 1)[0].rstrip(),
        ]
        trimmed_user = list(user_messages)
        trimmed_group = list(group_messages)

        while True:
            parts = lines.copy()
            parts.append(f"当前触发消息:\n{self._truncate_text(trigger_message, 1800)}")
            if trimmed_user:
                user_lines = []
                for item in trimmed_user:
                    user_lines.append(
                        f"[{self._format_time(int(item['ts']))}] {item.get('sender_name') or item['user_id']}: {self._truncate_text(str(item.get('text', '')), 500)}"
                    )
                parts.append("当前用户最近消息：\n" + "\n".join(user_lines))
            if trimmed_group:
                group_lines = []
                for item in trimmed_group:
                    group_lines.append(
                        f"[{self._format_time(int(item['ts']))}] {item.get('sender_name') or item.get('user_id')}: {self._truncate_text(str(item.get('text', '')), 300)}"
                    )
                parts.append("最近群消息：\n" + "\n".join(group_lines))
            parts.append(
                """请严格只输出一个 JSON 对象，不能输出解释、Markdown 或代码块。
JSON 格式：
{
  "violation": true,
  "categories": ["文爱", "色情", "性暗示", "暴力血腥", "辱骂攻击", "极端主义或违法动员", "涉政风险"],
  "reason": "一句话说明原因",
  "confidence": 0.0
}
"""
            )
            candidate = "\n\n".join(parts)
            if len(candidate) <= max_len:
                return candidate
            if trimmed_group:
                trimmed_group.pop(0)
                continue
            if trimmed_user:
                trimmed_user.pop(0)
                continue
            return self._truncate_text(candidate, max_len)

    def _extract_llm_text(self, resp: Any) -> str:
        if isinstance(resp, str):
            return resp.strip()
        for attr in ("completion_text", "text", "content", "message"):
            value = getattr(resp, attr, None)
            if isinstance(value, str) and value.strip():
                return value.strip()
        return str(resp or "").strip()

    def _parse_llm_decision(self, raw_text: str, user_id: str) -> dict[str, Any]:
        candidate = self._unwrap_json_candidate(raw_text)
        try:
            parsed = json.loads(candidate)
        except Exception:
            self._log_llm_parse_warning(user_id, raw_text, "json decode failed")
            return {
                "violation": False,
                "categories": [],
                "reason": "",
                "confidence": 0,
                "raw": self._truncate_text(raw_text, 500),
                "error": "LLM JSON 解析失败",
            }

        if not isinstance(parsed, dict):
            self._log_llm_parse_warning(user_id, raw_text, "root is not object")
            return {
                "violation": False,
                "categories": [],
                "reason": "",
                "confidence": 0,
                "raw": self._truncate_text(raw_text, 500),
                "error": "LLM JSON 根节点不是对象",
            }

        violation = parsed.get("violation")
        categories = parsed.get("categories")
        reason = parsed.get("reason")
        confidence = parsed.get("confidence")
        if not isinstance(violation, bool):
            self._log_llm_parse_warning(user_id, raw_text, "violation type invalid")
            return self._safe_negative_decision(raw_text)
        if not isinstance(categories, list) or any(not isinstance(i, str) for i in categories):
            self._log_llm_parse_warning(user_id, raw_text, "categories type invalid")
            return self._safe_negative_decision(raw_text)
        if not isinstance(reason, str):
            self._log_llm_parse_warning(user_id, raw_text, "reason type invalid")
            return self._safe_negative_decision(raw_text)
        if not isinstance(confidence, (int, float)):
            self._log_llm_parse_warning(user_id, raw_text, "confidence type invalid")
            return self._safe_negative_decision(raw_text)
        confidence_value = float(confidence)
        if 0 <= confidence_value <= 1:
            confidence_value *= 100
        if confidence_value < 0 or confidence_value > 100:
            self._log_llm_parse_warning(user_id, raw_text, "confidence out of range")
            return self._safe_negative_decision(raw_text)

        return {
            "violation": violation,
            "categories": [str(i) for i in categories],
            "reason": reason.strip()[:500],
            "confidence": int(round(confidence_value)),
            "raw": self._truncate_text(raw_text, 500),
        }

    def _safe_negative_decision(self, raw_text: str) -> dict[str, Any]:
        return {
            "violation": False,
            "categories": [],
            "reason": "",
            "confidence": 0,
            "raw": self._truncate_text(raw_text, 500),
            "error": "LLM JSON 解析失败或字段格式不合法",
        }

    def _unwrap_json_candidate(self, text: str) -> str:
        stripped = text.strip()
        fence = re.search(r"```(?:json)?\s*(.*?)\s*```", stripped, re.S | re.I)
        if fence:
            return fence.group(1).strip()
        start = stripped.find("{")
        end = stripped.rfind("}")
        if start >= 0 and end > start:
            return stripped[start : end + 1].strip()
        return stripped

    def _log_llm_parse_warning(self, user_id: str, raw_text: str, reason: str):
        logger.warning(
            "%s LLM parse failed user_id=%s reason=%s raw=%s",
            PLUGIN_NAME,
            user_id,
            reason,
            self._truncate_text(raw_text, 500),
        )

    def _confidence_value(self, decision: dict[str, Any]) -> int:
        value = decision.get("confidence", 0)
        try:
            confidence = float(value)
        except Exception:
            return 0
        if 0 <= confidence <= 1:
            confidence *= 100
        return int(round(max(0, min(100, confidence))))

    def _decision_allows_ban(self, decision: dict[str, Any]) -> bool:
        if not bool(decision.get("violation", False)):
            return False
        confidence = self._confidence_value(decision)
        if confidence < DEFAULT_CONFIDENCE_THRESHOLD:
            return False
        return True

    def _ban_user(
        self,
        identity: dict[str, str],
        decision: dict[str, Any],
        now: int,
        hits: list[dict[str, Any]],
        score_key: str,
    ) -> dict[str, Any]:
        strike_key = self._strike_key(identity)
        strike_state = self.state.setdefault("strikes", {}).setdefault(
            strike_key,
            {"count": 0, "last_at": 0},
        )
        strike_state["count"] = int(strike_state.get("count", 0)) + 1
        strike_state["last_at"] = now

        duration_hours, permanent = self._ban_duration_for_strike(int(strike_state["count"]))
        blocked_until = 0 if permanent else now + duration_hours * 3600
        ban_scope = self._ban_scope(identity)
        entry = {
            "user_key": self._ban_key(identity),
            "legacy_user_key": self._legacy_key(identity) if ban_scope == "global" else "",
            "platform": identity["platform"],
            "group_id": identity["group_id"],
            "user_id": identity["user_id"],
            "sender_name": identity["sender_name"],
            "reason": str(decision.get("reason", ""))[:500],
            "categories": self._join_categories(decision.get("categories", [])),
            "ban_scope": ban_scope,
            "blocked_at": now,
            "blocked_until": blocked_until,
            "duration_hours": duration_hours,
            "strike_count": int(strike_state["count"]),
            "permanent": permanent,
            "last_notify_at": 0,
            "recent_hits": hits[:20],
            "score_key": score_key,
        }
        self._upsert_blacklist_entry(entry)
        self.state.setdefault("scores", {}).pop(score_key, None)
        self._save_config()
        return entry

    def _ban_duration_for_strike(self, strike_count: int) -> tuple[int, bool]:
        permanent_after = self._int_cfg(
            "permanent_ban_after", DEFAULT_PERMANENT_BAN_AFTER, minimum=0
        )
        if permanent_after > 0 and strike_count >= permanent_after:
            return 0, True

        base_hours = self._int_cfg("ban_base_hours", DEFAULT_BAN_BASE_HOURS, minimum=1)
        multiplier = self._float_cfg("ban_multiplier", DEFAULT_BAN_MULTIPLIER, minimum=1.0)
        max_hours = self._int_cfg("ban_max_hours", DEFAULT_BAN_MAX_HOURS, minimum=1)
        duration = base_hours * (multiplier ** max(0, strike_count - 1))
        duration = int(min(duration, max_hours))
        return max(1, duration), False

    def _find_active_block_entry(self, identity: dict[str, str], now: int) -> dict[str, Any] | None:
        self._migrate_blacklist()
        candidates = self._ban_key_candidates(identity)
        for entry in self._blacklist_entries():
            if self._entry_matches_any_key(entry, candidates):
                if entry.get("permanent"):
                    return entry
                blocked_until = self._safe_int(entry.get("blocked_until"), 0)
                if blocked_until <= 0 or blocked_until > now:
                    return entry
        return None

    def _migrate_blacklist(self):
        entries = self._blacklist_entries()
        changed = False
        normalized: list[dict[str, Any]] = []
        now = int(time.time())
        for entry in entries:
            if not isinstance(entry, dict):
                changed = True
                continue
            normalized_entry = self._normalize_blacklist_entry(entry)
            if not normalized_entry:
                changed = True
                continue
            if not normalized_entry.get("permanent"):
                blocked_until = self._safe_int(normalized_entry.get("blocked_until"), 0)
                if blocked_until > 0 and blocked_until <= now:
                    self._set_post_unban_score(normalized_entry, now)
                    changed = True
                    continue
            normalized.append(normalized_entry)
            if normalized_entry != entry:
                changed = True
        if changed:
            self.config["blacklisted_users"] = normalized
            self._save_config()
            self._save_state()

    def _normalize_blacklist_entry(self, entry: dict[str, Any]) -> dict[str, Any] | None:
        user_key = str(entry.get("user_key", "") or "").strip()
        platform = str(entry.get("platform", "") or "").strip()
        user_id = str(entry.get("user_id", "") or "").strip()
        group_id = str(entry.get("group_id", "") or "").strip()
        ban_scope = str(entry.get("ban_scope", "") or "").strip().lower()

        if not user_key:
            if platform and user_id and group_id:
                user_key = f"{platform}:{group_id}:{user_id}"
                if not ban_scope:
                    ban_scope = "group"
            elif platform and user_id:
                user_key = f"{platform}:{user_id}"
                if not ban_scope:
                    ban_scope = "global"
            else:
                return None

        parsed = self._parse_user_key(user_key)
        if parsed:
            platform = platform or parsed["platform"]
            group_id = group_id or parsed["group_id"]
            user_id = user_id or parsed["user_id"]
            if not ban_scope:
                ban_scope = "group" if parsed["group_id"] else "global"

        if ban_scope not in {"global", "group", "private"}:
            ban_scope = "group" if group_id else "global"

        normalized = dict(entry)
        normalized.update(
            {
                "user_key": self._compose_user_key(platform, group_id, user_id, ban_scope),
                "legacy_user_key": f"{platform}:{user_id}" if ban_scope == "global" and platform and user_id else "",
                "platform": platform,
                "group_id": group_id,
                "user_id": user_id,
                "ban_scope": ban_scope,
                "blocked_at": self._safe_int(entry.get("blocked_at"), 0),
                "blocked_until": self._safe_int(entry.get("blocked_until"), 0),
                "duration_hours": self._safe_int(entry.get("duration_hours"), 0),
                "strike_count": self._safe_int(entry.get("strike_count"), 1),
                "permanent": self._safe_bool(entry.get("permanent"), False),
                "last_notify_at": self._safe_int(entry.get("last_notify_at"), 0),
                "reason": str(entry.get("reason", "") or ""),
                "categories": str(entry.get("categories", "") or ""),
                "sender_name": str(entry.get("sender_name", "") or ""),
                "recent_hits": entry.get("recent_hits", [])
                if isinstance(entry.get("recent_hits"), list)
                else [],
                "score_key": str(entry.get("score_key", "") or ""),
            }
        )
        if not normalized["score_key"]:
            normalized["score_key"] = self._score_key(
                {
                    "platform": normalized["platform"],
                    "group_id": normalized["group_id"],
                    "user_id": normalized["user_id"],
                }
            )
        return normalized

    def _blacklist_entries(self) -> list[dict[str, Any]]:
        entries = self.config.get("blacklisted_users", [])
        if not isinstance(entries, list):
            self.config["blacklisted_users"] = []
            self._save_config()
            return []
        return entries

    def _upsert_blacklist_entry(self, entry: dict[str, Any]):
        normalized = self._normalize_blacklist_entry(entry)
        if not normalized:
            return
        key = normalized["user_key"]
        entries = [item for item in self._blacklist_entries() if str(item.get("user_key", "")) != key]
        entries.append(normalized)
        self.config["blacklisted_users"] = entries

    def _unban_by_key(self, raw_key: str, now: int) -> list[dict[str, Any]]:
        parsed = self._parse_user_key(raw_key)
        removed: list[dict[str, Any]] = []
        kept: list[dict[str, Any]] = []
        for entry in self._blacklist_entries():
            normalized = self._normalize_blacklist_entry(entry)
            if not normalized:
                continue
            if self._entry_matches_unban_target(normalized, raw_key, parsed):
                removed.append(normalized)
                self._set_post_unban_score(normalized, now)
            else:
                kept.append(normalized)
        if removed:
            self.config["blacklisted_users"] = kept
            self._save_config()
        return removed

    def _entry_matches_unban_target(
        self,
        entry: dict[str, Any],
        raw_key: str,
        parsed: dict[str, str] | None,
    ) -> bool:
        if raw_key == entry.get("user_key"):
            return True
        if not parsed:
            return False
        if entry.get("platform") != parsed["platform"]:
            return False
        if entry.get("user_id") != parsed["user_id"]:
            return False
        scope = str(entry.get("ban_scope", "") or "").lower()
        if parsed["scope"] == "global":
            return scope == "global"
        if parsed["scope"] == "private":
            return scope == "private"
        return scope == "group" and entry.get("group_id", "") == parsed["group_id"]

    def _set_post_unban_score(self, entry: dict[str, Any], now: int):
        score_key = entry.get("score_key") or self._score_key(entry)
        post_score = self._int_cfg("post_unban_score", 4, minimum=0)
        reset_hours = self._hours_cfg("score_reset_hours", 24)
        score_rec = self.state.setdefault("scores", {}).setdefault(score_key, {})
        score_rec.update(
            {
                "score": post_score,
                "updated_at": now,
                "reset_at": now + reset_hours * 3600,
                "user_id": entry.get("user_id", ""),
                "platform": entry.get("platform", ""),
                "group_id": entry.get("group_id", ""),
                "sender_name": entry.get("sender_name", ""),
                "ban_scope": entry.get("ban_scope", "global"),
                "last_hits": entry.get("recent_hits", []),
                "unbanned_at": now,
            }
        )
        self._save_state()

    def _cleanup_scores(self, now: int):
        scores = self.state.setdefault("scores", {})
        expired = []
        for key, rec in list(scores.items()):
            if not isinstance(rec, dict):
                expired.append(key)
                continue
            reset_at = self._safe_int(rec.get("reset_at"), 0)
            if reset_at > 0 and reset_at <= now:
                expired.append(key)
        for key in expired:
            scores.pop(key, None)
        if expired:
            self._save_state()

    def _get_score_record(self, score_key: str, now: int, identity: dict[str, str]) -> dict[str, Any]:
        scores = self.state.setdefault("scores", {})
        rec = scores.setdefault(
            score_key,
            {
                "score": 0,
                "updated_at": now,
                "reset_at": now + self._hours_cfg("score_reset_hours", 24) * 3600,
                "user_id": identity["user_id"],
                "platform": identity["platform"],
                "group_id": identity["group_id"],
                "sender_name": identity["sender_name"],
                "ban_scope": self._ban_scope(identity),
                "last_hits": [],
                "hit_history": [],
            },
        )
        if not isinstance(rec, dict):
            rec = {}
            scores[score_key] = rec
        if self._safe_int(rec.get("reset_at"), 0) <= now:
            rec.clear()
            rec.update(
                {
                    "score": 0,
                    "updated_at": now,
                    "reset_at": now + self._hours_cfg("score_reset_hours", 24) * 3600,
                    "user_id": identity["user_id"],
                    "platform": identity["platform"],
                    "group_id": identity["group_id"],
                    "sender_name": identity["sender_name"],
                    "ban_scope": self._ban_scope(identity),
                    "last_hits": [],
                    "hit_history": [],
                }
            )
        return rec

    def _append_score_hit_history(self, score_rec: dict[str, Any], hits: list[dict[str, Any]], now: int):
        history = score_rec.setdefault("hit_history", [])
        if not isinstance(history, list):
            history = []
            score_rec["hit_history"] = history
        for hit in hits:
            history.append(
                {
                    "word": hit.get("word", ""),
                    "category": hit.get("category", ""),
                    "score": self._safe_int(hit.get("score"), 0),
                    "hit_at": now,
                }
            )
        if len(history) > 20:
            score_rec["hit_history"] = history[-20:]

    def _active_scores(self, now: int) -> list[dict[str, Any]]:
        self._cleanup_scores(now)
        items: list[dict[str, Any]] = []
        for score_key, rec in self.state.get("scores", {}).items():
            if not isinstance(rec, dict):
                continue
            item = dict(rec)
            item["score_key"] = score_key
            reset_at = self._safe_int(item.get("reset_at"), 0)
            item["reset_at_text"] = self._format_time(reset_at)
            item["seconds_to_reset"] = max(0, reset_at - now)
            items.append(item)
        items.sort(key=lambda item: int(item.get("score", 0)), reverse=True)
        return items

    def _render_notice(self, entry: dict[str, Any], event: AstrMessageEvent, now: int) -> str:
        interval_seconds = self._int_cfg("notify_interval_minutes", 10, minimum=0) * 60
        last_notify_at = self._safe_int(entry.get("last_notify_at"), 0)
        if interval_seconds > 0 and last_notify_at and now - last_notify_at < interval_seconds:
            return ""

        entry["last_notify_at"] = now
        self._save_config()

        template = str(self.config.get("blocked_notice", DEFAULT_BLOCKED_NOTICE)).strip()
        if not template:
            template = DEFAULT_BLOCKED_NOTICE
        values = {
            "user_id": entry.get("user_id", self._call_event(event, "get_sender_id")),
            "sender_name": entry.get("sender_name", self._call_event(event, "get_sender_name")),
            "reason": entry.get("reason", ""),
            "duration": "永久" if entry.get("permanent") else f"{entry.get('duration_hours', 0)}小时",
            "until": "永久" if entry.get("permanent") else self._format_time(self._safe_int(entry.get("blocked_until"), 0)),
            "strike_count": entry.get("strike_count", 0),
        }
        try:
            return template.format(**values)
        except Exception:
            return template

    def _event_identity(self, event: AstrMessageEvent) -> dict[str, str]:
        message_obj = getattr(event, "message_obj", None)
        sender = getattr(message_obj, "sender", None)
        is_ai_message = self._is_ai_message_event(event)
        platform = (
            self._call_event(event, "get_platform_id")
            or self._call_event(event, "get_platform_name")
            or getattr(message_obj, "platform", "")
            or "unknown"
        )
        if is_ai_message:
            assistant_scope = (
                self._call_event(event, "get_session_id")
                or getattr(message_obj, "session_id", "")
                or self._call_event(event, "get_sender_id")
                or getattr(sender, "user_id", "")
                or "assistant"
            )
            user_id = f"assistant_{self._safe_identity_part(assistant_scope)}"
        else:
            user_id = (
                self._call_event(event, "get_sender_id")
                or getattr(sender, "user_id", "")
                or self._call_event(event, "get_session_id")
                or getattr(message_obj, "session_id", "")
                or ""
            )
        group_id = self._call_event(event, "get_group_id") or getattr(message_obj, "group_id", "") or ""
        sender_name = (
            self._call_event(event, "get_sender_name")
            or getattr(sender, "nickname", "")
            or ("AI" if is_ai_message else "")
            or user_id
        )
        return {
            "platform": str(platform),
            "user_id": str(user_id),
            "group_id": str(group_id),
            "sender_name": str(sender_name),
        }

    def _base_user_key(self, identity: dict[str, str]) -> str:
        return f"{identity['platform']}:{identity['user_id']}"

    def _safe_identity_part(self, value: Any) -> str:
        text = str(value or "").strip()
        text = re.sub(r"[^0-9A-Za-z_.-]+", "_", text)
        return text[:80] or "assistant"

    def _group_key(self, identity: dict[str, str]) -> str:
        if not identity["group_id"]:
            return ""
        return f"{identity['platform']}:{identity['group_id']}"

    def _strike_key(self, identity: dict[str, str]) -> str:
        return self._base_user_key(identity)

    def _score_key(self, identity: dict[str, str]) -> str:
        return self._compose_user_key(
            identity["platform"],
            identity["group_id"],
            identity["user_id"],
            self._ban_scope(identity),
        )

    def _ban_scope(self, identity: dict[str, str] | None = None) -> str:
        configured = str(self.config.get("ban_scope", DEFAULT_BAN_SCOPE)).strip().lower()
        if configured not in {"global", "group", "private"}:
            configured = DEFAULT_BAN_SCOPE
        if not identity:
            return configured
        if configured == "group" and not identity.get("group_id"):
            return "private"
        return configured

    def _compose_user_key(self, platform: str, group_id: str, user_id: str, scope: str) -> str:
        platform = str(platform or "").strip()
        group_id = str(group_id or "").strip()
        user_id = str(user_id or "").strip()
        if not platform or not user_id:
            return ""
        if scope == "group" and group_id:
            return f"{platform}:{group_id}:{user_id}"
        if scope == "private":
            return f"{platform}:private:{user_id}"
        return f"{platform}:{user_id}"

    def _legacy_key(self, identity: dict[str, str]) -> str:
        return f"{identity['platform']}:{identity['user_id']}"

    def _ban_key(self, identity: dict[str, str]) -> str:
        return self._compose_user_key(
            identity["platform"],
            identity["group_id"],
            identity["user_id"],
            self._ban_scope(identity),
        )

    def _ban_key_candidates(self, identity: dict[str, str]) -> set[str]:
        candidates = set()
        if identity["group_id"]:
            candidates.add(
                self._compose_user_key(identity["platform"], identity["group_id"], identity["user_id"], "group")
            )
        else:
            candidates.add(
                self._compose_user_key(identity["platform"], "", identity["user_id"], "private")
            )
        candidates.add(
            self._compose_user_key(identity["platform"], identity["group_id"], identity["user_id"], "global")
        )
        return {item for item in candidates if item}

    def _entry_matches_any_key(self, entry: dict[str, Any], candidates: set[str]) -> bool:
        if not candidates:
            return False
        entry_key = str(entry.get("user_key", "")).strip()
        legacy_key = str(entry.get("legacy_user_key", "")).strip()
        ban_scope = str(entry.get("ban_scope", "") or "").strip().lower()
        if ban_scope in {"group", "private"}:
            return entry_key in candidates
        return entry_key in candidates or legacy_key in candidates

    def _parse_user_key(self, raw_key: str) -> dict[str, str] | None:
        raw = str(raw_key or "").strip()
        parts = [part.strip() for part in raw.split(":") if part.strip()]
        if len(parts) == 2:
            return {"platform": parts[0], "group_id": "", "user_id": parts[1], "scope": "global"}
        if len(parts) == 3:
            if parts[1].lower() == "private":
                return {"platform": parts[0], "group_id": "", "user_id": parts[2], "scope": "private"}
            return {"platform": parts[0], "group_id": parts[1], "user_id": parts[2], "scope": "group"}
        return None

    def _entry_matches_block_target(self, entry: dict[str, Any], candidates: set[str]) -> bool:
        return self._entry_matches_any_key(entry, candidates)

    def _find_blacklist_entry_for_identity(self, identity: dict[str, str], now: int) -> dict[str, Any] | None:
        candidates = self._ban_key_candidates(identity)
        for entry in self._blacklist_entries():
            normalized = self._normalize_blacklist_entry(entry)
            if not normalized:
                continue
            if self._entry_matches_any_key(normalized, candidates):
                if normalized.get("permanent"):
                    return normalized
                blocked_until = self._safe_int(normalized.get("blocked_until"), 0)
                if blocked_until <= 0 or blocked_until > now:
                    return normalized
        return None

    def _format_block_entry(self, entry: dict[str, Any], now: int) -> str:
        scope = str(entry.get("ban_scope", "global"))
        group_id = str(entry.get("group_id", ""))
        until = "永久" if entry.get("permanent") else self._format_time(self._safe_int(entry.get("blocked_until"), 0))
        return (
            f"- {entry.get('user_key')} | 范围={scope}"
            + (f" | 群={group_id}" if group_id else "")
            + f" | 到期={until} | 次数={entry.get('strike_count', 0)} | 分数={self._score_for_entry(entry)}"
            + f" | 最近命中={self._format_hits(entry.get('recent_hits', []))}"
            + f" | 原因={entry.get('reason', '')}"
        )

    def _score_for_entry(self, entry: dict[str, Any]) -> Any:
        score_key = str(entry.get("score_key", "") or "").strip()
        score_rec = self.state.get("scores", {}).get(score_key, {})
        if isinstance(score_rec, dict):
            return score_rec.get("score", 0)
        return entry.get("score", 0)

    def _format_hits(self, hits: Any) -> str:
        if not isinstance(hits, list) or not hits:
            return "无"
        parts = []
        for hit in hits[:5]:
            if not isinstance(hit, dict):
                continue
            parts.append(
                f"{hit.get('word', '')}({hit.get('score', 0)}/{hit.get('category', '') or '未分类'})"
            )
        return "，".join(parts) if parts else "无"

    def _collect_recent_user_messages(self, identity: dict[str, str], count: int) -> list[dict[str, Any]]:
        if count <= 0:
            return []
        user_key = self._base_user_key(identity)
        history = list(self._recent_user_messages.get(user_key, []))
        if not history:
            return []
        return history[-count:]

    def _collect_recent_group_messages(self, identity: dict[str, str], count: int) -> list[dict[str, Any]]:
        if count <= 0:
            return []
        group_key = self._group_key(identity)
        if not group_key:
            return []
        history = list(self._recent_group_messages.get(group_key, []))
        if not history:
            return []
        return history[-count:]

    def _record_history(self, identity: dict[str, str], text: str, event: AstrMessageEvent, now: int):
        user_key = self._base_user_key(identity)
        group_key = self._group_key(identity)
        item = {
            "ts": now,
            "user_id": identity["user_id"],
            "sender_name": identity["sender_name"],
            "group_id": identity["group_id"],
            "text": self._truncate_text(text, 1000),
        }
        self._recent_user_messages[user_key].append(item)
        if group_key:
            self._recent_group_messages[group_key].append(
                {
                    "ts": now,
                    "user_id": identity["user_id"],
                    "sender_name": identity["sender_name"],
                    "text": self._truncate_text(text, 1000),
                }
            )

    def _call_event(self, event: AstrMessageEvent, method_name: str) -> Any:
        method = getattr(event, method_name, None)
        if not callable(method):
            return ""
        try:
            return method()
        except Exception:
            return ""

    def _is_admin_event(self, event: AstrMessageEvent) -> bool:
        checker = getattr(event, "is_admin", None)
        if callable(checker):
            try:
                return bool(checker())
            except Exception:
                return False
        role = getattr(event, "role", "")
        return str(role).lower() in {"admin", "administrator", "owner"}

    def _join_categories(self, categories: Any) -> str:
        if isinstance(categories, list):
            return ", ".join(str(item) for item in categories if str(item).strip())
        return str(categories or "")

    def _format_time(self, ts: int) -> str:
        if not ts:
            return ""
        return time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(ts))

    def _truncate_text(self, text: str, limit: int) -> str:
        value = str(text or "")
        if limit <= 0 or len(value) <= limit:
            return value
        return value[: max(0, limit - 3)] + "..."

    def _save_config(self):
        try:
            save_config = getattr(self.config, "save_config", None)
            if callable(save_config):
                save_config()
        except Exception as exc:
            logger.warning("%s config save failed: %s", PLUGIN_NAME, exc)

    def _int_cfg(self, key: str, default: int, minimum: int | None = None) -> int:
        try:
            value = int(float(self.config.get(key, default)))
        except Exception:
            value = default
        if minimum is not None:
            value = max(minimum, value)
        return value

    def _float_cfg(self, key: str, default: float, minimum: float | None = None) -> float:
        try:
            value = float(self.config.get(key, default))
        except Exception:
            value = float(default)
        if minimum is not None:
            value = max(minimum, value)
        return value

    def _hours_cfg(self, key: str, default: int) -> int:
        return self._int_cfg(key, default, minimum=0)

    def _bool_cfg(self, key: str, default: bool) -> bool:
        value = self.config.get(key, default)
        if isinstance(value, str):
            return value.strip().lower() in {"1", "true", "yes", "on", "y"}
        return bool(value)

    def _safe_int(self, value: Any, default: int) -> int:
        try:
            return int(float(value))
        except Exception:
            return default

    def _safe_bool(self, value: Any, default: bool) -> bool:
        if isinstance(value, bool):
            return value
        if isinstance(value, (int, float)):
            return value != 0
        if isinstance(value, str):
            lowered = value.strip().lower()
            if lowered in {"1", "true", "yes", "on", "y"}:
                return True
            if lowered in {"0", "false", "no", "off", "n"}:
                return False
        return default
