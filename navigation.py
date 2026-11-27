from collections import OrderedDict
from contextvars import ContextVar
from copy import deepcopy
from dataclasses import dataclass
from functools import wraps
import re
import secrets

from telegram import InlineKeyboardButton, InlineKeyboardMarkup
from telegram.ext import ExtBot

BACK = "nav:back"
MAIN = "nav:main"
NAV_ROW = (InlineKeyboardButton("⬅️ مرحلهٔ قبل", callback_data=BACK),
           InlineKeyboardButton("🏠 منوی اصلی", callback_data=MAIN))
NONCE_KEYS = {"nonce", "token", "servers_token", "picker"}
SENSITIVE_KEYS = {"client", "expiry_job", "password", "root_pass", "_ssh_key", "client_id", "document", "rows", "confirmation"}
ACTION_NONCE = re.compile(r"(?<=:)[0-9a-f]{12,16}(?=:|$)")
MAX_DEPTH = 16
MAX_CHATS = 128
CURRENT = ContextVar("navigation_scope", default=None)
HISTORY = OrderedDict()


@dataclass
class Page:
    text: str
    markup: InlineKeyboardMarkup | None
    state: dict

    def key(self):
        return comparable(self.state), tuple(
            (button.text, ACTION_NONCE.sub("", button.callback_data))
            for row in (self.markup.inline_keyboard if self.markup else ())
            for button in row if isinstance(button.callback_data, str)
        )


@dataclass
class Visit:
    frames: list
    on_page: bool = False


@dataclass
class Scope:
    chat_id: int
    state: dict
    candidate: Page | None = None
    active: bool = True


def with_navigation(markup=None):
    if markup is not None and not isinstance(markup, InlineKeyboardMarkup):
        return markup
    rows = markup.inline_keyboard if markup else ()
    rows = [
        tuple(button for button in row if button.callback_data not in (BACK, MAIN))
        for row in rows
    ]
    return InlineKeyboardMarkup([*(row for row in rows if row), NAV_ROW])


def comparable(value):
    if isinstance(value, dict):
        return {key: comparable(child) for key, child in value.items() if key not in NONCE_KEYS}
    if isinstance(value, (list, tuple)):
        return tuple(comparable(item) for item in value)
    return value


def safe_state(value, budget):
    budget[0] -= 1
    if budget[0] < 0:
        return False
    if isinstance(value, dict):
        for key, child in value.items():
            if key in SENSITIVE_KEYS:
                return False
            if key == "step" and isinstance(child, str) and ("confirm" in child or child.endswith("review")):
                return False
            if not safe_state(child, budget):
                return False
        return True
    if isinstance(value, (tuple, list)):
        return all(safe_state(item, budget) for item in value)
    if isinstance(value, str):
        budget[0] -= len(value) // 128
        return budget[0] >= 0
    return value is None or type(value) in (bool, int, float)


def safe_keyboard(markup):
    if markup is None:
        return True
    if not isinstance(markup, InlineKeyboardMarkup):
        return False
    for row in markup.inline_keyboard:
        for button in row:
            data = button.callback_data
            if button.copy_text or (isinstance(data, str) and (
                {"confirm", "make", "apply", "rot_confirm", "rot_remove", "revoke", "keep", "auto"} & set(data.split(":"))
            )):
                return False
    return True


def remember(chat_id, text, markup, kwargs):
    scope = CURRENT.get()
    if not scope or not scope.active or scope.chat_id != chat_id:
        return
    # Do not replay command output, certificates, passwords or confirmation screens.
    if kwargs.get("protect_content") or kwargs.get("parse_mode") or kwargs.get("entities") or not safe_keyboard(markup):
        scope.candidate = None
        return
    if not scope.state and not markup:
        return
    if not safe_state(scope.state, [16000]):
        scope.candidate = None
        return
    scope.candidate = Page(text, markup, deepcopy(scope.state))


def reset(chat_id=None):
    if chat_id is None:
        HISTORY.clear()
    else:
        HISTORY.pop(chat_id, None)


def track(callback, can_navigate):
    @wraps(callback)
    async def wrapped(update, context):
        chat = update.effective_chat
        if not chat or chat.type != "private" or not can_navigate(chat.id):
            return await callback(update, context)
        scope = Scope(chat.id, context.user_data)
        token = CURRENT.set(scope)
        try:
            return await callback(update, context)
        finally:
            scope.active = False
            CURRENT.reset(token)
            page = scope.candidate
            visit = HISTORY.get(chat.id)
            if page and page.state == scope.state:
                if visit is None:
                    visit = Visit([])
                    HISTORY[chat.id] = visit
                if not visit.frames or page.key() != visit.frames[-1].key():
                    visit.frames.append(page)
                    del visit.frames[:-MAX_DEPTH]
                elif page.markup:
                    visit.frames[-1] = page
                visit.on_page = True
                HISTORY.move_to_end(chat.id)
                if len(HISTORY) > MAX_CHATS:
                    HISTORY.popitem(last=False)
            elif visit:
                visit.on_page = False
    return wrapped


def previous(chat_id):
    visit = HISTORY.get(chat_id)
    if not visit:
        return None
    if visit.on_page and visit.frames:
        visit.frames.pop()
    if not visit.frames:
        reset(chat_id)
        return None
    visit.on_page = True
    return visit.frames[-1]


def reissue(page, bot):
    state = deepcopy(page.state)
    replacements = {}

    def renew(value):
        if isinstance(value, dict):
            for key, item in value.items():
                if key in NONCE_KEYS and isinstance(item, str) and re.fullmatch("[0-9a-f]{12,16}", item):
                    value[key] = replacements.setdefault(item, secrets.token_hex(len(item) // 2))
                else:
                    renew(item)
        elif isinstance(value, (tuple, list)):
            for item in value:
                renew(item)

    renew(state)
    markup = page.markup
    if markup and replacements:
        data = markup.to_dict()
        for row in data["inline_keyboard"]:
            for button in row:
                action = button.get("callback_data")
                if isinstance(action, str):
                    button["callback_data"] = ":".join(replacements.get(part, part) for part in action.split(":"))
        markup = InlineKeyboardMarkup.de_json(data, bot)
    return state, markup


class NavigationBot(ExtBot):
    __slots__ = ("can_navigate",)

    def __init__(self, token, can_navigate):
        super().__init__(token)
        object.__setattr__(self, "can_navigate", can_navigate)

    def navigation_enabled(self, chat_id):
        return type(chat_id) is int and chat_id > 0 and self.can_navigate(chat_id)

    async def send_message(self, chat_id, text, **kwargs):
        enabled = self.navigation_enabled(chat_id)
        original = kwargs.get("reply_markup")
        if enabled:
            kwargs["reply_markup"] = with_navigation(original)
        result = await super().send_message(chat_id, text, **kwargs)
        if enabled:
            remember(chat_id, text, original, kwargs)
        return result

    async def edit_message_text(self, text, chat_id=None, message_id=None, **kwargs):
        enabled = self.navigation_enabled(chat_id)
        original = kwargs.get("reply_markup")
        if enabled:
            kwargs["reply_markup"] = with_navigation(original)
        result = await super().edit_message_text(text, chat_id=chat_id, message_id=message_id, **kwargs)
        if enabled:
            remember(chat_id, text, original, kwargs)
        return result

    async def send_document(self, chat_id, document, **kwargs):
        if self.navigation_enabled(chat_id):
            scope = CURRENT.get()
            if scope and scope.active and scope.chat_id == chat_id:
                scope.candidate = None
            kwargs["reply_markup"] = with_navigation(kwargs.get("reply_markup"))
        return await super().send_document(chat_id, document, **kwargs)
