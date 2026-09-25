# Vaultwarden Agentic MCP

[English](README.md) · **Русский**

Сервер [Model Context Protocol](https://modelcontextprotocol.io/) для [Vaultwarden](https://github.com/dani-garcia/vaultwarden). Даёт ИИ-агентам аккаунт в хранилище и не пускает значения секретов в контекст модели.

Тулзы возвращают имена, метаданные и отпечатки. Значения доходят до программ через одноразовые ссылки, до людей — через Bitwarden Send, в хранилище — через ссылки загрузки. Вернуть значение модели можно только отдельной тулзой, которая по умолчанию выключена.

Шифрование выполняется в сервере так же, как в официальных клиентах; Vaultwarden хранит только шифротекст.

## Тулзы

| Тулза | Назначение |
|---|---|
| `get_status` | Аккаунт, режим, видимые коллекции, включённые возможности |
| `list_collections` | Коллекции с числом элементов и доступом; в режиме admin — участники |
| `list_items` | Метаданные элементов по коллекции, типу или корзине |
| `search_items` | Поиск по имени, логину, URI, заметкам, именам полей; по значениям не ищет никогда |
| `get_item` | Всё, кроме значений секретов: заметки, поля, вложения, публичный SSH-ключ, отпечатки |
| `find_by_value` | Элементы со значением, которое у агента уже есть (≥ 8 символов, с ограничением частоты) |
| `find_copies` | Другие элементы с тем же секретом |
| `check_items` | Формат заметок, истёкшие и истекающие, пустые, дубликаты, нерасшифровываемые |
| `issue_value_link` | Одноразовый URL, отдающий одно значение или вложение |
| `request_value_upload` | Одноразовый URL, через который человек или программа сохраняет значение или файл |
| `share_with_human` | Ссылка Bitwarden Send на значение |
| `revoke_share` | Удалить ссылку Send, созданную этим клиентом |
| `create_item` | Создать в коллекции; пароль передан, сгенерирован в сервере или загружен |
| `update_item` | Изменить поля; прежний пароль или скрытое поле уходит в историю |
| `delete_item` | В корзину или, где разрешено, насовсем |
| `restore_item` | Восстановить из корзины |
| `add_attachment` | Приложить файл |
| `delete_attachment` | Удалить вложение |
| `get_secret` | Вернуть одно значение модели |
| `get_attachment` | Вернуть вложение модели |
| `list_members` | Admin: участники, роли, доступ к коллекциям |
| `invite_member` | Admin: пригласить с ролью и коллекциями |
| `confirm_member` | Admin: подтвердить после сверки фразы отпечатка |
| `update_member` | Admin: сменить роль или доступ к коллекциям |
| `change_member` | Admin: отозвать, вернуть или удалить |
| `create_collection` | Admin: создать коллекцию |
| `update_collection` | Admin: переименовать или изменить доступ |
| `delete_collection` | Admin: удалить пустую коллекцию |
| `set_item_collections` | Admin: перенести элемент между коллекциями |
| `list_events` | Admin: журнал событий организации |

Тулзы выключенной возможности не регистрируются. У каждой тулзы есть MCP-аннотации (`readOnlyHint`, `destructiveHint`, `openWorldHint`).

## Значения вне контекста

```
issue_value_link(item="CI_TOKEN")        →  curl -s <url> | gh auth login --with-token
request_value_upload(item="API_KEY")     →  человек открывает URL, или: printf %s "$V" | curl -X PUT --data-binary @- <url>
create_item(..., generate_password={})   →  генерируется и сохраняется в сервере, не показывается
share_with_human(item="WIFI", max_access=1)
```

- **Одноразовые ссылки** — 256-битные токены в памяти: одно использование, несколько минут, пропадают при рестарте. При погашении элемент ссылки заново сверяется с коллекциями выдавшего клиента. `VWMCP_LINK_SOURCES` ограничивает адреса, с которых ссылку можно погасить.
- **Загруженные значения** всегда попадают в секретное поле: `password`, `totp`, `ssh_private_key`, скрытое пользовательское поле или текст элемента-заметки.
- **TOTP-сиды** не покидают сервер; `totp` — текущий код.
- **Отпечатки** — HMAC на ключе, выведенном из пользовательского ключа аккаунта: одинаковые значения дают одинаковые отпечатки в пределах аккаунта, а перебрать отпечаток тому, кто видит только его, нельзя.
- Элементы из коллекций со скрытыми паролями и с повторным запросом мастер-пароля значений не отдают.

## Аккаунты, инстансы, клиенты

Один процесс обслуживает один аккаунт Vaultwarden; членство аккаунта — граница того, до чего он дотягивается. Несколько агентов могут делить инстанс со своими bearer-токенами, каждый при желании сужен до чтения или до части коллекций.

`VWMCP_MODE=consumer` работает с элементами. `VWMCP_MODE=admin` добавляет управление организацией и требует аккаунт владельца или администратора.

## Установка

### Требования

- Vaultwarden (проверено на 1.36)
- Аккаунт с персональным API-ключом (Settings → Security → Keys → API key) и его мастер-пароль

### Переменные окружения

| Переменная | Обязательна | По умолчанию | Назначение |
|---|---|---|---|
| `VWMCP_SERVER_URL` | Да | — | URL Vaultwarden |
| `VWMCP_CLIENT_ID` | Да | — | client id API-ключа (`user.<uuid>`) |
| `VWMCP_CLIENT_SECRET` | Да | — | client secret API-ключа |
| `VWMCP_MASTER_PASSWORD` | Да | — | Мастер-пароль |
| `VWMCP_CLIENTS` | Да (http) | — | `name:sha256(token)[:read_only][:collections=a\|b]` через запятую |
| `VWMCP_MODE` | Нет | `consumer` | `consumer` или `admin` |
| `VWMCP_ALLOW_WRITE` | Нет | `false` | Создание, изменение, удаление элементов; изменения в admin |
| `VWMCP_ALLOW_SHARE` | Нет | `false` | `share_with_human` (вместе с write) |
| `VWMCP_ALLOW_REVEAL` | Нет | `false` | `get_secret`, `get_attachment` |
| `VWMCP_ALLOW_PERMANENT_DELETE` | Нет | `false` | Удаление мимо корзины |
| `VWMCP_ALLOW_ADMIN_ROLES` | Нет | `false` | Выдавать и менять роли owner и admin |
| `VWMCP_INVITE_DOMAINS` | Нет | любые | Домены, которые может приглашать `invite_member` |
| `VWMCP_PUBLIC_URL` | Нет | — | Адрес сервера для клиентов; включает одноразовые ссылки |
| `VWMCP_LINK_SOURCES` | Нет | любые | Адреса или CIDR, с которых можно гасить ссылки |
| `VWMCP_NOTES_PREFIXES` | Нет | — | Строки, обязательные в заметках каждого элемента, для `check_items` |
| `VWMCP_TRANSPORT` | Нет | `http` | `http` или `stdio` |
| `VWMCP_LISTEN_ADDR` | Нет | `:8080` | Слушатель `/mcp`, ссылок, `/health`, `/ready`, `/metrics` |

Остальное — таймауты, TTL, лимиты, TLS — перечислено с дефолтами в [`env.example`](env.example). Расширяющие настройки и каждая переменная со значением по умолчанию пишутся в лог при старте.

Токен клиента и его хеш:

```bash
docker run --rm alexfail2/vaultwarden-agentic-mcp token
```

### Запуск в Docker

Образы для `linux/amd64` и `linux/arm64`: [`alexfail2/vaultwarden-agentic-mcp`](https://hub.docker.com/r/alexfail2/vaultwarden-agentic-mcp).

```bash
docker run -d \
  -e VWMCP_SERVER_URL=https://vault.example.com \
  -e VWMCP_CLIENT_ID=user.00000000-0000-0000-0000-000000000000 \
  -e VWMCP_CLIENT_SECRET=... \
  -e VWMCP_MASTER_PASSWORD=... \
  -e VWMCP_CLIENTS=agent:<sha256> \
  -e VWMCP_PUBLIC_URL=http://mcp.example.lan:8080 \
  -p 8080:8080 \
  alexfail2/vaultwarden-agentic-mcp
```

### Сборка из исходников

```bash
git clone https://github.com/Alexander-Zhukov/vaultwarden-agentic-mcp.git
cd vaultwarden-agentic-mcp
make build                   # ./bin/vaultwarden-agentic-mcp
docker build -t vaultwarden-agentic-mcp .
```

## Настройка MCP-клиента

```json
{
  "mcpServers": {
    "secrets": {
      "type": "http",
      "url": "http://mcp.example.lan:8080/mcp",
      "headers": { "Authorization": "Bearer <token>" }
    }
  }
}
```

## Эндпоинты

| Путь | |
|---|---|
| `/mcp` | Streamable HTTP, bearer-токен |
| `/v1/links/{token}`, `/v1/upload/{token}` | Одноразовые ссылки |
| `/health` | Процесс жив |
| `/ready` | Вход выполнен, последняя синхронизация успешна |
| `/metrics` | Prometheus; сроки истечения — счётчиками, без имён элементов |

## Как это работает

Сервер входит по API-ключу аккаунта, выводит мастер-ключ (PBKDF2 или Argon2id) и разворачивает пользовательский, приватный и организационные ключи. Он держит расшифрованный снимок хранилища короткий TTL и синхронизируется заново перед каждой записью; запись несёт дату ревизии элемента, поэтому изменение, сделанное в другом месте, отклоняется, а не затирается. Элементы, вложения и Send шифруются в сервере в тех же форматах, что у официальных клиентов. Расшифровывается только аутентифицированный шифротекст. Подробнее — [`doc/architecture.md`](doc/architecture.md).

## Разработка

```bash
make check-all         # формат, vet, линтеры, tidy, тесты с race и порогом покрытия, govulncheck
make test-integration  # против Vaultwarden в Docker со сверкой через официальный Bitwarden CLI
```

Юнит-тесты гоняют каждую тулзу по HTTP против фейкового сервера в памяти.

Тег `v*` собирает и публикует образ; изменения — в [CHANGELOG.md](CHANGELOG.md).

## Лицензия

[MIT](LICENSE). Словарь фразы отпечатка —
[EFF long word list](https://www.eff.org/dice) (CC BY 3.0 US).
