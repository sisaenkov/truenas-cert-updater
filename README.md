Based on https://github.com/mcao2/truenas-cert-updater

# upload_local_cert.py — загрузка локального сертификата в TrueNAS 25.x

Скрипт сделан на основе `renew_update_cert.py`, но без Tailscale. Он читает уже готовые PEM-файлы сертификата и ключа и загружает их в TrueNAS. Запускать можно с любой машины, у которой есть доступ к API.

Протестирован на мок-API, на живом TrueNAS 25.10 пока не запускался.

## Что делает

1. Читает `cert_file_path` и `key_file_path`. Если установлен пакет `cryptography`, проверяет, что ключ подходит к сертификату.
2. Проверяет связь с API (`/system/state`) и пишет в лог версию TrueNAS.
3. Сравнивает leaf-сертификат с тем, что сейчас стоит на UI. Если они совпадают, выходит с кодом 0 и ничего не меняет, поэтому его можно часто запускать из cron.
4. Импортирует сертификат под именем `<prefix>_YYYYMMDD_HHMMSS` и ждёт завершения job через `/core/get_jobs`. Если такой же сертификат уже был импортирован раньше (например, прошлый запуск упал на середине), повторно его не загружает, а берёт существующий.
5. Назначает его сертификатом UI (`PUT /system/general`) и перезапускает UI.
6. Удаляет предыдущий UI-сертификат, но только если его имя начинается с того же `prefix`. Поэтому `truenas_default` и сертификаты, загруженные руками, не трогаются. Удаление повторяется несколько раз, пока nginx перезапускается.

## Что изменено относительно оригинала

| | `update_cert.py` (старый) | `renew_update_cert.py` (новый) | `upload_local_cert.py` |
|---|---|---|---|
| Источник сертификата | локальные файлы | `tailscale cert` в docker | локальные файлы |
| Ожидание job импорта | `sleep 3` | поиск по имени | `core/get_jobs` с запасным поиском по имени |
| Определение текущего UI-сертификата | — | первый из `ui_certificate_choices` (неточно) | `system/general.ui_certificate` |
| Блок `ixCertificates`/`ingress` приложений (ломается на 24.10+) | есть | нет | нет |
| Удаляется | все прочие UI-сертификаты | предыдущий UI-сертификат | предыдущий UI-сертификат с тем же префиксом |
| Зависимости | requests | requests, PyYAML, docker | requests (PyYAML для YAML, cryptography по желанию) |

## Установка

```bash
pip install requests pyyaml cryptography   # pyyaml и cryptography — опционально
```

## Конфиг

YAML (`.config.yaml` рядом со скриптом):

```yaml
api_base_url: "https://nas.example.lan/api/v2.0"
api_key: "<API_KEY>"
cert_file_path: "/etc/letsencrypt/live/nas.example.lan/fullchain.pem"
key_file_path: "/etc/letsencrypt/live/nas.example.lan/privkey.pem"
# опционально
certificate_name_prefix: "cert"     # по умолчанию cert
verify_ssl: false                   # true / false / путь к CA bundle
delete_old: true                    # удалять предыдущий UI-сертификат
delete_only_prefixed: true          # ...только если его имя начинается с prefix
force: false                        # загрузить, даже если такой уже стоит
```

Старый `.config.json` продолжает работать без изменений:

```json
{
  "API_BASE_URL": "https://nas.example.lan/api/v2.0",
  "API_KEY": "<API_KEY>",
  "CERT_FILE_PATH": "/path/fullchain.pem",
  "CERT_KEY_PATH": "/path/privkey.pem",
  "CERT_NAME_PREFIX": "cert"
}
```

Путь к конфигу выбирается в таком порядке: первый аргумент командной строки, затем `$TRUENAS_CERT_CONFIG`, затем `.config.yaml`, `.config.yml` или `.config.json` рядом со скриптом. Относительные пути к PEM-файлам отсчитываются от папки конфига.

## Запуск

```bash
python3 upload_local_cert.py /path/to/.config.yaml
```

Пример для cron или хука certbot:

```bash
certbot renew --deploy-hook "python3 /opt/truenas-cert-updater/upload_local_cert.py /opt/truenas-cert-updater/.config.yaml"
```

Коды выхода: `0` — успех или ничего не нужно было делать, `1` — ошибка (текст ошибки пишется в лог).

## Важно для TrueNAS 25.x

- **Используйте HTTPS.** Начиная с 25.04, если API-ключ передаётся по plain HTTP, TrueNAS автоматически отзывает его.
- Ключ должен принадлежать пользователю с правами на `certificate` и `system.general`. Проще всего завести ключ для admin.
- REST API (`/api/v2.0`) в 25.x объявлен устаревшим, iX планируют убрать его в одном из следующих релизов. Пока он работает, но в будущем скрипт придётся переводить на WebSocket/JSON-RPC (`/api/current`, библиотека `truenas_api_client`).
- `verify_ssl: false` удобно при первом запуске, когда на NAS стоит самоподписанный сертификат. После того как поставлен нормальный сертификат, лучше включить `true`.
