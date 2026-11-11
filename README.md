# Multi-Exit Relay

Проброс **TCP и UDP** с российского Relay на любое число Exit-серверов. Relay только пересылает пакеты: DNAT, FORWARD и отдельный MASQUERADE на адрес и порт Exit. Он не ставит Xray, 3X-UI, HAProxy и Docker и не меняет SNI.

Так можно вывести наружу все входы узла, а не только TCP 443/8443. Пример набора Sakura: VLESS Reality `443/tcp`, XHTTP Reality `8443/tcp`, Hysteria2 `443/udp`, VLESS gRPC `4443/tcp`, Trojan gRPC `6443/tcp`.

Правила живут в собственных цепочках `MEX_PREROUTING` (nat), `MEX_POSTROUTING` (nat) и `MEX_FORWARD` (filter). Переход из системных цепочек добавляется один раз. Каждое правило помечено комментарием `mex:<id>`. Чужие правила, политика INPUT/FORWARD, правила SSH и UFW не изменяются и не отключаются. Слушать TCP 22 на Relay нельзя: DNAT перехватил бы SSH.

## Схема конфигурации v2

Файл: `/etc/multi-exit-relay/config.json`.

```json
{
  "version": 2,
  "exits": [
    {
      "id": "de-1",
      "name": "Германия",
      "host": "203.0.113.10",
      "forwards": [
        {"proto": "tcp", "listen": 443, "target": 443},
        {"proto": "tcp", "listen": 8443, "target": 8443},
        {"proto": "udp", "listen": 443, "target": 443},
        {"proto": "tcp", "listen": 4443, "target": 4443},
        {"proto": "tcp", "listen": 6443, "target": 6443}
      ]
    }
  ]
}
```

| Поле | Смысл |
| --- | --- |
| `version` | Всегда `2` для новой схемы. Файл v1 читается и при `relay apply` переписывается в v2. |
| `exits[].id` | Slug: буква или цифра, дальше буквы, цифры, `.`, `_`, `-`, до 64 символов. Попадает в комментарий `mex:<id>`. Нельзя `tcpmss` и `related-icmp`. |
| `exits[].name` | Подпись до 64 символов, без кавычек, `\`, `|` и управляющих символов. |
| `exits[].host` | IPv4 или DNS-имя (ASCII, punycode). |
| `forwards[].proto` | `tcp` или `udp`. |
| `forwards[].listen` | Порт на Relay, число 1–65535. |
| `forwards[].target` | Порт на Exit, число 1–65535. |

Один и тот же `listen` можно занять отдельно для TCP и для UDP. Два проброса с одной парой `proto`+`listen` — ошибка. Дополнительные поля (`public_ip`, `egress_interface`, `created_at`, `next_seq`, `status`) сохраняются и на проброс не влияют.

Если `host` — имя, `relay apply` берёт A-записи. Если среди них ещё есть адрес, на который уже смотрят правила, он остаётся. Иначе берётся первый IPv4. Повторный разбор делает служба `multi-exit-relay.service` при загрузке и таймер `multi-exit-relay-resolve.timer` каждые 5 минут (снова `relay apply`). Если DNS молчит, а адрес этого же имени уже сохранён, правила не снимаются: в проверке будет предупреждение `resolve_stale`.

## Требования

- Ubuntu 22.04 или 24.04
- публичный IPv4
- root
- `iptables` с backend iptables-nft
- `netfilter-persistent` (пакет `iptables-persistent`; неинтерактивная установка ставит его сама)
- Bash 5+, `jq`, `iproute2`, `curl`

## Установка

Не запускайте скачанный из интернета скрипт, не просмотрев его.

```bash
git clone https://github.com/vpnmda/multi-exit-relay.git
cd multi-exit-relay
less install.sh
sudo bash install.sh
```

Без вопросов, для панели или SSH:

```bash
sudo bash install.sh --non-interactive
```

Команда идемпотентна: ставит пакеты (`jq`, `iptables`, `iproute2`, `curl`, `iptables-persistent` и зависимости), копирует программу в `/opt/multi-exit-relay`, включает `net.ipv4.ip_forward`, создаёт пустой v2-конфиг, если его ещё нет, ставит команды и включает службу и таймер. Чужой `config.json` не затирается. Если в нём уже есть пробросы, правила применяются сразу. Повторный запуск безопасен.

Если рядом со скриптом нет каталога `lib/`, установщик клонирует репозиторий в `/opt/multi-exit-relay` и перезапускает себя оттуда.

Команды: `/usr/local/bin/multi-exit-relay` и, если `/usr/local/bin/relay` свободен или уже наш, `/usr/local/bin/relay`.

Интерактивное меню по-прежнему работает и пишет ту же схему v2. Пункты «Добавить Exit» и `relay add` создают пару TCP: внешний порт Relay → `host:443` и второй → `host:8443`. Произвольные порты и UDP задаются в `config.json`.

## Integration with a bot admin panel

Панель Sakura ставит Relay один раз и дальше правит только файл конфигурации.

```bash
sudo bash install.sh --non-interactive
```

Дальше по SSH панель записывает `/etc/multi-exit-relay/config.json` и вызывает ровно эти команды:

```bash
sudo relay apply
sudo relay check --json
```

Эквивалент, если файл лежит не в штатном пути (его содержимое копируется в штатный `config.json` и применяется):

```bash
sudo relay apply --config /path/to/config.json
```

Удаление Exit — это удаление объекта из `exits` и снова `relay apply`. Неизменённые пробросы не удаляются и не создаются заново, счётчики iptables у них не сбрасываются. Смена `host` или порта: новое правило добавляется, затем снимается старое.

Машиночитаемый вывод (`--json`) — только stdout, один JSON-документ. Журнал и ошибки — stderr. Коды `error` и `problems[].code` стабильны. Поле `message` — текст для человека, на него опираться не нужно.

### Коды выхода

| Код | Смысл |
| --- | --- |
| 0 | Успех. Для `status`/`check` это ещё и «проблем нет». |
| 1 | Неверные аргументы. |
| 2 | Конфигурация отсутствует или не принята (`config_missing`, `config_invalid`, `config_collision`, `listen_reserved`, `host_is_local`). Правила не менялись. |
| 3 | Не удалось применить: DNS без кэша, занятый локальный порт, чужой DNAT, ошибка iptables, пакеты, права (`resolve_failed`, `listen_busy`, `listen_foreign_dnat`, `apply_failed`, `dependency`, `permission`, `unsupported_os`). |
| 4 | Отчёт построен, но есть проблемы: нет правила, TCP до Exit не открылся, выключен `ip_forward`, нет своей цепочки или перехода. |
| 5 | Не дождались блокировки 60 секунд (`lock_busy`). |

`relay apply` без `--json` ничего не печатает на stdout: ход работы идёт в stderr, результат — код выхода. С `--json` на stdout документ ниже.

`relay status` без `--json` печатает короткий текст и не открывает TCP. Код 0, если файл читается, и 2, если его нет или он сломан. `relay status --json` и `relay check` (с `--json` и без) делают полную проверку, включая TCP-подключение, и возвращают 0 или 4.

### `relay version --json`

```json
{
  "ok": true,
  "name": "multi-exit-relay",
  "version": "2.0.0"
}
```

Без `--json` строка `multi-exit-relay 2.0.0`.

### `relay apply --json`

```json
{
  "ok": true,
  "command": "apply",
  "version": "2.0.0",
  "config_file": "/etc/multi-exit-relay/config.json",
  "config_version": 2,
  "exits": 1,
  "forwards": 5,
  "rules_added": 26,
  "rules_removed": 0,
  "rules_unchanged": 0
}
```

Повторный apply тех же пробросов: `rules_added` и `rules_removed` равны 0.

Ошибка, stdout:

```json
{
  "ok": false,
  "command": "apply",
  "error": "config_collision",
  "message": "текст для человека",
  "version": "2.0.0",
  "config_file": "/etc/multi-exit-relay/config.json",
  "problems": [
    {"code": "config_collision", "message": "текст для человека"}
  ]
}
```

### `relay check --json` и `relay status --json`

Один и тот же документ. Отличается поле `command`: `check` или `status`.

```json
{
  "ok": true,
  "command": "check",
  "version": "2.0.0",
  "config_version": 2,
  "config_file": "/etc/multi-exit-relay/config.json",
  "public_ip": "203.0.113.5",
  "egress_interface": "eth0",
  "ip_forward": 1,
  "tcpmss": true,
  "chains": {
    "MEX_PREROUTING": true,
    "MEX_POSTROUTING": true,
    "MEX_FORWARD": true
  },
  "jumps": {
    "PREROUTING": true,
    "POSTROUTING": true,
    "FORWARD": true
  },
  "forward_policy": "ACCEPT",
  "netfilter_persistent": "enabled",
  "ufw_active": false,
  "problems": [],
  "warnings": [],
  "exits": [
    {
      "id": "de-1",
      "name": "Германия",
      "host": "exit.example.com",
      "resolved_ip": "203.0.113.10",
      "resolve_stale": false,
      "ok": true,
      "forwards": [
        {
          "proto": "tcp",
          "listen": 443,
          "target": 443,
          "rule_present": true,
          "dnat": true,
          "forward": true,
          "masquerade": true,
          "reachable": true,
          "reachability": "ok",
          "packets": 12,
          "bytes": 3456
        },
        {
          "proto": "udp",
          "listen": 443,
          "target": 443,
          "rule_present": true,
          "dnat": true,
          "forward": true,
          "masquerade": true,
          "reachable": null,
          "reachability": "not_checkable",
          "packets": 4,
          "bytes": 800
        }
      ]
    }
  ]
}
```

`reachable` для TCP — `true` или `false` (соединение с Relay на `resolved_ip:target`, таймаут 3 секунды на проброс). Для UDP всегда `null`, `reachability` равен `not_checkable`: рабочей проверки Hysteria2/QUIC нет, и из-за UDP код 4 не ставится. `packets` и `bytes` — счётчики DNAT, либо `null`, если их нет. `rule_present` истинен, только если на месте DNAT, FORWARD и MASQUERADE.

Проблема не роняет весь документ. `ok` становится `false`, код выхода 4, в `problems` стабильные коды:

| `code` | Когда |
| --- | --- |
| `rule_missing` | Нет DNAT, FORWARD или MASQUERADE этого проброса. |
| `tcp_unreachable` | TCP до `resolved_ip:target` не открылся. |
| `resolve_failed` | Имени нет ни в DNS, ни в сохранённом адресе, ни в правиле. |
| `ip_forward_disabled` | `net.ipv4.ip_forward` не 1, а пробросы есть. |
| `chain_missing` | Нет своей цепочки. Поле `chain`. |
| `jump_missing` | Нет перехода в свою цепочку. Поле `chain`: `PREROUTING`, `POSTROUTING` или `FORWARD`. |

Предупреждения не меняют код выхода: `resolve_stale` (DNS молчал, оставлен прежний адрес), `tcpmss_missing` (ядро без цели TCPMSS, только если есть TCP-проброс).

`netfilter_persistent`: `enabled`, `disabled`, `static`, `not_installed`, `unknown` или `dry_run`.

Если файла нет или он сломан, код 2 и короткий документ: `ok: false`, `error` равен `config_missing` или `config_invalid`.

Проверка порта — не проверка REALITY, VLESS, Hysteria2 или пароля. `relay apply` не требует, чтобы порт Exit уже был открыт: правила ставятся в любом случае, а `relay check` покажет `tcp_unreachable`.

## Меню и команда `relay add`

Меню:

1. Установить новый Relay
2. Добавить Exit
3. Удалить Exit
4. Показать конфигурацию
5. Проверить соединения
6. Проверить NAT и файрвол
7. Сохранить конфигурацию
8. Восстановить конфигурацию
9. Удалить установку
10. Выход
11. Изменить IP Exit (порты сохраняются)

```bash
sudo relay add --name Германия --ip 203.0.113.10
sudo relay add --name Германия --ip 203.0.113.10 --relay-port-443 443 --relay-port-8443 8443
```

Для этой пары порты Exit всегда 443 и 8443. Внешние порты по умолчанию: `443/8443`, затем `10443/18443`, `20443/28443` и далее по формуле `443+(N-1)*10000` и `8443+(N-1)*10000`. Занятый слот пропускается. Порт 22 не назначается. Перед записью проверяется маршрут и TCP до обоих портов Exit. Это только открытый TCP-порт. Закрытый порт останавливает добавление; `--force` помечает Exit как принудительный и всё равно записывает правила.

## Ссылка для клиента

Адрес в ссылке — публичный IP Relay, порт — `listen` нужного проброса. Для Hysteria2 это UDP-порт Relay. SNI, ключи и пароль не меняются.

## Проверка с терминала

```bash
sudo relay list
sudo relay status
sudo relay check
```

Текст `relay check` — таблица по каждому пробросу. Колонка доступности для UDP говорит, что проверка соединения не выполняется.

После установки включены `net.ipv4.ip_forward=1` (`/etc/sysctl.d/99-multi-exit-relay.conf`), сохранение `netfilter-persistent`, служба `multi-exit-relay.service` и таймер резолва. Каталог `/etc/multi-exit-relay/`: `config.json`, `state.json` (выбранные адреса имён), `backups/`, `logs/`. Запись конфига атомарная.

На каждый проброс: DNAT `listen` → `resolved_ip:target`, MASQUERADE только на этот адрес и порт, FORWARD для NEW и для ESTABLISHED,RELATED в обе стороны. Общей MASQUERADE нет. Для UDP возврат идёт через conntrack так же, как для TCP. Пока есть хотя бы один проброс, в `MEX_FORWARD` есть одно правило RELATED ICMP (`mex:related-icmp`), чтобы ошибки PMTU для QUIC не отбрасывались. Один раз в mangle/FORWARD добавляется `TCPMSS --clamp-mss-to-pmtu` (`mex:tcpmss`), если ядро умеет эту цель.

## Удаление

Один Exit из меню или:

```bash
sudo relay remove --id de-1 --yes
```

Снимаются только правила с комментарием этого Exit. Для панели надёжнее убрать объект из JSON и вызвать `relay apply`.

Полное удаление:

```bash
sudo bash uninstall.sh --yes --purge-config
sudo relay uninstall --yes --purge-config
```

Удаляются свои цепочки и переходы, TCPMSS, правило ICMP, файл sysctl (если в нём нет посторонних строк), служба, таймер и свои ссылки команд. `ip_forward` в 0 не сбрасывается. Без `--purge-config` `config.json` сохраняется. Резервные копии остаются. Каталог `/opt/multi-exit-relay` эта команда не удаляет.

## Резервная копия и восстановление

```bash
sudo relay backup
sudo relay restore --backup /etc/multi-exit-relay/backups/КАТАЛОГ --yes
```

Восстановление заново собирает правила из сохранённого `config.json`. Снимок `iptables.v4` в ядро не заливается.

## Устранение неполадок

**Сайты не открываются, а сам Relay доступен.** Смотрите маршруты и outbound на Exit. Relay только пересылает.

**UFW включён.** Его не нужно выключать. Своя цепочка стоит в начале FORWARD и принимает только трафик настроенных Exit.

**Крупные сайты обрываются.** Проверьте `mex:tcpmss`. Если ядро без TCPMSS, проброс работает, MSS не зажимается; `check` даст предупреждение `tcpmss_missing`, не код 4.

**После перезагрузки правил нет.** Должны быть включены `netfilter-persistent` и `multi-exit-relay.service`. Повторить: `sudo relay apply`.

**Имя Exit сменило адрес не сразу.** Таймер ходит раз в 5 минут. Сразу: `sudo relay apply`.

**Порт занят.** `relay apply` вернёт код 3 (`listen_busy` или `listen_foreign_dnat`) и не тронет уже стоящие правила.

## Команды

```text
relay status [--json]
relay list
relay check [--json]
relay backup
relay restore --backup КАТАЛОГ [--yes]
relay add --name ИМЯ --ip IP [--relay-port-443 N --relay-port-8443 M] [--force]
relay remove --id ID [--yes]
relay change-ip --id ID --ip IP [--force] [--yes]
relay apply [--config FILE] [--json]
relay uninstall [--yes] [--purge-config]
relay version [--json]
relay help
```

`MEX_DRY_RUN=1` гоняет iptables через встроенный симулятор. `MEX_IPTABLES` подменяет двоичный файл.

## Что проверялось

`bash -n`, shellcheck, разбор адресов и схемы v1/v2, сборка правил в dry-run (UDP, произвольные порты, несколько Exit, повторный apply, удаление Exit из файла, липкий DNS и смена A-записи, JSON и коды выхода, `install.sh --non-interactive`) и сквозной тест в сетевых пространствах имён: клиент → relay → два Exit, TCP и UDP, в том числе возврат UDP через conntrack и MASQUERADE, смена адреса по имени, повторный apply без сброса счётчика DNAT.

На ядре без TCPMSS реальное правило `--clamp-mss-to-pmtu` не ставится; установщик пишет предупреждение.

```bash
bash tests/run-all.sh
```

## Ограничения

- Только IPv4. AAAA не используется.
- Доступность UDP не проверяется активным запросом.
- Таймауты conntrack UDP остаются ядерными (поток часто около 120 секунд). Долгая пауза QUIC может потребовать отдельной настройки хоста; этот пакет глобальные таймауты conntrack не меняет.
- Пока таймер не сработал, смена DNS видна не дольше чем через 5 минут. Выбирается один IPv4.
- Имя хоста — ASCII или punycode.
- У iptables нет общей транзакции на чужие таблицы. Для изменённого проброса новое правило ставится раньше, чем удаляется старое. Обрыв процесса между этими шагами оставляет оба до следующего `relay apply`. Неизменённые пробросы не переписываются.
- `relay check` не проверяет REALITY, VLESS, пароль и сам QUIC.
- Локальный слушатель или чужой DNAT на той же паре протокол/порт отклоняют `relay apply` (код 3), чтобы не перехватывать чужой трафик.

## Состав

```text
install.sh
uninstall.sh
relay
config/example.json
lib/common.sh
lib/validation.sh
lib/resolve.sh
lib/ports.sh
lib/iptables.sh
lib/exits.sh
lib/backup.sh
lib/diagnostics.sh
tests/
```

## Лицензия

MIT. Текст лицензии — в файле [LICENSE](LICENSE).
