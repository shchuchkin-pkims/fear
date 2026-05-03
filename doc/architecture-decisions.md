# F.E.A.R. — архитектурные решения для v0.5.x → v0.6.0

Документ — финальные решения после обсуждения. По каждому пункту зафиксировано
**что делаем** и **в каком порядке**. Цель — чтобы каждый последующий коммит
укладывался в общую картину.

Маркеры:
- **★★★** — критично (без этого нельзя двигаться к user-facing фичам)
- **★★** — важно (но можно отложить на пару месяцев)
- **★** — nice-to-have / будущее
- 🔧 — лёгкая реализация (часы–дни)
- 🔧🔧 — средняя (1-2 недели)
- 🔧🔧🔧 — большая (2+ недели, риск ошибок)

Статус-маркеры решений:
- ✅ — решено, делаем
- ⏸ — отложено осознанно
- ❌ — отвергнуто

---

## 0. Откуда стартуем (краткая фотография)

| Что | Сейчас | Куда движемся |
|-----|--------|---------------|
| Сервер | Stateless TCP relay | SQLite + квоты + retention |
| Identity | Ed25519 на инсталляцию, plaintext на диске | Mastodon-handle + EncryptedFile/Storage |
| Контакты | Локальный TOFU-файл | Encrypted blob на сервере + auto-sync |
| История | RAM | Локальный SQLite + serverside inbox |
| Метаданные | `room`, `sender_name` plaintext | Opaque HMAC-производные |
| Ключ комнаты | Один навсегда | K_room + K_epoch иерархия |
| Аутентификация | Опциональная sig | Опциональная sig (mandatory отложено) |
| Бэкап identity | Нет | Encrypted file + QR |
| Auth ECDH | Подпись опциональна | Опциональна (отложено) |
| Push | Только онлайн | FCM с toggle (Phase E) |

---

## 1. Identity ★★★ ✅ РЕШЕНО

**Двухслойная модель (Mastodon + криптография):**

**Слой 1 — Identity (всегда):**
- Ed25519-ключпара, генерится один раз при первом запуске
- `identity_pk` (32 байта) — настоящий «паспорт», основа TOFU-проверок
- `fpshort` = первые 8 байт BLAKE2b(identity_pk) в hex → `a3b9c1d2`
- Полная криптоформа: **`evgenii#a3b9c1d2`** — fallback и cross-server

**Слой 2 — Handle (per-server, опциональный):**
- Mastodon-стиль: **`@username@server`** (`@evgenii@fear-project.ru`)
- Уникален в рамках сервера. Сервер хранит реестр `(handle, identity_pk, claimed_at)`
- На разных серверах `@evgenii` — разные люди (различимы по identity_pk)
- При смене сервера handle перерегистрируется заново

### Структура контакта
```
{
  identity_pk:  <32 bytes>,                  // truth
  fingerprint:  "a3b9c1d2",
  handles: [
    "@bob@fear-project.ru",
    "@bobby@friends.example.com",
  ],
  display_name: "Боб (друг детства)",
  added_at:     1730000000,
  verified:     true,
}
```

### Три способа добавить контакт
1. **QR-код** — сразу всё (identity_pk + актуальный handle)
2. **`@bob@fear-project.ru`** — клиент идёт на сервер, lookup
3. **`bob#a3b9c1d2`** — без сервера, TOFU при первом сообщении

### Решённые подвопросы
- ✅ Handle можно поменять (release старого + claim нового)
- ✅ Если сервер недоступен — graceful degradation на `name#fpshort`
- ⏸ Срок аренды handle (squatting) — для MVP индефинитно

### Сложность
🔧🔧 — серверная команда `register_handle`/`lookup_handle` + БД-таблица + UI

---

## 2. Бэкап identity ★★★ ✅ РЕШЕНО

**Реализуем:** encrypted file + QR-код.

**Encrypted file:**
- Формат: `[magic 4][version 1][argon2id_salt 16][nonce 12][ciphertext + tag]`
- Argon2id (m=64MB, t=3, p=1) → 32-байт ключ → AES-256-GCM
- Содержимое: identity_sk + identity_pk + handles[] + display_name
- Расширение: `.fbk` (FEAR backup)
- Десктоп: file dialog «Экспорт identity»/«Импорт identity»
- Android: SAF (Storage Access Framework) → сохранить в Downloads/Drive

**QR-код:**
- Тот же encrypted blob, base64-encoded → QR (Version 7-10 типично, ~200-300 символов)
- **Генерация:** на обеих платформах
  - Android: `com.journeyapps:zxing-android-embedded`
  - Desktop: `libqrencode` → QImage
- **Сканирование:**
  - Android: камера через ZXing ScanContract
  - Desktop: import из PNG-файла (без камеры) — выбрать файл, декодировать
- При сканировании на новом устройстве запрашивается пароль для расшифровки

**❌ Отвергнуто:** BIP-39 seed phrase (overkill для MVP, добавим позже если будет спрос).
**❌ Отвергнуто:** серверный бэкап за пароль (зависит от качества пароля, лишний attack surface).

### Сложность
🔧 (encrypted file) + 🔧 (QR generation) + 🔧 (QR scan Android) + 🔧 (QR import Desktop). Итого ~5-7 дней.

---

## 3. Список контактов ★★ ✅ РЕШЕНО

**Encrypted blob на сервере + auto-sync.**

- Сервер хранит `(identity_pk, blob, updated_at)`
- Клиент шифрует список контактов под `K_contacts = HKDF(identity_sk, "fear.contacts.v1")`
- Расшифровка только локально (нужен identity_sk)
- **Auto-sync:** debounce 5-10 секунд после любого изменения списка контактов
  - Сервер видит размер blob и время доступа. Содержимое — нет
  - Клиент держит локальную копию, blob на сервере = «source of truth» при подключении нового устройства
- Структура контакта — см. §1

### Сложность
🔧 — после §7 (server-state foundation)

---

## 4. Метаданные на проводе ★★★ ✅ РЕШЕНО

**Делаем после §5.** Заменяем plaintext-поля на opaque:

| Поле | Сейчас | Заменяем на |
|---|---|---|
| `room_name` | "guest" | `room_id = HMAC(K_room, "room-id")` — 16 байт |
| `sender_name` | "Pavel" | `sender_alias = HMAC(K_room, identity_pk)` — 8 байт |

Сервер видит: «opaque-room A36F получил пакет от opaque-sender B91C размером N байт в 19:42». Внутри комнаты участники тривиально декодируют (у них есть K_room и список identity_pk-ов).

**Не закрывает:**
- IP пользователя (Tor/VPN — отдельная история)
- Тайминг (нужен dummy traffic)
- Размер пакета (нужен padding)

Эти три — **отдельная Phase «metadata padding»**, на старте не делаем.

### Сложность
🔧🔧 — bump протокола, idёт в Phase D вместе с §14

---

## 5. Ротация ключей комнаты ★★★ ✅ РЕШЕНО

**Двухуровневая иерархия (γ-вариант с поправками):**

### Уровень 1 — K_room (мастер-ключ комнаты)
- 32 байта, генерируется при создании комнаты
- Распространяется через ECDH (X25519 → identity_pk каждого участника)
- Хранится локально у каждого участника
- **Никогда не передаётся в открытом виде**
- **Сервер K_room не знает**

### Уровень 2 — K_epoch (эпохальный ключ)
- Производный, **никогда не хранится** на диске
- `K_epoch[N] = HKDF(K_room_v, "fear.epoch.v1" || N)`, где N = час от UNIX epoch
- Все участники независимо вычисляют один K_epoch для одного N
- Заголовок пакета содержит `[room_key_version: 2 bytes][epoch_num: 4 bytes]`

### Когда меняется K_room
**Только при изменении состава комнаты:**
- Вошёл новый участник → новый K_room
- Вышел участник → новый K_room (чтобы он не мог расшифровать новые сообщения)

**Время-базированной K_room ротации НЕТ.** Только эпохи (K_epoch) меняются каждый час.

### Доставка нового K_room
При rotation-событии инициатор формирует bundle и отправляет на сервер:
```
rotation_event {
  room_id, new_K_room_version,
  per_member_blobs: [
    { recipient_pk: pk_alice, payload: X25519_encrypt(pk_alice, new_K_room) },
    ...
  ]
}
```
Сервер хранит bundle. Оффлайн-участники забирают свой blob при подключении.

### Старые K_room
Не удаляются локально — нужны для расшифровки исторических сообщений из (b) inbox.
Хранилище: 32 байта × количество ротаций ≈ ~КБ на комнату. Удаляются при «Очистить историю».

### Свойства
- ✅ Forward Secrecy: при выходе участника он не видит будущих сообщений
- ✅ FS на membership change: компрометация K_room_v2 не даёт K_room_v3
- ⚠️ Внутри одного K_room — все эпохи производные, утечка = вся переписка эпохи
- ❌ Post-compromise security в стиле Signal — нет (overkill для MVP)

### Сложность
🔧🔧 — крипто-критично, нужны test vectors. Phase C.

---

## 6. Аутентификация при отправке ⏸ ОТЛОЖЕНО

**Решение:** пока пользователей нет — спам/бот-защита не нужна.

**Что остаётся как есть:**
- Подпись Ed25519 на сообщениях — опциональная (как сейчас)
- Маркеры `[V]` / `[T]` / `[?]` / `[!]` — продолжают работать на уровне identity_pk
- Server-side rate limit — нет

**Когда вернёмся:** появятся реальные пользователи / публичные комнаты. Тогда:
- Per-IP rate limit (anti-flood)
- Mandatory sig (anti-impersonation)
- Возможно captcha при первом подключении к публичной комнате

---

## 7. Серверное состояние ★★★ ✅ РЕШЕНО

### Хранилище: SQLite в Docker volume
Простой, hostable, бэкапится одной командой. Postgres — когда упрёмся.

### Таблицы
- `handles` (handle, identity_pk, claimed_at) — для §1
- `rooms` (room_id, created_at, last_active)
- `messages` (room_id, room_key_version, epoch_num, sender_alias, server_ts, ciphertext)
- `user_blobs` (identity_pk, blob_type, ciphertext, updated_at) — контакты, settings
- `inbox` (target_identity_pk, room_id, ciphertext, server_ts) — offline-доставка
- `rotation_bundles` (room_id, new_key_version, recipient_pk, payload, created_at)
- `fcm_tokens` (identity_pk, token, updated_at) — для §12 в Phase E

### Квоты (по объёму, не по времени)
| Параметр | Лимит |
|---|---|
| Размер одного сообщения | 64 KB |
| Размер одного файла | 10 MB |
| **Хранилище на комнату (sliding FIFO)** | **10 MB** |
| Файловое хранилище на пользователя | 100 MB |
| Контакт-blob на пользователя | 100 KB |
| Запросов на IP в секунду | 10 (только базовая защита от ddos) |

При достижении 10 MB на комнату — старые сообщения дропаются (FIFO). Без time-retention (никаких «30 дней» — только размер).

### Клиентский лимит
- Локальный кэш на чат: 10 MB FIFO (по умолчанию, настраивается)
- **Кнопка «Очистить историю» в каждом чате** — обязательна
  ```
  ☐ Также удалить с сервера (мои сообщения у других сохранятся)
  ☐ Удалить ключи комнаты (расшифровка станет невозможна)
  ```
- Кнопка «Очистить всю историю» в Settings

### Бэкап
Cron в Docker контейнере: `sqlite3 .backup` → ротация на N последних. Описано в README.

### Сложность
🔧🔧 — добавляется БД, миграции, retention-cron. Phase B.

---

## 8. Мульти-девайс ★ ✅ РЕШЕНО

**(P) — один identity_sk на все устройства.** Импорт через QR/файл из §2.

**Минус принимаем:** если устройство украли — атакующий получает identity_sk, может писать от твоего имени. Нет remote-wipe для v1.

**Когда добавим (Q) linked devices:** при появлении реального спроса.

### Сложность
🔧 поверх §2

---

## 9. История сообщений ★★ ✅ РЕШЕНО

**Делаем (a) и (b). (c) пропускаем.**

### (a) Локальный кэш — Phase A
SQLite на ПК, Room на Android. Каждый клиент держит свою копию. Лимит 10 MB FIFO (см. §7).

### (b) Серверный inbox — Phase E
Сервер хранит шифротекст до доставки. Лимит 10 MB на (recipient_pk, room_id) sliding FIFO. После доставки клиент шлёт ACK → сервер удаляет.

### (c) История для нового member — ❌ НЕ ДЕЛАЕМ
В UI пишем «Новые участники видят сообщения только с момента входа» (Signal-модель). Если кому-то критически надо — пользователь может явно поделиться через export/import.

---

## 10. UX: «1 кнопка → готов» ★★★ ✅ РЕШЕНО

**Контакт-центричный UI (Telegram-style).** DM = специальная комната.

### Главный экран
```
┌──────────────────────────┐
│ ☰   F.E.A.R.       🔍 ⋮ │
├──────────────────────────┤
│ 🟢 Alice          10:42  │
│    Привет!               │
│ ⚪ Bob            Yest.  │
│    Файл получен          │
│ 👥 guest          14:30  │
│    Eve: Готовы?          │
└──────────────────────────┘
                       [+]
```

DM и комнаты в одном списке, отсортированы по последней активности. Иконка отличает (👤 vs 👥).

[+] → «Add contact (QR / @user@server / fpshort)» / «Create room»

### Архитектурные следствия
- Сервер дефолтный (`fear-project.ru`) зашит, меняется в Settings
- Identity создаётся автоматически при первом запуске
- При первом DM с peer X — авто ECDH создаёт DM-room (см. §11)

### Сложность
🔧🔧 для UI на каждом клиенте + 🔧 для DM-flow

---

## 11. DM (1-на-1) ★★ ✅ РЕШЕНО

**DM = комната типа `dm` с фиксированным составом из 2 участников.**

- Тип в метаданных: `room.type = dm | group`
- DM-room_id вычисляется детерминированно:
  ```
  room_id = BLAKE2b(min(pk_alice, pk_bob) || max(pk_alice, pk_bob), 16)
  ```
  Когда Алиса добавляет Боба, оба клиента вычисляют один и тот же room_id без согласования.
- В DM нет UI «добавить участника», «покинуть» — состав заморожен
- Шифрование, звонки, файлы — то же что для group rooms

### Сложность
🔧 — добавление поля type, детерминированный room_id

---

## 12. Push-уведомления ★ ✅ РЕШЕНО

**FCM с toggle. Делаем в Phase E.**

### Как работает
- FCM получает только «push для com.fear, device X, в момент T»
- Push-payload — пустой wake-up сигнал
- App просыпается, идёт на сервер, забирает шифротекст inbox, расшифровывает локально, показывает уведомление через NotificationManager (привязано к com.fear)

### Что узнаёт Google
- Время прихода push-ей
- НЕ узнаёт: контент, отправителя, имя комнаты

### Что НЕ могут другие приложения
По умолчанию доступа к нашим notifications нет. Только если пользователь явно даст `BIND_NOTIFICATION_LISTENER_SERVICE` (редкое разрешение для wear OS / accessibility).

### Settings UI
```
Уведомления
  ☑ Push через Google FCM (рекомендуется)
     Google узнаёт время уведомлений, но не их содержимое
  ☐ Polling каждые 5 минут (без Google, расход батареи)
  ☐ Только при открытом приложении
```

### Сложность
🔧🔧 — FCM SDK + endpoint на сервере для регистрации device tokens. Phase E.

---

## 13. Replay protection ★★ ✅ РЕШЕНО

- Каждое сообщение содержит `sender_seq` (4 байта, монотонно растущий счётчик от данного отправителя в данной комнате) — в AAD шифрования
- Сервер хранит `last_seq` per `(sender_pk, room_id)` (in-memory + persist в БД)
- Дубликаты и out-of-order — drop
- Сервер добавляет `server_ts` для сортировки

### Сложность
🔧 — небольшое изменение протокола. Phase A.

---

## 14. Versioning и миграция ★★★ ✅ РЕШЕНО

**Чистая миграция, без legacy support.**

Пользователей пока нет → можем ломать совместимость свободно.

- v0.5.x — текущий wire format
- v0.6.0 — новый wire format со всеми изменениями (§4 opaque IDs, §5 epoch headers, §13 sender_seq)
- Сервер v0.6.0 принимает только v2 клиентов
- Старые клиенты (если бы были) при подключении получают сервисное `MSG_TYPE_PROTOCOL_REJECT` и отключаются с сообщением «Требуется обновление до v0.6.0+»

Экономит ~30% сложности кода (нет двух codepath-ов).

---

## 15. Спам-защита и абьюз ⏸ ОТЛОЖЕНО

Откладывается вместе с §6. Когда вернёмся — добавим:
1. Per-IP rate limit (см. §6)
2. Mute/block по identity_pk на клиенте (фильтр в receive loop)
3. Friends-only mode комнаты — опционально

---

## 16. Group management ⏸ ОТЛОЖЕНО

Комнаты flat для v1: у кого есть K_room — тот член. Roles, signed kick/invite — после v0.6.0.

---

## 17. Search ★ ✅ РЕШЕНО

Локальный поиск по своему SQLite через FTS5. Сервер не может (всё ciphertext).

UI: иконка лупы вверху → поиск по всем чатам или по текущему. Phase A.

### Сложность
🔧 — стандартное SQLite FTS5

---

## 18. Удаление аккаунта (GDPR) ★ ✅ РЕШЕНО

**Базовый delete me для v1.**

Команда `MSG_TYPE_DELETE_ME`:
- Сервер удаляет: контакт-blob, мои сообщения из inbox, мой handle (освобождается), мой fcm_token
- Сервер ставит tombstone на identity_pk (чтобы случайно не reuse при collision)
- Клиенты других пользователей при lookup моего handle получают «удалён»
- Мои сообщения у других пользователей **остаются** локально (E2E — мы не можем их удалить)

**❌ «Delete for everyone» отдельных сообщений** — отдельная фича, не v1.

### Сложность
🔧 — серверная команда + UI button в Settings. Phase F.

---

## Phase-план (финальный)

### **Phase 0 — security baseline (3-5 дней)**
- Android: identity в EncryptedFile (вместо plaintext)
- Релизы: minisign-подпись артефактов + ключ в README

### **Phase A — foundation (2-3 недели)**
- §1 Identity-формат `name#fpshort` в UI везде (handle позже в B)
- §2 Backup: encrypted file (export/import) на обеих платформах
- §2 Backup: QR generation на обеих, scan на Android, import-from-PNG на Desktop
- §9a Локальная история (SQLite Desktop / Room Android)
- §13 Replay protection (sender_seq + server last_seq cache)
- §17 Локальный FTS5-поиск

### **Phase B — server state + UI rebuild (2-3 недели)**
- §7 Server БД (SQLite в Docker volume), таблицы, квоты, retention-cron
- §1 Server commands `register_handle` / `lookup_handle` + UI «Hold @username»
- §3 Encrypted contacts blob с auto-sync
- §10 Главный экран = контакты+комнаты в одном списке (Telegram-style)
- §11 DM = special room type, детерминированный room_id

### **Phase C — crypto evolution (2-3 недели, самая рискованная)**
- §5 K_room + K_epoch иерархия, membership-change rotation
- §5 Rotation bundle protocol (server stores per-recipient blobs)
- Тест-векторы для KDF-цепочки

### **Phase D — privacy метаданные (1 неделя)**
- §4 Opaque room_id (HMAC) + sender_alias на проводе
- §14 Wire format v2, чистая миграция, отключение v1

### **Phase E — полноценный мессенджер (2-3 недели)**
- §9b Server inbox для offline-доставки
- §12 FCM push с toggle
- §6 + §15 (если назрело к этому моменту): rate limit, mandatory sig, mute/block

### **Phase F — запуск к людям (1 неделя)**
- §18 Delete me
- Доки на сайте: retention policy, FCM disclosure, encryption details
- Снимаем prerelease с релизов → v0.6.0 stable

### **Опционально на потом:**
- §8(Q) linked devices
- §9c История для new room member
- §16 Group roles
- BIP-39 seed phrase для бэкапа
- Onion / Tor поддержка
- Metadata padding (dummy traffic, fixed sizes)

**Итого до v0.6.0 stable: 10-13 недель** реальной работы.

В рамках v0.5.x делаем Phase 0 и Phase A. Версия бампается в 0.6.0 после Phase D (когда меняется wire format).

---

## Принципы при реализации

1. **Phase C — единственное место где обязательно остановиться**. Крипто-ошибки катастрофичны. Тест-векторы пишем до кода.
2. **Каждая Phase должна оставлять приложение работающим**. Не накапливаем half-done features.
3. **Backwards-compat не делаем** (см. §14). Это снимает 30% сложности.
4. **«1 кнопка → готов»** — главная UX-метрика. Если новая фича делает onboarding сложнее — что-то не так.
