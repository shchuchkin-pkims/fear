# Roadmap

## Release History

| Version | Highlights | Status |
|---------|-----------|--------|
| **v0.1** | Basic messaging, key exchange, GUI | Done |
| **v0.2** | Encrypted audio calls (Opus + AES-GCM) | Done |
| **v0.3** | Secure key handling, file transfer, auto-updater, mobile app | Done |
| **v0.4** | Encrypted video calls (VP8 + SDL3 + AES-GCM) | Done |
| **v0.4.1** | ECDH key exchange, Ed25519 identity (TOFU), Android v0.4.1 | Done |
| **v0.4.2** | TCP media relay, server keepalive, Android in-app updates | Done |
| **v0.4.3** | RTT latency measurement, video call latency fixes | Done |
| **v0.5.0** | Phase A/B: identity handles, encrypted backup (file + QR), local history, server SQLite, contacts blob, DM | Done |
| **v0.5.1** | Audit remediation (5 Critical), signed releases, hardened relay | Done |
| **v0.6.0** | Phase C-F: key rotation, metadata privacy, offline inbox, push | In progress |

---

## Completed

### v0.5.1 - Audit remediation, test infrastructure, Phase C groundwork
- [x] All five Critical audit findings (memory corruption in the media path,
      server BLOB_PUT, desktop FILE_START; ECDH MITM bypass)
- [x] Signed releases: Ed25519 signature in CI, mandatory verification in the
      updater, Zip-Slip archives rejected
- [x] Relay hardening: I/O timeouts, per-IP connection cap, blob quotas,
      sender anti-spoofing
- [x] BLOB_GET is owner-only via a signed one-shot challenge (M10) - server,
      desktop and Android
- [x] Onboarding: identity created on first run, Connect no longer hard-locks
      on an inconclusive registration probe
- [x] Honest connection status, visible file-transfer progress, modal warning
      when the identity key of a peer changes
- [x] Unit tests for the crypto core, a server + two-client integration smoke
      test, and a protocol test for M10, all wired into ctest
- [x] CI: those tests run on every push to dev/main; Android runs its JVM unit
      tests before building the APK

### v0.4.3 — RTT Latency & Video Call Improvements
- [x] RTT ping/pong measurement in video calls (StatsPayload with hold-time compensation)
- [x] RTT ping/pong measurement in audio calls (new AudioStatsPayload + PKT_VER_STATS)
- [x] Color-coded RTT overlay on SDL video window (green/yellow/red)
- [x] RTT display in desktop GUI via [STATS] stdout parsing
- [x] Ring buffer for video capture (eliminates frame accumulation delay)
- [x] TCP_NODELAY on media relay sockets
- [x] Android: RTT stats for video and audio calls with color-coded display

### v0.4.2 — TCP Media Relay & Server Hardening
- [x] TCP media relay for audio/video calls through server (MSG_TYPE_MEDIA_RELAY = 17)
- [x] TCP keepalive on server (idle=60s, interval=10s, 3 probes — dead connection detection in ~90s)
- [x] Duplicate name rejection with error message to client
- [x] Android: in-app update (check GitHub releases, download and install APK)
- [x] Android: menu button on connection screen (theme, trusted keys, updates)
- [x] Android: online users list persists across theme changes
- [x] Android: close previous connection before starting new one (fixes ghost session bug)

### v0.4.1 — ECDH & Identity
- [x] ECDH key exchange (X25519 + crypto_box) — `--create` / `--join` modes
- [x] Ed25519 identity verification with TOFU model
- [x] GUI: Create Room / Join Room / Connect buttons
- [x] Android app updated to v0.4.1 (ECDH, identity, video calls, themes, push notifications)

### v0.4.0 — Video Calls
- [x] VP8 video codec via FFmpeg (libvpx)
- [x] SDL3 hardware-accelerated YUV420P display
- [x] AES-256-GCM encryption per fragment
- [x] UDP fragmentation/reassembly (1200B chunks, up to 128 per frame)
- [x] Adaptive bitrate (LOW/MEDIUM/HIGH presets)
- [x] Peer disconnect detection (5s timeout) + auto reconnect
- [x] "No camera" receive-only mode
- [x] GUI integration with camera/quality selection

### v0.3.0 — Security & Features
- [x] AES-256-GCM encryption (upgraded from XSalsa20)
- [x] Secure key generation (stdout only, not saved to disk)
- [x] GUI auto-copy keys to clipboard
- [x] Secure key input via stdin / `--key-file` (deprecate `--key` argument)
- [x] File transfer with CRC32 integrity verification
- [x] Auto-updater
- [x] Audio device Host API in names (fixes duplicates)
- [x] Android mobile app (initial release)

### v0.2.0 — Audio Calls
- [x] Encrypted voice calls (Opus + PortAudio + AES-GCM over UDP)

### v0.1.0 — Foundation
- [x] Client-server architecture with room-based chat
- [x] E2E encrypted messaging
- [x] Qt6 GUI application
- [x] Console client/server
- [x] Diffie-Hellman key exchange utility

---

## In Progress

- [x] **Phase C - crypto evolution.** Landed: the key schedule, rotation
      bundles, sender-rooted media keys, HELLO2 (now carrying a display name),
      the sender table with replay windows, call invites carrying the call_id,
      the switchover of the live media path on both platforms, group audio
      mixing, group video with a speaker view and a strip on both platforms,
      an incoming-call screen on Android, and the epoch key schedule under the
      chat path on both platforms. The desktop client now rotates K_room on a
      membership change, which is what actually closes the forward-secrecy
      finding: a member cannot read what was said before it arrived, and a
      member that leaves cannot read what is said after.

      Four things made that work and are worth not undoing, each of them
      found by a room that split rather than by reasoning.

      The election needs the rosters to agree, so a membership change arms a
      rotation rather than performing one - without the wait every client
      elects itself, since the server announces the change before the members
      have said who they are.

      The bundle is broadcast unsealed, because every entry in it is already
      sealed to one member's identity key and a member who has just joined
      has no current K_room to open an envelope with. Identity announcements
      ride the founding key rather than the current generation for the same
      reason - otherwise joining a room that has ever rotated is impossible.

      Only a member that was in the room before the change and is still in it
      after may be elected. This one is arithmetic, not principle: a member
      that has just arrived holds generation zero and cannot know the room is
      on generation four, so the "next" generation it draws is one the room
      has already used - everyone else discards it as a replay while the
      newcomer installs it and stops being able to read anything.

      And a member's own arrival is not a change it witnessed, so it takes no
      part in that election and accepts whichever rotator the room picked.
      Counting itself as having been present is what made two members rotate
      at once and the room split in two.

      Android speaks it too now, and the binding is pinned as a frozen vector
      on both sides so that either one drifting fails its own test rather
      than a room quietly splitting. Verified live: a phone and two console
      clients on one relay, two membership changes, one rotation each, and
      the member that joined last unable to read what came before it.

      Phase C is closed. Metadata privacy, the offline inbox and push are
      phases of their own and are listed below.
- [x] **Phase E - офлайн-ящик.** Письмо тому, кого нет в комнате, ложится в
      ящик на ретрансляторе и забирается, когда адресат придёт - в том числе
      сидя в совсем другой комнате: клиент следит за ящиками всех контактов и
      спрашивает их одним запросом раз в двадцать секунд.

      Адрес слепой: BLAKE2b под ключом пары. Оператор видит непрозрачную
      метку, а не чей-то ключ. Знание адреса и есть право забрать - K_pm у
      сервера нет и быть не должно, а значит и подпись под ним он не проверит.
      Имя отправителя едет внутри запечатанного письма: рядом его прочёл бы
      сервер, а в связанных данных получателю пришлось бы знать имя заранее.

      Хранение - решение оператора: `--inbox off | 30d | Nh`, по умолчанию
      месяц. Выключение выбрасывает накопленное. Срок едет в каждом ответе,
      поэтому клиент знает политику и говорит «не доставлено» честно, а не
      рисует вторую галочку. Квоты на адресата - 200 писем или 5 МБ.

      Открыто: письмо забирается опросом, а не уведомлением. Мгновенная
      доставка требовала бы привязать соединение к личному ключу, то есть
      создать у оператора список «кто сейчас в сети поимённо».
- [x] **Идентификатор личной комнаты больше не выводится ретранслятором.**
      Был BLAKE2b от двух открытых ключей без секрета, а сервер знает ключи
      всех, кто занял имя, - и мог подписать каждую личную комнату именами
      обоих. Теперь выводится под K_pm. Переписка переезжает при первом
      подключении; контакты, добавленные раньше, до переезда работают по
      старому выводу и не пропадают из списка.
- [x] **База Android переведена на явные миграции.** Была открыта с
      fallbackToDestructiveMigration: любое расхождение схемы Room решал тем,
      что стирал файл и заводил новый. Для контактов это терпимо - их копия
      лежит на сервере зашифрованным блобом. Для переписки не терпимо совсем:
      ретранслятор её не хранит, офлайн-ящик отдаёт письмо один раз. Стёртая
      история не восстанавливается ниоткуда, и человек узнал бы о потере,
      открыв пустой чат после обычного обновления.

      Схема теперь выкладывается в app/schemas и лежит в репозитории - без
      неё миграцию нечем сверять. Переход v1→v2 написан явно, DDL списан с
      выложенной схемы: Room сличает получившуюся базу с ожидаемой побайтно,
      вплоть до порядка столбцов, и расхождение замечает уже на устройстве.

      Проверок две. MigrationSqlTest сличает DDL миграции с выложенной схемой
      и проверяет, что цепочка переходов не имеет дыр, - идёт на обычной
      сборке. MigrationTest прогоняет миграцию на настоящем SQLite и
      убеждается, что строка, записанная до обновления, читается после;
      он инструментальный и требует устройства.

      Понижение версии намеренно оставлено падать, а не стирать: база новее
      приложения - это откат на старую сборку, и он лечится установкой новой.
      Стирание же необратимо.
- [x] **Phase D - приватность метаданных.** Ретранслятор больше не читает в
      своём журнале ни комнат, ни имён.

      *Комната.* На проводе не «general», а BLAKE2b от названия. Заодно
      исчезла приставка «pm:», по которой личные комнаты отличались от общих
      с одного взгляда. Вход по имени работает как раньше - обе стороны
      хешируют одну строку.

      Предел назван вслух: хеш без секрета, «general» подбирается по словарю.
      Это защита от чтения журнала, а не от оператора, который ищет. Полная
      непрозрачность требует ключа комнаты, которого у входящего по имени
      ещё нет.

      *Имя.* В поле имени кадра теперь метка сессии - 16 случайных байт,
      новые на каждое подключение. Настоящее имя уезжает внутрь шифра,
      анонсом личности, вместе с подписью, которая привязывает имя к этой
      самой метке: иначе чужой анонс можно было бы взять целиком и повторить
      под своей меткой, забрав вместе с ним и имя.

      Что это меняет для оператора: имена устойчивы между сеансами, и по ним
      складывался граф знакомств - кто с кем всегда оказывается в одной
      комнате. По метке не складывается: общего между двумя сеансами одного
      человека в ней нет.

      Защита от подмены отправителя осталась той же и на том же месте:
      сервер сверяет кадр с тем, чем это соединение представилось. Изменилось
      только, что закрепляется, - не имя, которого сервер больше не видит, а
      метка. Кому какая метка принадлежит, получатели узнают из подписанного
      анонса, и подделать это уже не в силах ни сосед по комнате, ни сам
      ретранслятор - раньше от подмены имени защищал только сервер.

      Три следствия, честно:

      * Уникальность имён в комнате сервер больше не сторожит - он их не
        видит. Двое могут объявиться тёзками; клиенты это показывают,
        добавляя отпечаток ключа к повторяющемуся имени.
      * Пока участник не объявился, показывается огрызок метки, а не имя:
        приписать сообщение не тому хуже, чем сказать «пока не знаю, кто
        это».
      * Метка освобождается вместе с соединением, и её может занять
        следующее. Поэтому ушедшему метку развязывают с именем и ключом:
        иначе кадры нового владельца показались бы под именем прежнего без
        единой подделанной подписи, просто по устаревшей записи.

      *Звонки.* Они идут отдельными процессами и своим подключением к тому же
      серверу - и передавали название комнаты и имя как есть. Достаточно было
      одного звонка, чтобы вернуть в журнал ретранслятора всё, что чат только
      что убрал. Теперь и звонок называет комнату меткой, а себя - меткой
      сессии чат-клиента; консольный клиент печатает её строкой `[SESSION]`,
      графический подхватывает оттуда.

- [x] **Phase F - уведомления без Google.** Выбран путь без FCM: фоновая
      служба держит соединение и опрашивает офлайн-ящик, уведомление рисует
      само приложение. Google не узнаёт ни времени сообщений, ни того, что
      они были; работает на телефонах без сервисов Google.

      В фоне опрос реже, чем на переднем плане: там человек ждёт ответа и
      смотрит на экран, здесь считает батарею. На заблокированном экране
      показывается «New message» без текста и отправителя - расшифрованное
      тело на локскрине сводило бы на нет всё сквозное шифрование на
      последнем шаге.

      Чего этот путь не даёт: пробуждения убитого системой приложения. Это
      умеет только FCM, а он означает чужой сервис, знающий время каждого
      вашего сообщения, и токен устройства, привязанный к личности на
      ретрансляторе. Осознанный размен, а не недоделка.
- [ ] Documentation updates and localization

## Planned

### Security
- [x] Desktop identity key encrypted at rest (libsecret / DPAPI). The public
      key stays in the clear - identity_load_pk is called on half a dozen GUI
      paths that only want a fingerprint and have no business unlocking a
      keyring - and the secret key is wrapped by a key the platform store
      holds. The keyring holds the wrapping key rather than the identity
      itself, so the identity is still a file the user can copy, back up or
      move; that file is simply useless on its own now.

      What this closes is the file leaving the machine: a backup, a copied
      home directory, a disk out of a laptop. It does not stop a process
      running as this user while the session is unlocked - the keyring is
      unlocked too and will hand the key over. That is the same bargain
      Android'''s Keystore-backed EncryptedFile makes.

      A build without libsecret, or a machine with no keyring running, keeps
      the old plaintext form and says so once on stderr. Refusing to start
      would be worse: headless and container use is real, and this is a
      hardening step rather than a new requirement. Linux CI installs
      libsecret so the wrapped path is compiled; the unit-test job does not,
      so the fallback is compiled too, and test_identity asserts whichever
      invariant matches the environment it finds.
- [ ] Post-compromise security (Signal-style ratchet) - deliberately out of scope
      for v0.6.0, recorded so the gap is not mistaken for an oversight

### Networking
- [~] **NAT traversal.** Сделано главное: адрес перестал вводиться руками.
      Раньше `/invite` требовал вписать хост и порт, а за NAT человек их
      попросту не знает - собственный интерфейс говорит «192.168.0.5», и
      собеседник по этому адресу не придёт никогда. Теперь процесс звонка
      спрашивает свой внешний адрес у сервера STUN и печатает строкой
      `[CANDIDATE]`, а графический клиент доносит её до комнаты вторым
      приглашением с тем же идентификатором звонка.

      Спрашивается с того самого сокета, который понесёт голос, и это не
      придирка: NAT выдаёт отображение не машине, а паре «внутренний адрес и
      порт». Спроси мы с другого сокета - сообщили бы собеседнику
      отображение, которого для голоса не существует.

      По умолчанию выключено, и это осознанно. Прямой звонок короче по пути
      и не даёт оператору ретранслятора видеть поток - но **раскрывает ваш
      адрес собеседнику**, чего ретранслятор не делает, и ещё серверу STUN.
      Решать этот размен за человека нельзя, поэтому поле пустое, а рядом
      написано, чем платят.

      Роль TURN играет ретранслятор: он уже есть, работает и остаётся
      запасным путём. При симметричном NAT прямой путь не откроется - там
      на каждый новый адрес назначения выделяется новый порт, и узнанное
      отображение недействительно к моменту, когда собеседник по нему
      постучит.

      Разбор ответа STUN рассчитан на враждебный ввод: пакет приходит по
      UDP, отправителя подделать может кто угодно. Сверяется идентификатор
      запроса и каждая длина внутри; 24 проверки в `test_stun`, включая
      враньё в длинах и все возможные обрезки пакета.

      Остаётся: настоящий перебор пар кандидатов (ICE) вместо одного
      адреса, местные адреса в списке кандидатов для звонков внутри одной
      сети, и то же самое на Android.
- [x] **TLS поверх TCP.** Внешний слой для связи с ретранслятором.

      Что он даёт. Содержимое разговоров и так зашифровано между
      собеседниками, и TLS к этому не добавляет ничего. Он закрывает
      наблюдателя на пути: провайдера, хозяина точки доступа, того, кто
      смотрит на канал. Без него видна структура кадров - длины полей,
      метка комнаты, метка сессии, ритм обмена, - и этого хватает, чтобы
      сказать «вот эта машина разговаривает через F.E.A.R.», не прочитав ни
      слова.

      Чего не даёт, и это надо говорить прямо: ничего не прячет от самого
      ретранслятора. Тот стоит на другом конце туннеля и видит ровно то же,
      что видел раньше. Против оператора работают другие меры - хеш вместо
      названия комнаты, метка вместо имени, - а не эта.

      Сервер: `--tls-cert FILE --tls-key FILE`. Клиент: `--tls` или
      `--tls-pin SHA256HEX`. Отпечаток вместо удостоверяющего центра - более
      уместная проверка для своего ретранслятора с самоподписанным
      сертификатом: доверие здесь и так строится на сверке отпечатков, а не
      на списке чужих центров.

      Рукопожатие живёт в `dial_tcp` - единственном месте, где вообще
      открывается связь с ретранслятором. Сначала я вписал его в место
      вызова и оставил открытым пробное соединение, которое клиент делает,
      чтобы узнать состояние комнаты: короткое, молчаливое, незаметное.
      Один вход в сеть - одно место, где решается вопрос защиты.

      Где OpenSSL при сборке не нашёлся (Windows берёт зависимости готовыми
      из `lib/`), модуль собирается заглушкой и **отказывает**, а не
      соединяется открытым текстом: человек, попросивший TLS, иначе счёл бы
      себя защищённым, ничего таковым не будучи. Проверено сборкой с
      `-DFEAR_TLS=OFF`.

      Проверено вживую: рукопожатие сторонним `openssl s_client` (TLSv1.3),
      клиент с верным отпечатком проходит, с чужим - отказывается и
      показывает настоящий, клиент без TLS к серверу с TLS не проходит.
      Образ сервера собирается с TLS.

### Quality
- [x] Load testing for the server: tests/load_server.c, plus a regression test
      that the connection caps hold (16 per address, 100 total - both measured
      exactly). About 365k relayed frames/s with a full room of 100.
      Still open: load testing the calls themselves.
- [x] Fuzzing the parsers that read the network before anything is trusted -
      HELLO2, the call invite, the media packet header, the sealed chat frame.
      Deterministic driver under ASan/UBSan, bounded in CI, 100M inputs over
      five seeds locally with nothing found. The server frame header joined
      them once both of its parsers were merged into one; the fuzzer checks
      that every view it returns lies inside the buffer, not merely that it
      returned. Still open: client.c, which reads field by field from a
      socket and needs a harness that owns one.
- [x] Утилита администрирования ретранслятора (admin/, Qt6). Работает с базой
      на машине сервера: занятые имена, зашифрованные блобы, чёрный список
      ключей, живые подключения, выгрузка и VACUUM. Сетевых команд
      администрирования сервер не получил намеренно - это была бы новая
      аутентифицированная поверхность атаки на машине, через которую ходит
      чужая переписка.

      Блокировка ключа действует там, где сервер вообще видит ключ:
      регистрация имени, поиск по ключу, доступ к блобам. Войти в комнату она
      не мешает, потому что ключа обычного подключения сервер не видит - и
      сделать так, чтобы видел, значило бы создать у оператора список «кто с
      кем разговаривает». Подробности в admin/README.md.

- [x] **Один интерфейс вместо двух.** Старое окно (MainWindow) держали за
      ключом `--classic-ui` на время перехода, и держали слишком долго: два
      окна - это два места, где чинить каждую ошибку, два набора настроек в
      QSettings и два набора возможностей, расходящихся тем сильнее, чем
      дольше живут оба. Аудит 2026-07 отметил это отдельным пунктом.

      Удалению предшёл перенос, а не наоборот. Только в старом окне были:
      свой ретранслятор («Run a relay here»), ручной обмен ключами, выбор
      шрифта переписки, ссылка на руководство и значок в системном лотке.
      Всё перенесено в новое окно и проверено вживую под Xvfb; выбранный
      шрифт применяется в том числе к уже показанным сообщениям и переживает
      перезапуск.

      Значок в лотке заодно меняет смысл закрытия окна: оно прячется, а
      соединение живёт дальше. Иначе закрытое окно означало бы пропущенный
      разговор. Выход - отдельным пунктом, и в меню, и в лотке.

### Features
- [x] **Шумоподавление и ручные настройки звука и видео.**

      *На ПК.* Между микрофоном и кодировщиком встала обработка
      (`identity/mic_dsp.c`): срез ниже 80 Гц, ворота по громкости с
      оценкой фона и ручная чувствительность в децибелах. Ключи
      `--mic-gain dB` и `--noise-suppress off|low|medium|high` у обеих
      программ звонков, настройки - во вкладке Audio, читаются перед каждым
      звонком.

      Обещать надо ровно то, что программа делает: это не спектральная
      чистка. Шум из-под голоса не вычитается, и пока человек говорит, фон
      слышен таким, какой он есть. Уходит то, что слышно в паузах - гул,
      шипение, вентилятор, улица. На слух собеседника это и есть основная
      разница, потому что пауз в разговоре больше, чем речи. Настоящее
      подавление потребовало бы отдельной библиотеки (speexdsp, RNNoise) в
      каждой из четырёх сборок, включая Windows, где зависимости лежат
      собранными заранее, - это отдельная работа, а не строчка в CMake.

      Ворота настроены под слух, а не под цифры: открываются быстро
      (срезанное начало слова - самый заметный дефект), закрываются
      медленно (иначе «дышат» на каждой паузе между словами), а оценка фона
      ползёт вниз быстро и вверх медленно - иначе заговоривший человек сам
      захлопнул бы ворота посреди фразы. Проверено 16 проверками
      (`test_mic_dsp`), в том числе на первом кадре речи после долгой тишины.

      *На Android.* Подавление системное (`NoiseSuppressor`) - на телефоне
      оно часто сделано прямо в звуковом тракте устройства и лучше всего,
      что можно написать самому. Было включено всегда; теперь его можно
      выключить: на некоторых аппаратах оно ощутимо режет тихую речь.
      Чувствительность - программным усилением с насыщением.

      *Видео.* На ПК ручной набор (ширина, высота, частота, поток) стал
      сохраняемой настройкой, а не только полем в окне звонка. На Android
      поток и частота кадров правятся поверх выбранного набора: разрешение
      диктуют камера и собеседник, а поспевает звонок или сыпется - решают
      эти два числа.
- [ ] iOS mobile app

---

## Changelog

### v0.4.3

**RTT Latency Measurement:**
- Ping/pong via StatsPayload in video calls, new AudioStatsPayload in audio calls
- Hold-time compensation: echo includes delay since ping reception for accurate RTT
- Color-coded SDL overlay on desktop video (green < 100ms, yellow 100-300ms, red > 300ms)
- Desktop GUI parses [STATS] lines from stdout for audio/video call RTT display

**Video Call Latency Fixes:**
- Ring buffer in video_capture replaces unbounded queue — prevents frame accumulation
- TCP_NODELAY on TCP media relay sockets
- video_capture_read_latest() returns only the most recent frame

**Android v0.4.3:**
- RTT stats exchange for both video and audio calls
- Color-coded RTT display (VideoCallActivity + MainActivity)

### v0.4.2

**TCP Media Relay:**
- MSG_TYPE_MEDIA_RELAY (17) — audio/video calls relayed through TCP server when UDP is blocked
- Each call manager opens dedicated TCP connection, registers with room+name
- Server broadcasts media frames to room participants

**Server Hardening:**
- TCP keepalive (SO_KEEPALIVE, idle=60s, interval=10s, 3 probes) — detects dead connections in ~90s
- Duplicate name rejection sends error message before disconnecting

**Android v0.4.2:**
- In-app update: check GitHub releases, download and install APK directly
- Menu button on connection screen
- Online users list preserved on theme change
- Previous connection closed before starting new one (fixes ghost session)

### v0.4.1

**ECDH Key Exchange:**
- MSG_TYPE_KEY_REQUEST (15) / MSG_TYPE_KEY_RESPONSE (16) service messages
- X25519 ephemeral keypairs + crypto_box for key transport
- Ed25519 signature on ECDH response prevents MITM
- CLI: `--create` (auto-gen key), `--join` (ECDH exchange)
- GUI: Create Room / Join Room / Connect buttons

**Identity Verification:**
- Ed25519 keypair generation and persistent storage (`.fear/identity/`)
- Trust On First Use (TOFU) — first-seen pubkey is saved, mismatch = warning
- Peer verification during calls (guarded against spam)

**Android v0.4.1:**
- ECDH key exchange (Create Room / Join Room)
- Identity verification
- Video calls
- Light/dark theme toggle
- Push notifications for background messages
- Recent hosts dropdown

### v0.4.0

**Video Calls:**
- VP8 video codec via FFmpeg (libvpx), SDL3 YUV420P display
- AES-256-GCM per-fragment encryption, UDP fragmentation
- Adaptive bitrate (LOW: 320x240@15fps, MEDIUM: 640x480@25fps, HIGH: 1280x720@30fps)
- Peer disconnect detection (5s timeout), auto reconnect
- "No camera" receive-only mode, GUI camera/quality selection

### v0.3.0

**Security:**
- Keys output to stdout only (not auto-saved to disk)
- GUI auto-copies keys to clipboard
- Secure key input via stdin / `--key-file`
- `--key` CLI argument deprecated (visible in process lists)

**Audio:**
- Host API info in device names (e.g., "Microphone (WASAPI)")
- Fixes duplicate device names across APIs

**Other:**
- File transfer with encryption and CRC32 verification
- Auto-updater with version checks
