# TASKS: трекер выполнения ROADMAP

План, обоснования и критерии готовности — в [ROADMAP.md](ROADMAP.md). Здесь только статус работ. Детальные задачи расписываются для текущего и следующего milestone; остальные пока перечислены крупными блоками и детализируются, когда до них доходит работа.

**Легенда:** ✅ сделано · 🔄 в работе · ⬜ не начато · 👤 нужно действие владельца (настройки GitHub и т. п.; из сессии это сделать нельзя)

## Сводка

| Milestone | Версия | Статус | Готово |
|---|---|---|---|
| M0 Фундамент | — | 🔄 | 18 / 21 |
| M1 Вертикальный срез | v0.1.0-alpha | ✅ | 19 / 19 |
| M2 MVP | v0.2.0 | 🔄 | 17 / 18 |
| M3 Hardening | v0.3.0 | ⬜ | 0 / 12 |
| M3b Windows | — | ⬜ | 0 / 3 |
| M4 Multi-user и Ops | v0.4.0 | ⬜ | 0 / 9 |
| M5 Distribution | v0.5.0 | ⬜ | 0 / 7 |
| M6 v1.0 | v1.0.0 | ⬜ | 0 / 8 |

## M0: Фундамент и расчистка

| ID | Задача | Статус | Где / заметка |
|---|---|---|---|
| M0-01 | D1 лицензия (Apache-2.0), D2 имена (`go-sftp-server` / `gosftpd`) | ✅ | Подтверждено владельцем; `docs/adr/0001-foundation.md` |
| M0-02 | D3, D4, D14, D16, D17, D19 — по рекомендациям §13 | ✅ | ADR 0001; можно пересмотреть |
| M0-03 | Удалить старый код (`main.go`, `cmd/server`, `pkg/`) | ✅ | |
| M0-04 | Module path `github.com/o-kolomoiets/go-sftp-server`, `go 1.26.5` | ✅ | `go.mod` |
| M0-05 | Скелет: `cmd/gosftpd`, `internal/cli` (cobra, `version [--json]`, exit codes 0/1/2), `internal/version` | ✅ | С unit-тестами |
| M0-06 | `.gitattributes` (LF), `.gitignore`, `.editorconfig` | ✅ | |
| M0-07 | `LICENSE` → Apache-2.0, SPDX-заголовки в `.go` | ✅ | Запись в CHANGELOG |
| M0-08 | Честный README на английском | ✅ | |
| M0-09 | CI `ci.yml`: lint, test (Linux amd64/arm64, macOS, Windows × Go 1.26/1.27), min-go, govulncheck, `ci-ok` | ✅ | |
| M0-10 | `.golangci.yml` (§9.2) | ✅ | `config verify` и `run` чистые |
| M0-11 | `tools/go.mod` (govulncheck, staticcheck, gotestsum, actionlint), `Makefile` | ✅ | go-licenses добавится в M5 |
| M0-12 | `.github/dependabot.yml` (gomod `/` и `/tools`, github-actions) | ✅ | |
| M0-13 | `SECURITY.md`, `CONTRIBUTING.md`, `CHANGELOG.md`, шаблоны issue и PR, `CODEOWNERS` | ✅ | |
| M0-14 | `docs/adr/0001-foundation.md`, `docs/adr/0002-non-goals.md`, `docs/DEPENDENCIES.md` | ✅ | |
| M0-15 | Трекер задач | ✅ | Этот файл вместо GitHub milestones и issues; переносить в issues, когда появятся контрибьюторы |
| M0-16 | `CODE_OF_CONDUCT.md` (Contributor Covenant 3.0) | ⬜ 👤 | Нужен контакт для жалоб (email): владелец сообщает, текст добавлю |
| M0-17 | Переименовать репозиторий в `go-sftp-server` | ⬜ 👤 | Settings → General → Repository name. Не обязательно: GitHub не различает регистр в URL |
| M0-18 | Включить private vulnerability reporting, secret scanning + push protection, CodeQL default setup | ✅ | PVR (проверено через API), Secret Protection, push protection, Dependabot alerts и security updates, CodeQL (проверка `Analyze (go)` в PR #3) |
| M0-19 | Ruleset на `main`: PR обязателен (approvals: 0), required check `ci-ok`, без удаления и force-push | ✅ | Проверено через API 2026-10-08: `deletion`, `non_fast_forward`, `pull_request`, `required_status_checks: ci-ok`. Linear history и code scanning не включены: merge-коммиты разрешены, CodeQL и так идёт на каждом PR |
| M0-20 | DoD: `go install github.com/o-kolomoiets/go-sftp-server/cmd/gosftpd@latest` работает | ✅ | Проверено 2026-10-07 на чистом GOBIN |
| M0-21 | DoD: страница Community Standards закрыта полностью | ⬜ | После M0-16 |

## M1: Вертикальный срез (v0.1.0-alpha)

Цель: `gosftpd serve --dir ./share` → OpenSSH `sftp`/`scp` делают list/get/put/mkdir/rm/rename внутри `os.Root`, аудит на каждую операцию, корректный shutdown. Подробности — ROADMAP §5 M1.

| ID | Задача | Статус | Где / заметка |
|---|---|---|---|
| M1-01 | Spike: handshake + subsystem `sftp` + `exit-status` в in-process тесте; зависимости x/crypto v0.57.0, pkg/sftp v1.13.11 | ✅ | Сделано в составе M1: тест `TestExitStatus` |
| M1-02 | `internal/hostkey`: генерация ed25519 (`O_EXCL`, 0600), загрузка с проверкой прав, RSA только SHA-2, fingerprint и known_hosts | ✅ | `internal/hostkey` |
| M1-03 | `internal/server`: `ServerConfig` (профиль `modern`, `MaxAuthTries 6`, `ServerVersion`, `AuthLogCallback`) | ✅ | `internal/server`, профиль `modern` |
| M1-04 | Accept-цикл: deadline на handshake 30 с, `recover`, учёт соединений, backoff | ✅ |  |
| M1-05 | Каналы: только `session` (≤ 4 на соединение), subsystem через `ssh.Unmarshal`, остальное `Reply(false)` | ✅ | direct-tcpip, exec, shell, другие subsystem отклоняются (тесты) |
| M1-06 | `RequestServer` + `exit-status` (0 при `nil`/`io.EOF`, иначе 1) | ✅ | T1 закрыт: `scp` завершается с 0 (interop) |
| M1-07 | Graceful shutdown (SIGINT/SIGTERM, `shutdown_timeout`), SIGHUP игнорируется | ✅ | Проверено в interop: SIGHUP не останавливает, SIGTERM → exit 0 |
| M1-08 | `ServeConn` для тестов | ✅ | `testutil.AsyncConn` перенесён в M3-12 (нужен для synctest-тестов таймаутов) |
| M1-09 | `internal/auth`: `--authorized-keys`, allowlist опций, чистый lookup, личность только из `Permissions`, `--user` | ✅ | `internal/auth`; `from=` → `source-address`, `expiry-time=`, `cert-authority`/`verify-required` отклоняются |
| M1-10 | `internal/vfs`: mount table из `--dir [NAME=]PATH`, `os.OpenRoot`, синтетический корень, `resolve()` | ✅ | `internal/vfs` |
| M1-11 | Операции VFS: open (`O_NONBLOCK`, только регулярные), write (без `O_APPEND`), stat/lstat, листинг, mkdir, remove, rename no-clobber, symlink/link → unsupported, setstat | ✅ | Rename без перезаписи: `renameat2(RENAME_NOREPLACE)` на Linux, иначе `Link`+`Remove` |
| M1-12 | Политика конфликтов `rename\|reject\|overwrite`: `O_EXCL`-резервирование, remap `r.Filepath`, posix-rename, очистка оборванных; resume отклоняется | ✅ | 50 параллельных загрузок → 50 файлов, оригинал цел |
| M1-13 | `internal/sftpd`: `SetSFTPExtensions` один раз, маппинг ошибок (`sftpStatus`), лимит 64 handles, счёт байтов, `TransferError` | ✅ | `internal/sftpd` |
| M1-14 | `internal/audit`: JSON через slog, sink с перехватом ошибок записи (fail-closed), события §6.4 | ✅ | `internal/audit` |
| M1-15 | CLI `serve` (флаги M1), `hostkey show`, вывод при первом запуске | ✅ | `gosftpd serve`, `gosftpd hostkey show` |
| M1-16 | Интеграционные тесты: ST-1…5, 7, 9…11, 50 параллельных загрузок, goleak | ✅ | ST-1…5, 7, 9…11 + fail-closed аудит; goleak, `-race`; покрытие `internal/vfs` 81% |
| M1-17 | Interop: `test/interop/run.sh` + `basic.batch` (`sftp -b`, `scp`), job в CI, добавить в `ci-ok` | ✅ | `test/interop/run.sh` (26 проверок, OpenSSH 9.6p1), job `interop` в CI |
| M1-18 | `docs/adr/0003-sftp-library.md` | ✅ |  |
| M1-19 | Проверка DoD M1, тег `v0.1.0-alpha` | ✅ | [Релиз v0.1.0-alpha](https://github.com/o-kolomoiets/Go-SFTP-Server/releases/tag/v0.1.0-alpha) (pre-release, 533795c); `go list -m …@v0.1.0-alpha` находит его через proxy.golang.org. Проверка на OpenSSH 10.x перенесена в M2-15 |

## M2: MVP (v0.2.0)

| ID | Задача | Статус | Где / заметка |
|---|---|---|---|
| **M2a** | **Конфиг, пользователи, права, CLI** | | |
| M2-01 | `internal/config`: типы, `Default()`, загрузка TOML (неизвестный ключ — ошибка с позицией), `FileMode`, `config_version`, `include` | ✅ | `internal/config`; `ByteSize` — в M3 вместе с `max_file_size`. `include` принимает только `[users.NAME]` |
| M2-02 | Источники: порядок поиска файла, приоритет флаги > env > файл > умолчания; zero-config `--dir` без поиска файла | ✅ | `config.Find`, `cli.buildConfig`; `--authorized-keys`, `--user`, `--state-dir` — только с `--dir` |
| M2-03 | `Validate()` (все ошибки сразу, с путём ключа) и `CheckFS()` (пути mount'ов, права файлов по §6.5) | ✅ | Права файлов как StrictModes в sshd: не запускается, если конфиг, ключи или `authorized_keys` доступны группе на запись |
| M2-04 | Опции mount'а: `create`, `read_only`, `on_conflict`, `rename_template`, `max_rename_attempts`, `compound_extensions`, `umask`, `require_mountpoint`, `setstat_mode`, `flatten` | ✅ | `symlinks`, `resume`, `stat_redirect` — в M2b |
| M2-05 | Пользователи `[users.NAME]`: `authorized_keys`, `authorized_keys_file`, `allow_from`, `expires`, `disabled`, `access`; неизвестный пользователь идёт тем же путём, что неверный ключ | ✅ | `auth.NewUsers` |
| M2-06 | Права: флаги и пресеты §6.3, temp-загрузки через `write`, `size` на writer этой сессии, `read_only` | ✅ | `vfs/perm.go`; interop: пользователи `read`, `upload`, `full` с OpenSSH |
| M2-07 | `{user}`-home: безопасное создание и открытие (ST-12) | ✅ | `Mount.openHome`: `Lstat` + `OpenRoot` + `os.SameFile`; symlink `alice → bob` или наружу → mount недоступен, `fs.denied reason=home_not_dir` |
| M2-08 | CLI: `init`, `config validate\|show\|example`, `user add\|list`, `hostkey generate`, `completion`; golden-тесты | ✅ | golden-тест `user add`; `completion` — встроенная команда cobra |
| M2-09 | Примеры конфигов через go:embed; тест `Validate()` и e2e минимального примера | ✅ | `TestExamples`, `TestExampleFullCoversEveryKey`, `TestServeMinimalExample` |
| **M2b** | **Протокол** | | |
| M2-10 | Докачка: append-only guard, `resume = "append-only"\|"off"` | ✅ | `WriteAt` и `FSETSTAT size` ниже исходного размера → `PERMISSION_DENIED` «existing data is immutable»; interop: `reput` даёт идентичный файл |
| M2-11 | `stat_redirect` (в пределах сессии, TTL 60 с, цель posix-rename) | ✅ | STAT, LSTAT, SETSTAT; снимается при open, remove, rename этого пути |
| M2-12 | `statvfs@openssh.com` (Linux, darwin, freebsd) | ✅ | `df -h` в interop; mount без прав на изменение — read-only |
| M2-13 | Виртуальные владельцы в листинге, `Readlink` → unsupported, политика `symlinks = "inside-only"\|"deny"` | ✅ | uid/gid 1000, в `ls -l` — имя пользователя |
| M2-14 | Аудит: фильтр `audit.events`, `audit.on_error`, golden-схема `testdata/audit.schema.json` | ✅ | `internal/server/testdata/audit.schema.json` + `TestAuditSchema`; события `fs.list`, `fs.stat` (opt-in) |
| **M2c** | **Interop, документация, релиз** | | |
| M2-15 | Interop: OpenSSH 10.x, paramiko, rclone, lftp | ✅ | CI: матрица interop (OpenSSH 9.6p1 + paramiko 5.0.0, rclone v1.75.0, lftp; OpenSSH 10.6p1 из исходников); локально 62 проверки. Найдено и исправлено: rclone работает через несколько соединений → «свои» файлы и `stat_redirect` теперь на уровне пользователя |
| M2-16 | Документация: README, quickstart, configuration (тест на каждый ключ), audit-log, security, interop, release-checklist | ✅ | `docs/*.md`; тесты `TestConfigurationDocCoversEveryKey`, `TestAuditDocCoversSchema` |
| M2-17 | Минимальный GoReleaser, `release.yml`, job `goreleaser-check` | ✅ | `.goreleaser.yaml` (linux, darwin × amd64, arm64), `release.yml` по публикации релиза, job `goreleaser-check` в `ci-ok` |
| M2-18 | DoD M2, релиз `v0.2.0` | ⬜ 👤 | DoD проверен (покрытие: всего 87%, vfs 88.9%, auth 91.7%, config 87.1%, sftpd 82.9%). После мержа владелец публикует релиз по `docs/release-checklist.md` |

## M3: Hardening (v0.3.0)

| ID | Блок | Статус |
|---|---|---|
| M3-01 | Лимиты соединений, idle timeout, keepalive | ⬜ |
| M3-02 | Ban-таблица | ⬜ |
| M3-03 | Пароли opt-in (argon2id), `user hash-password` | ⬜ |
| M3-04 | `max_file_size`, `min_free_space` | ⬜ |
| M3-05 | `atomic_uploads`, janitor | ⬜ |
| M3-06 | `on_conflict = "version"` | ⬜ |
| M3-07 | Профиль `compat` и тест профилей криптографии | ⬜ |
| M3-08 | Fuzzing (≥ 5 целей), `fuzz.yml`, `fuzz-smoke`, пороги покрытия | ⬜ |
| M3-09 | ssh-audit в CI, Scorecard, actions по SHA | ⬜ |
| M3-10 | Отказ от uid 0 без `--allow-root`; WinSCP вручную; исследование `limits@openssh.com` | ⬜ |
| M3-11 | Документы threat-model и hardening, DoD M3, релиз `v0.3.0` | ⬜ |
| M3-12 | `testutil.AsyncConn` и synctest-тесты таймаутов (перенесено из M1-08) | ⬜ |

## M3b: Windows (можно после v1.0)

| ID | Блок | Статус |
|---|---|---|
| M3b-01 | Набор тестов изоляции на `windows-latest` | ⬜ |
| M3b-02 | Interop WinSCP в CI | ⬜ |
| M3b-03 | `windows/amd64` в релизах (experimental) | ⬜ |

## M4: Multi-user и Operations (v0.4.0)

| ID | Блок | Статус |
|---|---|---|
| M4-01 | Reload по SIGHUP, переоткрытие mount'ов | ⬜ |
| M4-02 | sd_notify, drop-in для systemd < 253 | ⬜ |
| M4-03 | `user add --write`, `disable`, `remove` | ⬜ |
| M4-04 | SSH user certificates | ⬜ |
| M4-05 | Ротация host keys, host certificates | ⬜ |
| M4-06 | Admin listener (`/metrics`, `/healthz`, `/readyz`), `healthcheck` | ⬜ |
| M4-07 | Hooks (exec, webhook с HMAC) | ⬜ |
| M4-08 | PROXY protocol v2, systemd unit, sysusers, tmpfiles, Landlock | ⬜ |
| M4-09 | Документы operations, metrics, recipes; DoD M4, релиз `v0.4.0` | ⬜ |

## M5: Distribution (v0.5.0)

| ID | Блок | Статус |
|---|---|---|
| M5-01 | Полный `.goreleaser.yaml`, воспроизводимые сборки | ⬜ |
| M5-02 | Docker-образ (distroless, GHCR) | ⬜ |
| M5-03 | Пакеты deb/rpm/apk/archlinux | ⬜ |
| M5-04 | Подписи cosign, SBOM, attestations, `THIRD_PARTY_LICENSES` | ⬜ |
| M5-05 | Man-страницы и completions | ⬜ |
| M5-06 | `--ephemeral`, миграция с atmoz | ⬜ |
| M5-07 | `docs/install.md`, DoD M5, релиз `v0.5.0` | ⬜ |

## M6: v1.0.0

| ID | Блок | Статус |
|---|---|---|
| M6-01 | `docs/compatibility.md`: заморозка контрактов | ⬜ |
| M6-02 | Бенчмарки против OpenSSH | ⬜ |
| M6-03 | Покрытие ≥ 80% / ≥ 90% для security-пакетов | ⬜ |
| M6-04 | Fuzz ≥ 2 недель, interop ≥ 1 месяца, ручные чек-листы клиентов | ⬜ |
| M6-05 | OpenSSF Best Practices, Scorecard ≥ 7, Immutable Releases | ⬜ |
| M6-06 | Самопроверка по §7.2, внешний review | ⬜ |
| M6-07 | RC ≥ 4 недель, `v1.0.0` | ⬜ |
| M6-08 | Документы architecture и development, запуск (HN, r/selfhosted, awesome-selfhosted) | ⬜ |

## Журнал

| Дата | Что сделано | Где |
|---|---|---|
| 2026-10-07 | Roadmap | [o-kolomoiets/Go-SFTP-Server#1](https://github.com/o-kolomoiets/Go-SFTP-Server/pull/1) |
| 2026-10-07 | M0: расчистка, скелет, CI, гигиена, документы, ADR; CI зелёный (12/12) | [o-kolomoiets/Go-SFTP-Server#2](https://github.com/o-kolomoiets/Go-SFTP-Server/pull/2) |
| 2026-10-07 | M1: `gosftpd serve` — SSH/SFTP, ключи, изоляция `os.Root`, политика конфликтов, аудит, interop с OpenSSH | [o-kolomoiets/Go-SFTP-Server#3](https://github.com/o-kolomoiets/Go-SFTP-Server/pull/3) |
| 2026-10-08 | Ruleset на `main` и релиз `v0.1.0-alpha` (владелец); M1 закрыт, M2 разбит на задачи | этот файл |
| 2026-10-08 | M2a: конфиг TOML, пользователи и права, `{user}`-home, команды `init`, `config`, `user`, `hostkey generate`; ревью (22 находки, исправлены) | [o-kolomoiets/Go-SFTP-Server#4](https://github.com/o-kolomoiets/Go-SFTP-Server/pull/4) |
